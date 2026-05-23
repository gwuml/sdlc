"""Artifact manifest, signing, and verification support."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from .ledger import Ledger
from .models import RunPlan, open_findings
from .util import read_json


MANIFEST_PATH = "artifacts/attestations/manifest.json"
SIGNATURE_PATH = "artifacts/attestations/manifest.signature.json"
VERIFY_PATH = "artifacts/attestations/verification.json"
CONTROL_SNAPSHOT_DIR = "artifacts/attestations/control-snapshots"
CONTROL_SNAPSHOT_FILES = {
    "plan.json": "plan.json",
    "findings.json": "findings.json",
    "events.jsonl": "events.jsonl",
    "final-report.md": "final-report.md",
    "artifacts/release/readiness.json": "release-readiness.json",
}


def write_artifact_manifest(store: Any, run_id: str) -> dict[str, Any]:
    plan = store.load_plan(run_id)
    run_dir = store.run_dir(run_id)
    ledger = Ledger(run_dir, run_id)
    _write_control_snapshots(ledger, run_dir)
    try:
        manifest = build_artifact_manifest(run_dir)
    except ValueError as exc:
        reason = str(exc)
        ledger.event("attestation.manifest_rejected", reason=reason)
        _update_attestation_gate(store, plan, run_id, "", verdict="NO_GO", notes=reason)
        return {"status": "REJECTED", "reason": reason, "failures": [reason]}
    artifact = ledger.artifact(
        MANIFEST_PATH,
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        event="attestation.manifest_written",
        artifact_count=len(manifest["artifacts"]),
    )
    _update_attestation_gate(store, plan, run_id, artifact, verdict=None, notes="Artifact manifest generated; signature verification still required.")
    return {"status": "MANIFEST_WRITTEN", "artifact": artifact, "manifest": manifest}


def sign_artifact_manifest(store: Any, run_id: str, *, key: str, execute: bool) -> dict[str, Any]:
    run_dir = store.run_dir(run_id)
    ledger = Ledger(run_dir, run_id)
    manifest_path = run_dir / MANIFEST_PATH
    if not manifest_path.exists():
        generated = write_artifact_manifest(store, run_id)
        if generated.get("status") == "REJECTED":
            return {"status": "REJECTED", "reason": generated.get("reason", "Artifact manifest generation failed")}
    plan = store.load_plan(run_id)
    manifest_bytes = manifest_path.read_bytes()
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    if not execute:
        artifact = ledger.artifact(
            "artifacts/attestations/signing-dry-run.json",
            json.dumps({"execute_requested": False, "manifest_sha256": manifest_sha, "status": "DRY_RUN"}, indent=2, sort_keys=True) + "\n",
            event="attestation.signing_dry_run",
        )
        return {"status": "DRY_RUN", "artifact": artifact}

    key_path = Path(key).expanduser()
    if not key_path.exists() or not key_path.is_file():
        ledger.event("attestation.signing_rejected", reason="signing key unavailable")
        return {"status": "REJECTED", "reason": "Signing key path does not exist or is not a file"}
    key_path_error = _key_path_boundary_error(key_path, store.repo, run_dir, "Signing")
    if key_path_error:
        ledger.event("attestation.signing_rejected", reason=key_path_error, key_path=str(key_path.resolve(strict=False)))
        return {"status": "REJECTED", "reason": key_path_error}
    key_bytes = key_path.read_bytes()
    signature = hmac.new(key_bytes, manifest_bytes, hashlib.sha256).hexdigest()
    artifact = ledger.artifact(
        SIGNATURE_PATH,
        json.dumps({
            "algorithm": "HMAC-SHA256",
            "manifest_path": MANIFEST_PATH,
            "manifest_sha256": manifest_sha,
            "signature": signature,
        }, indent=2, sort_keys=True) + "\n",
        event="attestation.signature_written",
        manifest_sha256=manifest_sha,
    )
    _update_attestation_gate(store, plan, run_id, artifact, verdict=None, notes="Artifact manifest signed; verification still required.")
    return {"status": "SIGNED", "artifact": artifact}


def verify_artifact_manifest(store: Any, run_id: str, *, key: str | None = None) -> dict[str, Any]:
    plan = store.load_plan(run_id)
    run_dir = store.run_dir(run_id)
    ledger = Ledger(run_dir, run_id)
    manifest_path = run_dir / MANIFEST_PATH
    if not manifest_path.exists():
        reason = "Artifact manifest is missing"
        artifact = ledger.artifact(
            VERIFY_PATH,
        json.dumps({"status": "NO_GO", "verified": False, "failures": [reason]}, indent=2, sort_keys=True) + "\n",
            event="attestation.verification_artifact",
            verdict="NO_GO",
        )
        _update_attestation_gate(store, plan, run_id, artifact, verdict="NO_GO", notes=reason)
        return {"status": "NO_GO", "artifact": artifact, "failures": [reason]}

    manifest = read_json(manifest_path, {})
    failures = _verify_manifest_entries(run_dir, manifest)
    signature_failures = _verify_signature(store.repo, run_dir, key)
    failures.extend(signature_failures)
    artifact_integrity_verified = not failures
    release_blockers = _attestation_release_blockers(plan, store.load_findings(run_id))
    failures.extend(release_blockers)
    status = "GO" if not failures else "NO_GO"
    artifact = ledger.artifact(
        VERIFY_PATH,
        json.dumps({
            "status": status,
            "verified": status == "GO",
            "artifact_integrity_verified": artifact_integrity_verified,
            "release_gate_blockers": release_blockers,
            "failures": failures,
        }, indent=2, sort_keys=True) + "\n",
        event="attestation.verification_artifact",
        verdict=status,
    )
    _update_attestation_gate(store, plan, run_id, artifact, verdict=status, notes="Artifact manifest and signature verified." if status == "GO" else "; ".join(failures))
    ledger.event("attestation.verified", verdict=status, failures=failures, evidence=[artifact])
    return {"status": status, "artifact": artifact, "failures": failures}


def build_artifact_manifest(run_dir: Path) -> dict[str, Any]:
    producing_events = _producing_events(run_dir)
    artifacts: list[dict[str, Any]] = []
    run_root = run_dir.resolve(strict=True)
    for path in sorted(run_dir.rglob("*")):
        rel = str(path.relative_to(run_dir))
        if path.is_symlink():
            raise ValueError(f"Attestation manifest refuses symlinked run artifact: {rel}")
        if not path.is_file():
            continue
        if _manifest_excluded(rel):
            continue
        path_error = _manifest_artifact_path_error(run_root, path, rel)
        if path_error:
            raise ValueError(path_error)
        content = path.read_bytes()
        event = producing_events.get(rel, {})
        artifacts.append({
            "path": rel,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
            "artifact_type": _artifact_type(rel),
            "producing_event": event.get("event", "unknown"),
            "timestamp": event.get("ts", ""),
        })
    return {"manifest_version": 1, "artifacts": artifacts}


def _write_control_snapshots(ledger: Ledger, run_dir: Path) -> list[str]:
    snapshots: list[str] = []
    for source_name, snapshot_name in CONTROL_SNAPSHOT_FILES.items():
        source = run_dir / source_name
        if source.is_symlink():
            continue
        if not source.exists() or not source.is_file():
            continue
        rel = f"{CONTROL_SNAPSHOT_DIR}/{snapshot_name}"
        content = _control_snapshot_content(run_dir, source_name, source)
        existing = run_dir / rel
        if existing.exists() and existing.is_file() and not existing.is_symlink():
            try:
                if existing.read_text(encoding="utf-8") == content:
                    snapshots.append(rel)
                    continue
            except OSError:
                pass
        artifact = ledger.artifact(
            rel,
            content,
            event="attestation.control_snapshot_written",
            source=source_name,
        )
        snapshots.append(artifact)
    return snapshots


def _control_snapshot_content(run_dir: Path, source_name: str, source: Path) -> str:
    if source_name == "events.jsonl":
        return _filtered_events_snapshot(source)
    if source_name == "plan.json":
        return json.dumps(_normalized_plan_snapshot(read_json(source, {})), indent=2, sort_keys=True) + "\n"
    if source_name in {"findings.json", "artifacts/release/readiness.json"}:
        return json.dumps(read_json(source, [] if source_name == "findings.json" else {}), indent=2, sort_keys=True) + "\n"
    return source.read_text(encoding="utf-8")


def _filtered_events_snapshot(source: Path) -> str:
    lines: list[str] = []
    for line in source.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            lines.append(line)
            continue
        event_name = str(event.get("event", ""))
        if event_name.startswith("attestation.") or event_name.startswith("deploy.") or event_name == "report.generated":
            continue
        lines.append(json.dumps(event, sort_keys=True))
    return "\n".join(lines) + ("\n" if lines else "")


def _normalized_plan_snapshot(plan: Any) -> Any:
    if not isinstance(plan, dict):
        return plan
    normalized = json.loads(json.dumps(plan))
    gates = normalized.get("gates")
    if isinstance(gates, list):
        for gate in gates:
            if isinstance(gate, dict) and gate.get("id") in {
                "evidence_traceability_attestations",
                "deploy_rollout_postdeploy",
                "final_report_reaudit",
            }:
                gate["state"] = "<attestation-self-state-excluded>"
                gate["verdict"] = "<attestation-self-verdict-excluded>"
                gate["evidence"] = []
                gate["notes"] = "<attestation/later-gate self-reference excluded from signed plan snapshot>"
    return normalized


def _verify_manifest_entries(run_dir: Path, manifest: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    artifacts = manifest.get("artifacts", [])
    if not isinstance(artifacts, list):
        return ["manifest artifacts must be a list"]
    run_root = run_dir.resolve(strict=True)
    for item in artifacts:
        if not isinstance(item, dict):
            failures.append("manifest contains a non-object artifact entry")
            continue
        rel = str(item.get("path", ""))
        path = run_dir / rel
        path_error = _manifest_artifact_path_error(run_root, path, rel)
        if path_error:
            failures.append(path_error)
            continue
        if not path.exists() or not path.is_file():
            failures.append(f"missing artifact: {rel}")
            continue
        content = path.read_bytes()
        actual_sha = hashlib.sha256(content).hexdigest()
        if actual_sha != item.get("sha256"):
            failures.append(f"digest mismatch: {rel}")
        if len(content) != item.get("size"):
            failures.append(f"size mismatch: {rel}")
    return failures


def _manifest_artifact_path_error(run_root: Path, path: Path, rel: str) -> str | None:
    if Path(rel).is_absolute() or ".." in Path(rel).parts:
        return f"manifest artifact path escapes run boundary: {rel}"
    if path.is_symlink():
        return f"manifest artifact is a symlink: {rel}"
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return f"manifest artifact cannot be resolved: {rel}"
    if not _path_inside(resolved, run_root):
        return f"manifest artifact escapes run boundary: {rel}"
    if not resolved.is_file():
        return f"manifest artifact is not a regular file: {rel}"
    try:
        stat = resolved.stat()
    except OSError:
        return f"manifest artifact cannot be statted: {rel}"
    if stat.st_nlink > 1:
        return f"manifest artifact has multiple hard links and is not run-isolated: {rel}"
    return None


def _verify_signature(repo: Path, run_dir: Path, key: str | None) -> list[str]:
    signature_path = run_dir / SIGNATURE_PATH
    if not signature_path.exists():
        return ["manifest signature is missing"]
    signature = read_json(signature_path, {})
    if signature.get("algorithm") != "HMAC-SHA256":
        return ["unsupported signature algorithm"]
    manifest_path = run_dir / MANIFEST_PATH
    manifest_bytes = manifest_path.read_bytes()
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    if signature.get("manifest_sha256") != manifest_sha:
        return ["signature manifest digest does not match current manifest"]
    if not key:
        return ["signature verification key is required"]
    key_path = Path(key).expanduser()
    if not key_path.exists() or not key_path.is_file():
        return ["signature verification key is unavailable"]
    if key_path_error := _key_path_boundary_error(key_path, repo, run_dir, "Signature verification"):
        return [key_path_error]
    expected = hmac.new(key_path.read_bytes(), manifest_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(signature.get("signature", ""))):
        return ["signature mismatch"]
    return []


def _key_path_boundary_error(key_path: Path, repo: Path, run_dir: Path, purpose: str) -> str | None:
    resolved = key_path.resolve(strict=False)
    if _path_inside(resolved, repo.resolve(strict=False)) or _path_inside(resolved, run_dir.resolve(strict=False)):
        return f"{purpose} key path must be outside the repository and run artifacts"
    return None


def _path_inside(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def _update_attestation_gate(store: Any, plan: RunPlan, run_id: str, artifact: str, *, verdict: str | None, notes: str) -> None:
    gate = next((item for item in plan.gates if item.id == "evidence_traceability_attestations"), None)
    if gate is None:
        store.save_plan(plan)
        return
    before = (gate.state, gate.verdict, tuple(gate.evidence), gate.notes)
    if verdict == "GO":
        unresolved = [
            f"{item.id}={item.state}/{item.verdict}"
            for item in plan.gates
            if item.order < gate.order and not _attestation_prerequisite_satisfied(item)
        ]
        blockers = open_findings(store.load_findings(run_id), {"CRITICAL", "HIGH", "MEDIUM"})
        if unresolved or blockers:
            verdict = "NO_GO"
            notes = "Attestation verified but release prerequisites are unresolved: " + ", ".join(unresolved or [finding.id for finding in blockers])
    if verdict:
        gate.verdict = verdict
        gate.state = "GO" if verdict == "GO" else "NO_GO"
    if artifact and artifact not in gate.evidence:
        gate.evidence.append(artifact)
    if verdict is not None or gate.state != "GO":
        gate.notes = notes
    after = (gate.state, gate.verdict, tuple(gate.evidence), gate.notes)
    if after != before:
        store.save_plan(plan)


def _attestation_release_blockers(plan: RunPlan, findings: list[Any]) -> list[str]:
    gate = next((item for item in plan.gates if item.id == "evidence_traceability_attestations"), None)
    if gate is None:
        return ["attestation gate is missing"]
    unresolved = [
        f"{item.id}={item.state}/{item.verdict}"
        for item in plan.gates
        if item.order < gate.order and not _attestation_prerequisite_satisfied(item)
    ]
    blockers = [finding.id for finding in open_findings(findings, {"CRITICAL", "HIGH", "MEDIUM"})]
    return unresolved + blockers


def _attestation_prerequisite_satisfied(gate: Any) -> bool:
    if gate.state == "SKIPPED":
        return gate.verdict == "SKIPPED"
    if gate.state == "GO":
        return gate.verdict in {"GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"} and bool(gate.evidence)
    return False


def _producing_events(run_dir: Path) -> dict[str, dict[str, Any]]:
    events_path = run_dir / "events.jsonl"
    if not events_path.exists():
        return {}
    events: dict[str, dict[str, Any]] = {}
    for line in events_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        path = event.get("path")
        if isinstance(path, str):
            events[path] = event
    return events


def _manifest_excluded(path: str) -> bool:
    mutable_control_files = {"events.jsonl", "plan.json", "findings.json", "final-report.md", "artifacts/release/readiness.json"}
    return path in {MANIFEST_PATH, SIGNATURE_PATH, VERIFY_PATH, *mutable_control_files} or path.endswith(".pyc")


def _artifact_type(path: str) -> str:
    if path == "plan.json":
        return "plan"
    if path == "findings.json":
        return "findings"
    if path.startswith("prompts/"):
        return "prompt"
    if path.startswith("worker-results/"):
        return "worker-output"
    if path.startswith("artifacts/scans/"):
        return "scanner-output"
    if path.startswith("artifacts/deploy/"):
        return "deploy-evidence"
    if path.startswith("artifacts/attestations/"):
        return "attestation"
    if path == "final-report.md":
        return "report"
    return "artifact"
