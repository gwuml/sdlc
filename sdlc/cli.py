"""Terminal CLI for the Secure SDLC control plane."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import hmac
import json
import os
import re
import shlex
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from .adapters import ADAPTERS, adapter_from_policy, capture_worker_result, worker_identity_group
from .agents import agent_status, agents_doctor, execute_agent_plan, write_agent_plan
from .attestations import MANIFEST_PATH, SIGNATURE_PATH, VERIFY_PATH, _verify_manifest_entries, sign_artifact_manifest, verify_artifact_manifest, write_artifact_manifest
from .briefing import build_intake_brief, build_standards_mapping, write_prework_artifacts
from .classifier import classify_feature
from .deploy import approve_deployment, execute_deployment, plan_deployment, production_deploy_gate_rejection, rollback_deployment, verify_deployment
from .engine import RunStore, create_redteam_findings, execute_redteam_workers, final_verdict, invalidate_downstream_gates, run_dry_gates, validate_run_id
from .ledger import LEDGER_ARTIFACT_SCHEMA, LEDGER_EVENT_SCHEMA, LEGACY_PREFIX_SEAL_EVENT, Ledger, canonical_artifact_event, canonical_chain_start, is_canonical_ledger_event, ledger_event_digest
from .memory import delete_memory, disable_memory, export_memory, init_memory, memory_status, record_episode, search_memory
from .models import GateState, RunPlan, Finding, open_findings, plan_condition_value
from .pipeline import DEFAULT_GATES, gates_as_dicts
from .policies import ensure_policy_files, load_policy
from .prompts import write_prompt_bundle
from .reporting import build_report, generate_report
from .scanners import run_security_scans, scan_notes, scan_verdict
from .util import git_current_branch, is_git_repo, now_iso, read_json, relpath_under_base, resolve_repo_paths, resolve_under_base, run_cmd, slugify, write_json
from .validation import validate_json_schema


SCHEMA_DIR_CONTENT = {
    "gate_result.schema.json": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["gate_id", "verdict", "evidence", "notes", "actor"],
        "properties": {
            "gate_id": {"type": "string"},
            "verdict": {"enum": ["GO", "NO_GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS", "SKIPPED"]},
            "evidence": {"type": "array", "items": {"type": "string"}},
            "notes": {"type": "string"},
            "actor": {"type": "string"},
        },
        "additionalProperties": True,
    },
    "finding.schema.json": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["id", "severity", "title", "evidence", "impact", "required_fix", "owner", "status"],
        "properties": {
            "id": {"type": "string"},
            "severity": {"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
            "title": {"type": "string"},
            "evidence": {"type": "array", "items": {"type": "string"}},
            "impact": {"type": "string"},
            "required_fix": {"type": "string"},
            "owner": {"type": "string"},
            "status": {"enum": ["OPEN", "FIXED_PENDING_REVIEW", "CLOSED", "ACCEPTED", "DEFERRED"]},
        },
        "additionalProperties": True,
    },
    "final_report.schema.json": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["run_id", "feature", "verdict", "gates", "findings", "residual_risks"],
        "properties": {
            "run_id": {"type": "string"},
            "feature": {"type": "string"},
            "verdict": {"enum": ["GO", "NO_GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"]},
            "gates": {"type": "array"},
            "findings": {"type": "array"},
            "residual_risks": {"type": "array"},
        },
    },
}


_RUN_EVENTS_CACHE: dict[tuple[str, int, int], list[dict[str, object]]] = {}
_ARTIFACT_INDEX_CACHE: dict[tuple[str, int, int, bool, tuple[str, ...]], dict[tuple[str, str], dict[str, object]]] = {}


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


HUMAN_GATE_ACTORS = {
    "human_approval_authority",
    "human_product_owner",
    "human_release_manager",
    "human_security_owner",
}
AUTHORIZED_FINDING_CLOSERS = HUMAN_GATE_ACTORS | {
    "agent_4_evidence_reporting_owner",
    "agent_6_redteam_deploy_rollback",
}
POSITIVE_GATE_VERDICTS = {"GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"}
REDTEAM_TERMINAL_EVENTS = {"redteam.execution_completed", "redteam.execution_interrupted", "redteam.execution_cancelled"}
REDTEAM_NONCOMPLETION_EVENTS = {"redteam.execution_interrupted", "redteam.execution_cancelled"}
PROTECTED_BRANCHES = {"main", "master", "trunk", "prod", "production"}
COMMIT_MESSAGE_RE = re.compile(r"^[a-z]+(\([a-z0-9_.-]+\))?!?: .+")
GIT_PROVENANCE_GATES = {"repo_context_env_branch", "baseline_freeze", "commit_branch_pr_ci"}
SDLC_GITIGNORE_HEADER = "# Generated SDLC run evidence"
SDLC_GITIGNORE_ENTRIES = (
    ".sdlc/runs/",
    ".sdlc-worker-tmp/",
    ".sdlc-redteam-tmp/",
    ".sdlc/memory.sqlite",
)
GIT_COMMAND_ARTIFACTS = {
    ("repo_context_env_branch", "git_status"): ("git status --short --branch", True),
    ("repo_context_env_branch", "current_branch"): ("git branch --show-current", False),
    ("repo_context_env_branch", "remote_summary"): ("git remote -v", False),
    ("baseline_freeze", "git_status_before"): ("git status --short --branch", True),
    ("commit_branch_pr_ci", "branch_name"): ("git branch --show-current", False),
}
CANONICAL_ARTIFACT_EVENTS = {
    "artifact.written",
    "attestation.control_snapshot_written",
    "attestation.manifest_written",
    "attestation.signature_written",
    "attestation.signing_dry_run",
    "attestation.verification_artifact",
    "deploy.approval_artifact",
    "deploy.execute_failed_artifact",
    "deploy.execute_plan_artifact",
    "deploy.execution_artifact",
    "deploy.plan_artifact",
    "deploy.rollback_artifact",
    "deploy.rollback_failed_artifact",
    "deploy.rollback_rejected_artifact",
    "deploy.verification_artifact",
    "finding.remediation_diff",
    "finding.remediation_summary",
    "finding.remediation_validation",
    "finding.risk_acceptance",
    "gate.evidence_recorded",
    "gate.required_artifact_recorded",
    "gate.residual_risk_acceptance",
    "gate.source_evidence_recorded",
    "git.provenance_artifact",
    "redteam.findings_parsed",
    "security.scans_completed",
    "worker.output_captured",
}
FINDING_CLOSURE_ARTIFACT_EVENTS = {
    "finding.remediation_diff",
    "finding.remediation_summary",
    "finding.remediation_validation",
    "finding.risk_acceptance",
    "gate.residual_risk_acceptance",
    "remediation.diff_artifact",
    "remediation.summary",
    "remediation.validation_artifact",
}
RELEASE_GATE_EVIDENCE_MARKERS = {
    "implementation": ["diff --git", "changed files", "implementation"],
    "deterministic_quality": ["returncode: 0", "validation passed", "ran ", "ok"],
    "qa_tests_integration_smoke": ["ran ", "ok", "test", "smoke"],
    "security_scans": ["security scan", "scanner", "verdict:"],
    "observability_runbooks": ["observability", "runbook", "incident", "monitor"],
    "implementer_self_review": ["self-review", "self review", "claim", "risk"],
    "independent_redteam_cross_model": ["redteam_execution_summary", "execute_requested: true", "executed_families"],
    "critical_high_fix_loop": ["redteam_execution_summary", "second-validation", "validation", "fix"],
    "evidence_traceability_attestations": ["manifest", "verification", "verified"],
    "commit_branch_pr_ci": ["commit", "branch", "pr", "ci"],
    "deploy_rollout_postdeploy": ["deploy", "rollback", "smoke", "monitor"],
    "final_report_reaudit": ["secure sdlc final report", "verdict:"],
}


def _gate_definition(gate_id: str):
    return next((item for item in DEFAULT_GATES if item.id == gate_id), None)


def _gate_satisfied(gate: GateState, plan: RunPlan | None = None) -> bool:
    if gate.state == "WAIVED":
        return True
    if gate.state == "SKIPPED":
        return _skipped_gate_valid(gate, plan)
    if gate.state == "GO":
        return gate.verdict in POSITIVE_GATE_VERDICTS
    return False


def _skipped_gate_valid(gate: GateState, plan: RunPlan | None) -> bool:
    if gate.verdict != "SKIPPED" or not gate.conditional_on:
        return False
    return plan_condition_value(plan, gate.conditional_on) is False


def _reject_gate_completion(ledger: Ledger, gate: GateState, args: argparse.Namespace, reason: str, evidence: list[str] | None = None) -> int:
    ledger.event(
        "gate.completion_rejected",
        gate=gate.id,
        actor=args.actor,
        verdict=args.verdict,
        reason=reason,
        evidence=evidence or [],
    )
    eprint(reason)
    return 3


def _actor_can_complete_gate(gate: GateState, actor: str | None) -> bool:
    return bool(actor) and (actor == gate.owner or actor in HUMAN_GATE_ACTORS)


def _validate_gate_dependencies(plan: RunPlan, gate: GateState, verdict: str) -> str | None:
    if verdict not in POSITIVE_GATE_VERDICTS:
        return None
    unresolved = [
        item.id
        for item in sorted(plan.gates, key=lambda value: value.order)
        if item.order < gate.order and not _gate_satisfied(item, plan)
    ]
    if unresolved:
        return f"Cannot mark {gate.id} {verdict}; unresolved prerequisite gates: {', '.join(unresolved)}"
    return None


def _validate_security_gate_completion(store: RunStore, run_id: str, gate: GateState, verdict: str, actor: str | None, notes: str) -> str | None:
    if gate.id != "security_scans" or verdict not in POSITIVE_GATE_VERDICTS:
        return None
    summary = store.run_dir(run_id) / "artifacts" / "security_scan_summary.md"
    if not summary.exists():
        return "Security scans require scanner-produced security_scan_summary.md evidence"
    events = _load_run_events(store.run_dir(run_id))
    scan_events = [event for event in events if event.get("event") == "security.scans_completed"]
    if not scan_events:
        return "Security scans require ledger-backed security.scans_completed evidence"
    latest_evidence = {str(item) for item in scan_events[-1].get("evidence", [])}
    if "artifacts/security_scan_summary.md" not in latest_evidence:
        return "Security scan ledger evidence must include artifacts/security_scan_summary.md"
    text = summary.read_text(encoding="utf-8")
    if verdict == "GO" and "Verdict: GO" not in text:
        return "Security scans can only be GO when the scanner-produced summary verdict is GO"
    if "Verdict: NO_GO" not in text:
        return None
    if verdict == "GO":
        return "Security scans with a NO_GO scanner summary require GO_WITH_ACCEPTED_RESIDUAL_RISKS and explicit residual-risk evidence; they cannot be converted to GO"
    if actor not in {"human_security_owner", "human_product_owner", "human_approval_authority"}:
        return "Accepted residual risk for a NO_GO security scan requires a human security/product approval actor"
    lowered = notes.lower()
    if "residual" not in lowered or "reason" not in lowered:
        return "Accepted residual risk for a NO_GO security scan requires notes containing residual risk and reason"
    return None


def _validate_residual_risk_gate_completion(repo: Path, run_dir: Path, gate: GateState, verdict: str, actor: str | None, notes: str, evidence_paths: list[str]) -> str | None:
    if verdict != "GO_WITH_ACCEPTED_RESIDUAL_RISKS":
        return None
    if gate.id in {"security_scans", "deploy_rollout_postdeploy", "final_report_reaudit"}:
        return None
    if actor not in HUMAN_GATE_ACTORS:
        return "GO_WITH_ACCEPTED_RESIDUAL_RISKS requires an authorized human approval actor unless a stricter gate-specific workflow applies"
    ledger_backed = _ledger_backed_artifacts(repo, run_dir, evidence_paths, CANONICAL_ARTIFACT_EVENTS)
    residual_artifacts = [item for item in ledger_backed if item.get("event") == "gate.residual_risk_acceptance"]
    if not residual_artifacts:
        return "GO_WITH_ACCEPTED_RESIDUAL_RISKS requires ledger-backed residual-risk evidence"
    evidence_text = "\n".join(str(item.get("text", "")) for item in residual_artifacts)
    lowered = f"{notes}\n{evidence_text}".lower()
    if "residual risk" not in lowered or "reason" not in lowered:
        return "GO_WITH_ACCEPTED_RESIDUAL_RISKS requires notes or evidence containing residual risk and reason"
    if not any(marker in lowered for marker in ["accepted residual risk", "risk acceptance", "accepted risk", "human accepted"]):
        return "GO_WITH_ACCEPTED_RESIDUAL_RISKS requires explicit accepted-risk evidence"
    return None


def _validate_final_report_gate_completion(store: RunStore, run_id: str, gate: GateState, verdict: str, evidence_paths: list[str]) -> str | None:
    if gate.id != "final_report_reaudit" or verdict not in POSITIVE_GATE_VERDICTS:
        return None
    run_dir = store.run_dir(run_id)
    report_path = run_dir / "final-report.md"
    if not report_path.exists():
        return "Final report gate requires a generated final-report.md"
    expected_evidence = f".sdlc/runs/{run_id}/final-report.md"
    if expected_evidence not in evidence_paths and "final-report.md" not in evidence_paths:
        return "Final report gate evidence must include the current final-report.md"
    report_text = report_path.read_text(encoding="utf-8")
    report_sha = hashlib.sha256(report_path.read_bytes()).hexdigest()
    current_report = build_report(Path(store.load_plan(run_id).repo), run_id)
    if report_text != current_report:
        return "Final report content is stale relative to current plan, findings, or gate state"
    source_paths = [store.plan_path(run_id), store.findings_path(run_id)]
    report_mtime = report_path.stat().st_mtime
    stale_sources = [path.name for path in source_paths if path.exists() and path.stat().st_mtime > report_mtime]
    if stale_sources:
        return "Final report is stale relative to " + ", ".join(stale_sources)
    report_event = _latest_artifact_event(run_dir, event_name="report.generated", path="final-report.md", sha256=report_sha)
    if report_event is None:
        return "Final report gate requires ledger-backed report.generated provenance for the current report"
    report_sequence = int(report_event.get("ledger_sequence") or -1)
    stale_event_records = _ledger_event_records_after_sequence(
        run_dir,
        report_sequence,
        ignored_events={
            "report.generated",
            "attestation.control_snapshot_written",
            "attestation.manifest_written",
            "attestation.signature_written",
            "attestation.verification_artifact",
            "report.auto_refreshed",
        },
    )
    attestation_after_report = [
        event for event in stale_event_records
        if event.get("event") == "attestation.verified"
    ]
    stale_events = [
        str(event.get("event", ""))
        for event in stale_event_records
        if event.get("event") != "attestation.verified"
    ]
    if stale_events:
        return "Final report is stale relative to later ledger events: " + ", ".join(stale_events[:5])
    missing_findings = [finding.id for finding in store.load_findings(run_id) if finding.id not in report_text]
    if missing_findings:
        return "Final report omits current findings: " + ", ".join(missing_findings)
    readiness_path = run_dir / "artifacts" / "release" / "readiness.json"
    if not readiness_path.exists():
        return "Final report gate requires artifacts/release/readiness.json release-readiness evidence"
    try:
        readiness_text = readiness_path.read_text(encoding="utf-8")
        readiness_payload = json.loads(readiness_text)
    except (OSError, json.JSONDecodeError):
        return "Final report readiness evidence is invalid JSON"
    readiness_sha = hashlib.sha256(readiness_text.encode("utf-8")).hexdigest()
    readiness_event = _latest_artifact_event(
        run_dir,
        event_name="release.readiness_evaluated",
        path="artifacts/release/readiness.json",
        sha256=readiness_sha,
    )
    if readiness_event is None:
        return "Final report gate requires ledger-backed release.readiness_evaluated provenance for artifacts/release/readiness.json"
    readiness_sequence = int(readiness_event.get("ledger_sequence") or -1)
    if readiness_sequence > report_sequence:
        return "Final report is stale relative to later release-readiness evaluation"
    readiness_blockers = readiness_payload.get("blockers", [])
    if readiness_payload.get("release_verdict") == "NO_GO" or readiness_payload.get("release_satisfied") is False:
        if isinstance(readiness_blockers, list) and readiness_blockers:
            return "Final report structured readiness evidence is NO_GO: " + "; ".join(str(item) for item in readiness_blockers[:5])
        return "Final report structured readiness evidence is NO_GO"
    verification = run_dir / "artifacts" / "attestations" / "verification.json"
    manifest = run_dir / "artifacts" / "attestations" / "manifest.json"
    snapshot = run_dir / "artifacts" / "attestations" / "control-snapshots" / "final-report.md"
    readiness_snapshot = run_dir / "artifacts" / "attestations" / "control-snapshots" / "release-readiness.json"
    if not verification.exists() or not manifest.exists() or not snapshot.exists() or not readiness_snapshot.exists():
        return "Final report gate requires a verified attestation manifest containing final-report and release-readiness control snapshots"
    try:
        verification_payload = json.loads(verification.read_text(encoding="utf-8"))
        manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return "Final report attestation evidence is invalid JSON"
    if verification_payload.get("verified") is not True:
        return "Final report gate requires attestation verification with verified=true"
    attestation_event_error = _final_report_attestation_event_error(attestation_after_report)
    if attestation_event_error:
        return attestation_event_error
    chain_error = _final_report_attestation_chain_error(
        store,
        run_id,
        verification_payload=verification_payload,
        manifest_payload=manifest_payload,
        report_sha=report_sha,
        readiness_sha=readiness_sha,
    )
    if chain_error:
        return chain_error
    if verification.stat().st_mtime < report_mtime or manifest.stat().st_mtime < report_mtime:
        return "Final report was generated after the latest attestation verification"
    snapshot_sha = hashlib.sha256(snapshot.read_bytes()).hexdigest()
    if report_sha != snapshot_sha:
        return "Final report digest does not match the attested control snapshot"
    readiness_snapshot_sha = hashlib.sha256(readiness_snapshot.read_bytes()).hexdigest()
    if readiness_sha != readiness_snapshot_sha:
        return "Release-readiness digest does not match the attested control snapshot"
    manifest_entries = manifest_payload.get("artifacts", [])
    if not any(isinstance(item, dict) and item.get("path") == "artifacts/attestations/control-snapshots/final-report.md" and item.get("sha256") == snapshot_sha for item in manifest_entries):
        return "Verified manifest does not cover the current final-report control snapshot"
    if not any(isinstance(item, dict) and item.get("path") == "artifacts/attestations/control-snapshots/release-readiness.json" and item.get("sha256") == readiness_snapshot_sha for item in manifest_entries):
        return "Verified manifest does not cover the current release-readiness control snapshot"
    return None


def _final_report_attestation_event_error(attestation_events: list[dict[str, Any]]) -> str | None:
    if not attestation_events:
        return "Final report gate requires ledger-backed attestation.verified provenance after report generation"
    latest = attestation_events[-1]
    if latest.get("verdict") != "GO":
        return "Final report is stale relative to later failed attestation verification"
    evidence = {str(item) for item in latest.get("evidence", []) if isinstance(item, str)}
    if "artifacts/attestations/verification.json" not in evidence:
        return "Final report attestation verification event must reference artifacts/attestations/verification.json"
    return None


def _final_report_attestation_chain_error(
    store: RunStore,
    run_id: str,
    *,
    verification_payload: dict[str, Any],
    manifest_payload: dict[str, Any],
    report_sha: str,
    readiness_sha: str,
) -> str | None:
    run_dir = store.run_dir(run_id)
    verification_path = run_dir / VERIFY_PATH
    manifest_path = run_dir / MANIFEST_PATH
    signature_path = run_dir / SIGNATURE_PATH
    verification_sha = hashlib.sha256(verification_path.read_bytes()).hexdigest()
    verification_event = _latest_artifact_event(
        run_dir,
        event_name="attestation.verification_artifact",
        path=VERIFY_PATH,
        sha256=verification_sha,
    )
    if verification_event is None:
        return "Final report gate requires ledger-backed attestation.verification_artifact provenance for the current verification.json"
    if verification_event.get("verdict") != "GO":
        return "Final report gate requires the current attestation verification artifact to have verdict=GO"
    verified_events = [
        event for event in _load_run_events(run_dir)
        if event.get("event") == "attestation.verified"
        and event.get("verdict") == "GO"
        and VERIFY_PATH in {str(item) for item in event.get("evidence", []) if isinstance(item, str)}
    ]
    if not verified_events:
        return "Final report gate requires a ledger-backed attestation.verified GO event for the current verification.json"
    latest_verified = verified_events[-1]
    verified_sequence = int(latest_verified.get("ledger_sequence") or -1)
    verification_sequence = int(verification_event.get("ledger_sequence") or -1)
    if verified_sequence < verification_sequence:
        return "Final report gate requires attestation.verified provenance after the current verification artifact"
    if latest_verified.get("failures"):
        return "Final report gate requires a successful attestation.verified event without failures"
    if verification_payload.get("status") != "GO" or verification_payload.get("verified") is not True:
        return "Final report gate requires verification.json status=GO and verified=true"
    if verification_payload.get("artifact_integrity_verified") is not True:
        return "Final report gate requires artifact_integrity_verified=true"
    if verification_payload.get("failures"):
        return "Final report gate requires verification.json without failures"
    if verification_payload.get("release_gate_blockers"):
        return "Final report gate requires verification.json without release gate blockers"
    manifest_event = _latest_artifact_event(
        run_dir,
        event_name="attestation.manifest_written",
        path=MANIFEST_PATH,
        sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
    )
    if manifest_event is None:
        return "Final report gate requires ledger-backed attestation.manifest_written provenance for the current manifest.json"
    signature_event = _latest_artifact_event(
        run_dir,
        event_name="attestation.signature_written",
        path=SIGNATURE_PATH,
        sha256=hashlib.sha256(signature_path.read_bytes()).hexdigest(),
    )
    if signature_event is None:
        return "Final report gate requires ledger-backed attestation.signature_written provenance for the current manifest.signature.json"
    manifest_failures = _verify_manifest_entries(run_dir, manifest_payload)
    if manifest_failures:
        return "Final report gate requires a manifest that verifies current artifact digests: " + "; ".join(manifest_failures[:5])
    signature_payload = read_json(signature_path, {})
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    if signature_payload.get("manifest_sha256") != manifest_sha:
        return "Final report gate requires signature metadata bound to the current manifest digest"
    manifest_entries = manifest_payload.get("artifacts", [])
    if not isinstance(manifest_entries, list):
        return "Final report gate requires a manifest artifact list"
    required = {
        "artifacts/attestations/control-snapshots/final-report.md": report_sha,
        "artifacts/attestations/control-snapshots/release-readiness.json": readiness_sha,
    }
    for path, sha in required.items():
        if not any(isinstance(item, dict) and item.get("path") == path and item.get("sha256") == sha for item in manifest_entries):
            return f"Final report gate requires current manifest coverage for {path}"
    return None


def _validate_non_placeholder_evidence(repo: Path, verdict: str, evidence_paths: list[str]) -> str | None:
    if verdict not in POSITIVE_GATE_VERDICTS:
        return None
    placeholder_markers = [
        "placeholder is not sufficient for production GO",
        "dry-run placeholder cannot mark this gate GO",
    ]
    for rel in evidence_paths:
        if rel.startswith(".sdlc/runs/"):
            continue
        if rel.startswith(("sdlc/", "tests/", "docs/", "scripts/")):
            continue
        path = repo / rel
        if not path.exists() or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        stripped = text.strip()
        is_placeholder_only = stripped.startswith("Gate ") and len(stripped.splitlines()) <= 3
        if is_placeholder_only and any(marker in text for marker in placeholder_markers):
            return f"Positive gate verdict cannot use placeholder-only evidence: {rel}"
        if not _contains_concrete_evidence_reference(text):
            return f"Positive gate verdict requires concrete evidence references, not generic prose: {rel}"
    return None


def _evidence_text(repo: Path, rel: str) -> str:
    path = repo / rel
    if not path.exists() or not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _run_or_repo_evidence_text(repo: Path, run_dir: Path, rel: str) -> str:
    try:
        path = _resolve_run_evidence_path(repo, run_dir, _strip_reference_fragment(rel))
    except Exception:
        return ""
    if not path.exists() or not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _strip_reference_fragment(value: str) -> str:
    return value.split("#", 1)[0].strip()


def _digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _repo_relative_path(repo: Path, path: Path) -> str | None:
    try:
        return str(path.resolve(strict=False).relative_to(repo.resolve(strict=False)))
    except ValueError:
        return None


def _run_relative_path(run_dir: Path, path: Path) -> str | None:
    try:
        return str(path.resolve(strict=False).relative_to(run_dir.resolve(strict=False)))
    except ValueError:
        return None


def _path_inside(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def _resolve_evidence_reference(repo: Path, run_dir: Path, value: str) -> tuple[Path | None, str | None, str | None]:
    ref = _strip_reference_fragment(value)
    if not ref:
        return None, None, "Artifact reference is empty"
    candidate = _resolve_run_evidence_path(repo, run_dir, ref)
    base = run_dir if _path_inside(candidate.resolve(strict=False), run_dir.resolve(strict=False)) else repo
    resolved, error = resolve_under_base(base, candidate, must_exist=True)
    if error or resolved is None:
        return None, None, error or f"Invalid artifact reference: {value}"
    if not resolved.is_file():
        return None, None, f"Artifact reference is not a file: {value}"
    run_rel = _run_relative_path(run_dir, resolved)
    return resolved, run_rel or _repo_relative_path(repo, resolved) or str(resolved), None


def _ledger_artifact_event(run_dir: Path, path: Path, sha256: str) -> dict[str, object] | None:
    run_rel = _run_relative_path(run_dir, path)
    if run_rel is None:
        return None
    event = _canonical_artifact_index(
        run_dir,
        allowed_events=CANONICAL_ARTIFACT_EVENTS,
        require_origin=True,
    ).get((run_rel, sha256))
    if event is not None:
        return {
            "type": "run_ledger_artifact",
            "event": event.get("event"),
            "path": run_rel,
            "sha256": sha256,
        }
    return None


def _ledger_cache_key(run_dir: Path) -> tuple[str, int, int] | None:
    events_path = run_dir / "events.jsonl"
    try:
        stat = events_path.stat()
    except OSError:
        return None
    return (str(events_path.resolve(strict=False)), stat.st_mtime_ns, stat.st_size)


def _canonical_artifact_index(
    run_dir: Path,
    *,
    allowed_events: set[str],
    require_origin: bool,
) -> dict[tuple[str, str], dict[str, object]]:
    events_key = _ledger_cache_key(run_dir)
    if events_key is None:
        return {}
    cache_key = (*events_key, require_origin, tuple(sorted(allowed_events)))
    cached = _ARTIFACT_INDEX_CACHE.get(cache_key)
    if cached is not None:
        return cached

    events = _load_run_events(run_dir)
    start = canonical_chain_start(events, require_origin=require_origin, run_dir=run_dir)
    if start is None:
        _ARTIFACT_INDEX_CACHE[cache_key] = {}
        return {}

    start_index, previous_sha256 = start
    indexed: dict[tuple[str, str], dict[str, object]] = {}
    for sequence in range(start_index, len(events)):
        event = events[sequence]
        if not is_canonical_ledger_event(
            event,
            sequence=sequence,
            previous_sha256=previous_sha256,
            require_origin=require_origin,
            run_dir=run_dir,
        ):
            indexed = {}
            break
        if _is_canonical_artifact_event(event, run_dir=run_dir, allowed_events=allowed_events):
            path = event.get("path")
            digest = event.get("sha256")
            if isinstance(path, str) and isinstance(digest, str):
                indexed[(path, digest)] = dict(event)
        event_sha256 = event.get("event_sha256")
        previous_sha256 = event_sha256 if isinstance(event_sha256, str) else None

    _ARTIFACT_INDEX_CACHE[cache_key] = indexed
    return indexed


def _artifact_provenance(repo: Path, run_dir: Path, path: Path, sha256: str) -> tuple[dict[str, object] | None, str | None]:
    ledger_event = _ledger_artifact_event(run_dir, path, sha256)
    if ledger_event:
        return ledger_event, None
    run_rel = _run_relative_path(run_dir, path)
    if run_rel is not None:
        return None, f"Run artifact lacks matching ledger sha256 provenance: {run_rel}"
    return None, f"Required gate artifact must be a ledger-produced run artifact, not an ordinary repo file: {_repo_relative_path(repo, path) or path}"


def _is_canonical_artifact_event(
    event: dict[str, object],
    *,
    run_dir: Path,
    allowed_events: set[str],
) -> bool:
    event_name = event.get("event")
    if not isinstance(event_name, str) or event_name not in allowed_events:
        return False
    if event.get("run_id") != run_dir.name:
        return False
    path = event.get("path")
    digest = event.get("sha256")
    if not isinstance(path, str) or not path.startswith("artifacts/") and not path.startswith("worker-results/"):
        return False
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        return False
    if event.get("ledger_schema") != LEDGER_EVENT_SCHEMA:
        return False
    if event.get("artifact_schema") != LEDGER_ARTIFACT_SCHEMA:
        return False
    if not isinstance(event.get("ledger_sequence"), int):
        return False
    event_hash = event.get("event_sha256")
    if not isinstance(event_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", event_hash):
        return False
    if ledger_event_digest(event) != event_hash:
        return False
    previous = event.get("prev_event_sha256")
    if previous is not None and (not isinstance(previous, str) or not re.fullmatch(r"[a-f0-9]{64}", previous)):
        return False
    return True


def _normalize_command(value: object) -> str:
    if isinstance(value, list):
        return " ".join(str(item) for item in value)
    text = str(value or "").strip()
    try:
        return " ".join(shlex.split(text))
    except ValueError:
        return " ".join(text.split())


def _transcript_section(text: str, header: str) -> str:
    match = re.search(rf"(?im)^{re.escape(header)}:\s*$", text)
    if not match:
        return ""
    remainder = text[match.end():]
    next_header = re.search(r"(?m)^[A-Za-z0-9_. -]+:\s*$", remainder)
    return (remainder[:next_header.start()] if next_header else remainder).strip()


def _parse_command_transcript(text: str) -> dict[str, object] | None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict) and "command" in payload:
        return {
            "command": _normalize_command(payload.get("command")),
            "cwd": str(payload.get("cwd", "")),
            "timestamp": str(payload.get("timestamp", "")),
            "returncode": payload.get("returncode"),
            "stdout": str(payload.get("stdout", "")),
            "stderr": str(payload.get("stderr", "")),
        }
    command = re.search(r"(?im)^command:\s*(.+)$", text)
    returncode = re.search(r"(?im)^returncode:\s*(-?\d+)\s*$", text)
    cwd = re.search(r"(?im)^cwd:\s*(.+)$", text)
    timestamp = re.search(r"(?im)^timestamp:\s*(.+)$", text)
    if not command or not returncode:
        return None
    return {
        "command": _normalize_command(command.group(1)),
        "cwd": cwd.group(1).strip() if cwd else "",
        "timestamp": timestamp.group(1).strip() if timestamp else "",
        "returncode": int(returncode.group(1)),
        "stdout": _transcript_section(text, "stdout"),
        "stderr": _transcript_section(text, "stderr"),
    }


def _git_command_artifact_error(gate_id: str, key: str, path: Path, text: str) -> str | None:
    requirement = GIT_COMMAND_ARTIFACTS.get((gate_id, key))
    if requirement is None:
        return None
    expected_command, needs_branch_status = requirement
    transcript = _parse_command_transcript(text)
    if transcript is None:
        return f"{gate_id}.{key} must be a machine-captured git command transcript: {path}"
    if transcript.get("command") != expected_command:
        return f"{gate_id}.{key} must capture `{expected_command}`, not `{transcript.get('command')}`"
    if transcript.get("returncode") != 0:
        return f"{gate_id}.{key} git transcript must record returncode: 0"
    if not transcript.get("cwd"):
        return f"{gate_id}.{key} git transcript must record cwd"
    if not transcript.get("timestamp"):
        return f"{gate_id}.{key} git transcript must record timestamp"
    combined = f"{transcript.get('stdout', '')}\n{transcript.get('stderr', '')}".lower()
    if "not a git repository" in combined or "fatal:" in combined:
        return f"{gate_id}.{key} git transcript records a git failure"
    stdout = str(transcript.get("stdout", ""))
    if needs_branch_status and "## " not in stdout:
        return f"{gate_id}.{key} must include `git status --short --branch` stdout with the current branch"
    if key in {"current_branch", "branch_name"}:
        branch = stdout.strip().splitlines()[0].strip() if stdout.strip() else ""
        if not branch or branch in {"HEAD", "unknown", "<unknown>"}:
            return f"{gate_id}.{key} must record a concrete branch name"
    return None


def _gate_artifact_content_error(gate_id: str, key: str, path: Path, text: str) -> str | None:
    lowered = text.lower()
    is_patch_artifact = key == "code_diff" or path.suffix in {".patch", ".diff"}
    is_git_command_artifact = (gate_id, key) in GIT_COMMAND_ARTIFACTS
    if not is_patch_artifact and _contains_template_stuffed_evidence(text):
        return f"{gate_id}.{key} uses template-stuffed evidence: {path}"
    if not is_patch_artifact and not is_git_command_artifact:
        if "artifact_type:" not in lowered:
            return f"{gate_id}.{key} evidence must declare artifact_type"
        if "provenance:" not in lowered:
            return f"{gate_id}.{key} evidence must declare provenance"
        if "scope:" not in lowered:
            return f"{gate_id}.{key} evidence must declare scope"
        if "acceptance:" not in lowered:
            return f"{gate_id}.{key} evidence must declare acceptance"
        structured_fields = ["evidence_id:", "claim:", "method:", "result:", "limitations:"]
        missing_fields = [field.rstrip(":") for field in structured_fields if field not in lowered]
        if missing_fields:
            return f"{gate_id}.{key} evidence lacks artifact-specific structured facts: {', '.join(missing_fields)}"
        if _looks_like_boilerplate_gate_artifact(gate_id, key, text):
            return f"{gate_id}.{key} evidence is boilerplate and lacks artifact-specific support: {path}"
        stuffing_terms = [
            "decision",
            "consequence",
            "json schema",
            "command contract",
            "invariant",
            "failure mode",
            "trust boundary",
            "threat model",
            "abuse cases",
            "misuse cases",
            "security acceptance",
            "metric",
            "log",
            "alert",
            "runbook",
            "incident response",
        ]
        if sum(1 for term in stuffing_terms if term in lowered) >= 10:
            return f"{gate_id}.{key} evidence uses cross-gate keyword stuffing instead of focused content"
    if _looks_like_bare_assertion(text):
        return f"{gate_id}.{key} is a bare assertion: {path}"
    if len(text.split()) < 18 and "returncode:" not in lowered:
        return f"{gate_id}.{key} evidence is too shallow: {path}"
    if not _contains_concrete_evidence_reference(text):
        return f"{gate_id}.{key} evidence lacks a concrete file, command, event, or digest reference: {path}"
    git_error = _git_command_artifact_error(gate_id, key, path, text)
    if git_error:
        return git_error
    if gate_id == "deterministic_quality":
        if "returncode: 0" not in lowered:
            return f"{gate_id}.{key} must include an executed command result with returncode: 0"
        if not any(token in lowered for token in ["command:", "$ ", "python -m", "python3 -m"]):
            return f"{gate_id}.{key} must include the validation command that produced the result"
    required_markers = {
        ("architecture_contracts", "adr"): ["decision", "consequence"],
        ("architecture_contracts", "api_contracts"): ["command", "contract"],
        ("architecture_contracts", "data_contracts"): ["json", "schema"],
        ("architecture_contracts", "invariants"): ["invariant"],
        ("architecture_contracts", "failure_modes"): ["failure"],
        ("threat_model_abuse_cases", "trust_boundaries"): ["trust boundary"],
        ("threat_model_abuse_cases", "threat_model"): ["threat"],
        ("threat_model_abuse_cases", "abuse_cases"): ["abuse"],
        ("threat_model_abuse_cases", "misuse_cases"): ["misuse"],
        ("threat_model_abuse_cases", "security_acceptance_criteria"): ["acceptance"],
        ("observability_runbooks", "metrics"): ["metric"],
        ("observability_runbooks", "logs"): ["log"],
        ("observability_runbooks", "alerts"): ["alert"],
        ("observability_runbooks", "runbook"): ["runbook"],
        ("observability_runbooks", "incident_response_notes"): ["incident"],
    }
    missing = [marker for marker in required_markers.get((gate_id, key), []) if marker not in lowered]
    if missing:
        return f"{gate_id}.{key} evidence is missing marker(s): {', '.join(missing)}"
    return None


def _looks_like_boilerplate_gate_artifact(gate_id: str, key: str, text: str) -> bool:
    lowered = text.lower()
    generic_refs = [
        "tests/test_core.py",
        "sdlc/cli.py",
        "plan.json",
        "events.jsonl",
        "python -m unittest discover -s tests",
        "returncode: 0",
        "gate.required_artifact_recorded",
    ]
    generic_hits = sum(1 for ref in generic_refs if ref in lowered)
    has_digest = bool(re.search(r"\bsha256:\s*[a-f0-9]{16,}\b|\"sha256\"\s*:\s*\"[a-f0-9]{16,}\"", text, flags=re.IGNORECASE))
    has_command_transcript = _parse_command_transcript(text) is not None and "stdout:" in lowered and "stderr:" in lowered
    has_supporting_artifacts = "supporting_artifacts:" in lowered and bool(re.search(r"(?im)^supporting_artifacts:\s*(?!\s*(?:none|n/a)\s*$).+", text))
    has_gate_specific_anchor = f"{gate_id}.{key}" in lowered and f"for {gate_id}.{key}" in lowered
    if generic_hits >= 5 and not (has_digest or has_command_transcript or has_supporting_artifacts):
        return True
    if not has_gate_specific_anchor and not (has_digest or has_command_transcript or has_supporting_artifacts):
        return True
    return False


def _build_gate_artifact_bindings(
    repo: Path,
    run_dir: Path,
    gate_id: str,
    artifacts: dict[str, str],
    source_evidence: list[str],
) -> tuple[dict[str, dict[str, object]], str | None]:
    source_paths: set[Path] = set()
    for source in source_evidence:
        resolved, _canonical, error = _resolve_evidence_reference(repo, run_dir, source)
        if error or resolved is None:
            return {}, f"Gate source evidence is missing or invalid: {source}"
        source_paths.add(resolved.resolve(strict=False))

    bindings: dict[str, dict[str, object]] = {}
    for key, value in artifacts.items():
        path, canonical, error = _resolve_evidence_reference(repo, run_dir, value)
        if error or path is None or canonical is None:
            return {}, f"Gate artifact {key} is missing or invalid: {error or value}"
        if path.resolve(strict=False) in source_paths:
            return {}, f"Gate artifact {key} must reference a concrete artifact, not the source evidence summary itself"
        text = path.read_text(encoding="utf-8", errors="replace")
        content_error = _gate_artifact_content_error(gate_id, key, path, text)
        if content_error:
            return {}, content_error
        digest = _digest_file(path)
        provenance, provenance_error = _artifact_provenance(repo, run_dir, path, digest)
        if provenance_error or provenance is None:
            return {}, provenance_error or f"Gate artifact {key} lacks provenance"
        bindings[key] = {
            "reference": value,
            "path": canonical,
            "sha256": digest,
            "provenance": provenance,
        }
    return bindings, None


def _validate_release_gate_evidence(repo: Path, run_dir: Path, gate: GateState, verdict: str, evidence_paths: list[str]) -> str | None:
    if verdict not in POSITIVE_GATE_VERDICTS:
        return None
    if evidence_paths and all("gate_evidence_index" in path for path in evidence_paths):
        return f"{gate.id} requires gate-specific evidence, not only a shared evidence index"
    return _validate_gate_evidence_contract(run_dir, gate, evidence_paths)


def _validate_attestation_gate_completion(store: RunStore, plan: RunPlan, gate: GateState, verdict: str, evidence_paths: list[str]) -> str | None:
    if gate.id != "evidence_traceability_attestations" or verdict not in POSITIVE_GATE_VERDICTS:
        return None
    repo = Path(plan.repo)
    run_dir = store.run_dir(plan.run_id)
    manifest = next((path for path in evidence_paths if path.endswith("manifest.json")), "")
    signature = next((path for path in evidence_paths if path.endswith("manifest.signature.json")), "")
    verification = next((path for path in evidence_paths if path.endswith("verification.json")), "")
    if not manifest or not signature or not verification:
        return "Attestation gate requires manifest.json, manifest.signature.json, and verification.json evidence"
    manifest_path = _resolve_run_evidence_path(repo, run_dir, manifest)
    signature_path = _resolve_run_evidence_path(repo, run_dir, signature)
    verification_path = _resolve_run_evidence_path(repo, run_dir, verification)
    try:
        payload = json.loads(verification_path.read_text(encoding="utf-8"))
        manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        signature_payload = json.loads(signature_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "Attestation manifest, signature, or verification evidence is missing or invalid JSON"
    if payload.get("verified") is not True:
        return "Attestation verification evidence must record verified=true"
    if payload.get("artifact_integrity_verified") is not True:
        return "Attestation verification must record artifact_integrity_verified=true"
    blockers = payload.get("release_gate_blockers")
    if blockers:
        return "Attestation verification must record no release_gate_blockers"
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    if signature_payload.get("manifest_sha256") != manifest_sha:
        return "Attestation signature must bind the current manifest digest"
    if verification_path.stat().st_mtime < manifest_path.stat().st_mtime or verification_path.stat().st_mtime < signature_path.stat().st_mtime:
        return "Attestation verification is stale relative to manifest or signature evidence"
    snapshot_error = _attestation_snapshot_freshness_error(run_dir, manifest_payload)
    if snapshot_error:
        return snapshot_error
    events = _load_run_events(run_dir)
    verified_events = [
        event for event in events
        if event.get("event") == "attestation.verified"
        and event.get("verdict") == "GO"
        and verification in [str(item) for item in event.get("evidence", [])]
    ]
    if not verified_events:
        return "Attestation gate requires ledger-backed attestation.verified GO provenance for verification evidence"
    return None


def _resolve_run_evidence_path(repo: Path, run_dir: Path, rel: str) -> Path:
    path = Path(rel)
    if path.is_absolute():
        return path
    if rel.startswith(".sdlc/"):
        return repo / rel
    run_path = run_dir / rel
    if run_path.exists():
        return run_path
    return repo / rel


def _summary_value(text: str, key: str) -> str:
    prefix = f"{key}:"
    for line in text.splitlines():
        if line.startswith(prefix):
            return line.split(":", 1)[1].strip()
    return ""


def _load_run_events(run_dir: Path) -> list[dict[str, object]]:
    path = run_dir / "events.jsonl"
    if not path.exists():
        return []
    try:
        stat = path.stat()
    except OSError:
        return []
    cache_key = (str(path.resolve(strict=False)), stat.st_mtime_ns, stat.st_size)
    cached = _RUN_EVENTS_CACHE.get(cache_key)
    if cached is not None:
        return cached
    events: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    _RUN_EVENTS_CACHE[cache_key] = events
    return events


def _ledger_events_after(
    run_dir: Path,
    timestamp: float,
    *,
    ignored_prefixes: tuple[str, ...] = (),
    ignored_events: set[str] | None = None,
) -> list[str]:
    ignored_events = ignored_events or set()
    events: list[str] = []
    for event in _load_run_events(run_dir):
        name = str(event.get("event", ""))
        if not name or name in ignored_events or any(name.startswith(prefix) for prefix in ignored_prefixes):
            continue
        try:
            event_timestamp = datetime.fromisoformat(str(event.get("ts", ""))).timestamp()
        except ValueError:
            continue
        if event_timestamp > timestamp:
            events.append(name)
    return events


def _ledger_event_records_after(
    run_dir: Path,
    timestamp: float,
    *,
    ignored_prefixes: tuple[str, ...] = (),
    ignored_events: set[str] | None = None,
) -> list[dict[str, object]]:
    ignored_events = ignored_events or set()
    records: list[dict[str, object]] = []
    for event in _load_run_events(run_dir):
        name = str(event.get("event", ""))
        if not name or name in ignored_events or any(name.startswith(prefix) for prefix in ignored_prefixes):
            continue
        try:
            event_timestamp = datetime.fromisoformat(str(event.get("ts", ""))).timestamp()
        except ValueError:
            continue
        if event_timestamp > timestamp:
            records.append(event)
    return records


def _latest_artifact_event(run_dir: Path, *, event_name: str, path: str, sha256: str) -> dict[str, object] | None:
    for event in reversed(_load_run_events(run_dir)):
        if event.get("event") == event_name and event.get("path") == path and event.get("sha256") == sha256:
            return event
    return None


def _ledger_event_records_after_sequence(
    run_dir: Path,
    sequence: int,
    *,
    ignored_prefixes: tuple[str, ...] = (),
    ignored_events: set[str] | None = None,
) -> list[dict[str, object]]:
    ignored_events = ignored_events or set()
    records: list[dict[str, object]] = []
    for fallback_index, event in enumerate(_load_run_events(run_dir)):
        name = str(event.get("event", ""))
        if not name or name in ignored_events or any(name.startswith(prefix) for prefix in ignored_prefixes):
            continue
        event_sequence_raw = event.get("ledger_sequence")
        event_sequence = int(event_sequence_raw) if isinstance(event_sequence_raw, int) else fallback_index
        if event_sequence > sequence:
            records.append(event)
    return records


def _recorded_gate_evidence_records(run_dir: Path, gate_id: str) -> dict[str, str]:
    records: dict[str, str] = {}
    for event in _load_run_events(run_dir):
        if event.get("event") != "gate.evidence_recorded" or event.get("gate") != gate_id:
            continue
        path = event.get("path")
        sha256 = event.get("sha256")
        if isinstance(path, str) and isinstance(sha256, str):
            records[path] = sha256
    return records


def _validate_gate_evidence_contract(run_dir: Path, gate: GateState, evidence_paths: list[str]) -> str | None:
    specialized = {
        "security_scans",
        "independent_redteam_cross_model",
        "commit_branch_pr_ci",
        "evidence_traceability_attestations",
        "deploy_rollout_postdeploy",
        "final_report_reaudit",
    }
    if gate.id in specialized:
        return None
    definition = _gate_definition(gate.id)
    if definition is None:
        return f"Gate {gate.id} has no registered gate definition; positive release evidence cannot be validated"
    recorded = _recorded_gate_evidence_records(run_dir, gate.id)
    required = set(definition.required_artifacts)
    repo = run_dir.parents[2]
    expected_error = f"{gate.id} requires typed ledger-backed gate evidence containing artifact_bindings, required_artifacts, and existing source_evidence paths: {', '.join(sorted(required))}"
    for rel in evidence_paths:
        evidence_file = repo / rel
        try:
            run_rel = str(evidence_file.resolve(strict=False).relative_to(run_dir.resolve(strict=False)))
        except ValueError:
            run_rel = rel
        if run_rel not in recorded:
            continue
        try:
            if _digest_file(evidence_file) != recorded[run_rel]:
                continue
        except OSError:
            continue
        try:
            payload = json.loads(evidence_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if payload.get("gate_id") != gate.id:
            continue
        artifacts = payload.get("required_artifacts")
        if not isinstance(artifacts, dict):
            continue
        source_evidence = payload.get("source_evidence")
        if not isinstance(source_evidence, list) or not source_evidence:
            continue
        if any(not isinstance(source, str) for source in source_evidence):
            continue
        source_binding_error = _validate_source_evidence_bindings(repo, run_dir, [str(source) for source in source_evidence], payload.get("source_evidence_bindings"))
        if source_binding_error:
            continue
        if not _source_evidence_covers_required_artifacts(repo, run_dir, source_evidence, required):
            continue
        if any(_looks_like_bare_assertion(str(value)) for value in artifacts.values()):
            continue
        missing = [item for item in required if not str(artifacts.get(item, "")).strip()]
        if missing:
            continue
        bindings = payload.get("artifact_bindings")
        if not isinstance(bindings, dict):
            continue
        if set(bindings) != required:
            continue
        refreshed, binding_error = _build_gate_artifact_bindings(
            repo,
            run_dir,
            gate.id,
            {str(key): str(value) for key, value in artifacts.items()},
            [str(source) for source in source_evidence],
        )
        if binding_error:
            continue
        matches = True
        for key in required:
            current = refreshed.get(key, {})
            recorded_binding = bindings.get(key, {})
            if not isinstance(recorded_binding, dict):
                matches = False
                break
            for field in ("path", "sha256"):
                if recorded_binding.get(field) != current.get(field):
                    matches = False
                    break
            if not matches:
                break
        if matches:
            return None
    return expected_error


def _build_source_evidence_bindings(repo: Path, run_dir: Path, source_evidence: list[str]) -> tuple[list[dict[str, object]], str | None]:
    bindings: list[dict[str, object]] = []
    for source in source_evidence:
        path, canonical, error = _resolve_evidence_reference(repo, run_dir, source)
        if error or path is None or canonical is None:
            return [], f"Gate source evidence is missing or invalid: {source}"
        digest = _digest_file(path)
        provenance, provenance_error = _artifact_provenance(repo, run_dir, path, digest)
        if provenance_error or provenance is None:
            return [], provenance_error or f"Gate source evidence lacks provenance: {source}"
        bindings.append({
            "reference": source,
            "path": canonical,
            "sha256": digest,
            "provenance": provenance,
        })
    return bindings, None


def _validate_source_evidence_bindings(repo: Path, run_dir: Path, source_evidence: list[str], bindings: object) -> str | None:
    if isinstance(bindings, list):
        if len(bindings) != len(source_evidence):
            return "Gate source evidence binding count mismatch"
        for source, binding in zip(source_evidence, bindings):
            if not isinstance(binding, dict):
                return "Gate source evidence binding is invalid"
            path, canonical, error = _resolve_evidence_reference(repo, run_dir, source)
            if error or path is None or canonical is None:
                return f"Gate source evidence is missing or invalid: {source}"
            try:
                digest = _digest_file(path)
            except OSError:
                return f"Gate source evidence is unavailable: {source}"
            if binding.get("path") != canonical or binding.get("sha256") != digest:
                return "Gate source evidence digest changed after recording"
            provenance, provenance_error = _artifact_provenance(repo, run_dir, path, digest)
            if provenance_error or provenance is None:
                return provenance_error or f"Gate source evidence lacks provenance: {source}"
        return None

    # Legacy evidence did not store explicit source bindings. Keep old runs
    # usable only when the current source still matches a ledger-backed artifact.
    for source in source_evidence:
        path, _canonical, error = _resolve_evidence_reference(repo, run_dir, source)
        if error or path is None:
            return f"Gate source evidence is missing or invalid: {source}"
        try:
            digest = _digest_file(path)
        except OSError:
            return f"Gate source evidence is unavailable: {source}"
        provenance, provenance_error = _artifact_provenance(repo, run_dir, path, digest)
        if provenance_error or provenance is None:
            return provenance_error or f"Gate source evidence lacks provenance: {source}"
    return None


def _source_evidence_covers_required_artifacts(repo: Path, run_dir: Path, source_evidence: list[object], required: set[str]) -> bool:
    text = "\n".join(_run_or_repo_evidence_text(repo, run_dir, str(source)) for source in source_evidence if isinstance(source, str))
    if _contains_template_stuffed_evidence(text):
        return False
    if len(text.split()) < max(40, len(required) * 8):
        return False
    for key in required:
        pattern = rf"(?im)^(?:#+\s*)?{re.escape(key)}\s*(?::|$)"
        match = re.search(pattern, text)
        if not match:
            return False
        section = _section_after_heading(text, match.end())
        lowered_section = section.lower()
        if len(section.split()) < 12 or not _contains_concrete_evidence_reference(section):
            return False
        if not all(marker in lowered_section for marker in ["evidence_id:", "claim:", "result:"]):
            return False
    return True


def _section_after_heading(text: str, start: int) -> str:
    next_heading = re.search(r"(?m)^#{1,6}\s+", text[start:])
    if not next_heading:
        return text[start:]
    return text[start:start + next_heading.start()]


def _contains_template_stuffed_evidence(text: str) -> bool:
    lowered = text.lower()
    template_markers = [
        "supported by the active run artifacts",
        "supported by active run artifacts",
        "implementation diff, validation outputs, policy controls, and ledger events",
        "rather than a placeholder assertion",
        "decision and consequence are recorded for architecture review",
        "json schema contract and command contract are cited",
        "invariant, failure mode, trust boundary, threat model, abuse cases, misuse cases",
        "incident response details are present where relevant",
    ]
    return any(marker in lowered for marker in template_markers)


def _contains_concrete_evidence_reference(text: str) -> bool:
    categories = [
        r"\b(?:sdlc|tests|docs|scripts)/[A-Za-z0-9_.\-/]+(?:\.py|\.md|\.json|\.toml|\.sh)?(?::\d+)?",
        r"\b(?:README\.md|pyproject\.toml|requirements\.txt|Makefile|AGENTS\.md)\b",
        r"\bpython(?:3)?\s+-m\s+",
        r"\breturncode:\s*0\b",
        r"\bsha256:[a-f0-9]{16,}\b",
        r'"sha256"\s*:\s*"[a-f0-9]{16,}"',
        r'"path"\s*:\s*"(?:artifacts|worker-results)/[A-Za-z0-9_.\-/]+"',
        r"\b(?:gate|worker|redteam|attestation|deploy|finding)\.[a-z_]+\b",
        r"\b(?:diff --git|git status --short --branch|git branch --show-current)\b",
        r"\b\.sdlc/runs/[a-z0-9-]+/[A-Za-z0-9_.\-/]+",
    ]
    hits = sum(1 for pattern in categories if re.search(pattern, text, flags=re.IGNORECASE))
    if hits < 2:
        return False
    generic_only = re.fullmatch(r"(?is).*concrete references?:\s*(?:artifacts|worker-results|\.sdlc)/[A-Za-z0-9_.\-/]+\s*\.?\s*", text.strip())
    return generic_only is None


def _attestation_snapshot_freshness_error(run_dir: Path, manifest_payload: dict[str, Any]) -> str | None:
    snapshots = {
        "plan.json": "artifacts/attestations/control-snapshots/plan.json",
        "findings.json": "artifacts/attestations/control-snapshots/findings.json",
        "events.jsonl": "artifacts/attestations/control-snapshots/events.jsonl",
        "final-report.md": "artifacts/attestations/control-snapshots/final-report.md",
        "artifacts/release/readiness.json": "artifacts/attestations/control-snapshots/release-readiness.json",
    }
    manifest_entries = manifest_payload.get("artifacts", [])
    if not isinstance(manifest_entries, list):
        return "Attestation manifest artifacts must be a list"
    manifest_digests = {
        str(item.get("path")): str(item.get("sha256"))
        for item in manifest_entries
        if isinstance(item, dict)
    }
    for source_name, snapshot_rel in snapshots.items():
        source = run_dir / source_name
        if not source.exists():
            continue
        snapshot = run_dir / snapshot_rel
        if not snapshot.exists():
            return f"Attestation control snapshot is missing: {snapshot_rel}"
        expected = _attestation_control_snapshot_content(run_dir, source_name, source)
        if snapshot.read_text(encoding="utf-8", errors="replace") != expected:
            return f"Attestation control snapshot is stale relative to {source_name}"
        snapshot_sha = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        if manifest_digests.get(snapshot_rel) != snapshot_sha:
            return f"Attestation manifest does not cover current control snapshot: {snapshot_rel}"
    return None


def _attestation_control_snapshot_content(run_dir: Path, source_name: str, source: Path) -> str:
    if source_name == "events.jsonl":
        lines: list[str] = []
        for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
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
    if source_name == "plan.json":
        plan_snapshot = read_json(source, {})
        if isinstance(plan_snapshot, dict):
            plan_snapshot = json.loads(json.dumps(plan_snapshot))
            gates = plan_snapshot.get("gates")
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
        return json.dumps(plan_snapshot, indent=2, sort_keys=True) + "\n"
    if source_name in {"findings.json", "artifacts/release/readiness.json"}:
        return json.dumps(read_json(source, [] if source_name == "findings.json" else {}), indent=2, sort_keys=True) + "\n"
    return source.read_text(encoding="utf-8", errors="replace")


def _looks_like_bare_assertion(value: str) -> bool:
    stripped = value.strip().lower()
    if not stripped:
        return True
    if stripped in {"evidence", "ok", "done", "complete", "completed", "passed", "n/a", "na"}:
        return True
    if stripped.endswith(" evidence") and len(stripped.split()) <= 4:
        return True
    return False


def _validate_redteam_gate_completion(store: RunStore, plan: RunPlan, gate: GateState, verdict: str, evidence_paths: list[str]) -> str | None:
    if gate.id not in {"independent_redteam_cross_model", "critical_high_fix_loop"} or verdict not in POSITIVE_GATE_VERDICTS:
        return None
    findings = store.load_findings(plan.run_id)
    if open_findings(findings, {"CRITICAL", "HIGH"}):
        return f"{gate.id} cannot be positive while CRITICAL/HIGH findings are open"
    summary_rel = next((path for path in evidence_paths if path.endswith("redteam_execution_summary.md")), "")
    if not summary_rel:
        return f"{gate.id} requires redteam_execution_summary.md evidence"
    summary_path = store.run_dir(plan.run_id) / summary_rel if not summary_rel.startswith(".sdlc/") else Path(plan.repo) / summary_rel
    if not summary_path.exists():
        return "Red-team execution summary evidence is missing"
    summary = summary_path.read_text(encoding="utf-8")
    if _summary_value(summary, "execute_requested") != "True":
        return "Red-team gate requires executed worker evidence, not dry-run evidence"
    if _summary_value(summary, "verdict") not in POSITIVE_GATE_VERDICTS:
        return "Red-team execution summary must have a positive verdict"
    policy = load_policy(Path(plan.repo), plan.policy_profile)
    min_rounds = int(policy.get("redteam", {}).get("min_rounds_high_stakes", 1) or 1)
    if plan.risk_level in {"HIGH", "EXTREME"} and int(_summary_value(summary, "rounds") or "0") < min_rounds:
        return f"Red-team summary does not satisfy policy minimum rounds: {min_rounds}"
    executed = [item.strip() for item in _summary_value(summary, "executed_families").split(",") if item.strip() and item.strip() != "<none>"]
    if plan.risk_level in {"HIGH", "EXTREME"} and len(set(executed)) < 2:
        return "Red-team summary must include at least two executed worker families"
    summary_groups = [item.strip() for item in _summary_value(summary, "executed_model_groups").split(",") if item.strip() and item.strip() != "<none>"]
    executed_groups = set(summary_groups) if summary_groups else {worker_identity_group(worker, policy) for worker in executed}
    if plan.risk_level in {"HIGH", "EXTREME"} and len(executed_groups) < 2:
        return "Red-team summary must include at least two distinct executed model identities"
    run_dir = store.run_dir(plan.run_id)
    events = _load_run_events(run_dir)
    try:
        event_summary_rel = str(summary_path.resolve().relative_to(run_dir.resolve()))
    except ValueError:
        event_summary_rel = summary_rel
    completed = [
        event for event in events
        if event.get("event") == "redteam.execution_completed"
        and event.get("verdict") in POSITIVE_GATE_VERDICTS
        and event_summary_rel in [str(item) for item in event.get("evidence", [])]
    ]
    if not completed:
        return "Red-team GO requires ledger-backed redteam.execution_completed evidence for the supplied summary"
    latest = completed[-1]
    if latest.get("execute_requested") is not True:
        return "Red-team ledger evidence must record execute_requested=true"
    latest_worker_verdicts = latest.get("worker_verdicts", [])
    if not isinstance(latest_worker_verdicts, list):
        return "Red-team ledger evidence has malformed worker verdict bindings"
    if not latest_worker_verdicts:
        return "Red-team ledger evidence must include worker verdict bindings"
    unverified_positive = [
        item for item in latest_worker_verdicts
        if isinstance(item, dict)
        and item.get("verdict") in POSITIVE_GATE_VERDICTS
        and item.get("context_attested") is not True
    ]
    if unverified_positive:
        workers = ", ".join(f"{item.get('worker')}@round{item.get('round')}" for item in unverified_positive)
        return "Red-team GO requires every positive worker verdict to bind reviewed_run_id and prompt_sha256: " + workers
    if int(latest.get("rounds") or 0) < min_rounds and plan.risk_level in {"HIGH", "EXTREME"}:
        return f"Red-team ledger evidence does not satisfy policy minimum rounds: {min_rounds}"
    latest_executed = {str(item) for item in latest.get("executed_families", [])}
    if plan.risk_level in {"HIGH", "EXTREME"} and len(latest_executed) < 2:
        return "Red-team ledger evidence must include at least two executed worker families"
    latest_groups_raw = latest.get("executed_identity_groups") or latest.get("executed_model_groups") or []
    latest_groups = {str(item) for item in latest_groups_raw if str(item)}
    if not latest_groups:
        latest_groups = {worker_identity_group(worker, policy) for worker in latest_executed}
    if plan.risk_level in {"HIGH", "EXTREME"} and len(latest_groups) < 2:
        return "Red-team ledger evidence must include at least two distinct executed model identities"
    completed_workers = [
        event for event in events
        if event.get("event") == "worker.completed"
        and str(event.get("mode", "")).startswith("REDTEAM_ROUND_")
        and event.get("executed") is True
        and event.get("returncode") == 0
    ]
    completed_families = {str(event.get("worker")) for event in completed_workers}
    if not latest_executed.issubset(completed_families):
        return "Red-team ledger evidence is missing matching successful worker.completed events"
    return None


def _validate_deploy_gate_completion(store: RunStore, plan: RunPlan, gate: GateState, verdict: str) -> str | None:
    if gate.id != "deploy_rollout_postdeploy" or verdict not in POSITIVE_GATE_VERDICTS:
        return None
    if not plan.production_rollout_allowed:
        return "Deployment gate cannot use a positive verdict unless production rollout is explicitly allowed"
    return production_deploy_gate_rejection(store, plan.run_id, verdict)


def _actor_proof_error(run_id: str, finding_id: str, actor: str, proof: str | None, *, repo: Path | None = None, run_dir: Path | None = None) -> str | None:
    key_text = os.environ.get("SDLC_ACTOR_PROOF_KEY", "")
    key_file = os.environ.get("SDLC_ACTOR_PROOF_KEY_FILE", "")
    if not key_text and key_file:
        try:
            key_path = Path(key_file).resolve(strict=True)
            if _key_path_inside_boundary(key_path, repo, run_dir):
                return "Actor proof key file must be outside the repository and run artifacts"
            key_text = key_path.read_text(encoding="utf-8").strip()
        except OSError:
            return "Actor proof key file is unavailable"
    if not key_text:
        return "Actor proof is required; set SDLC_ACTOR_PROOF_KEY or SDLC_ACTOR_PROOF_KEY_FILE outside the repo"
    if not proof:
        return "Actor proof is required for finding closure by policy"
    message = f"{run_id}:{finding_id}:{actor}:finding.close".encode("utf-8")
    expected = hmac.new(key_text.encode("utf-8"), message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(proof, expected):
        return "Actor proof verification failed"
    return None


def _key_path_inside_boundary(key_path: Path, repo: Path | None, run_dir: Path | None) -> bool:
    for base in (repo, run_dir):
        if base is None:
            continue
        try:
            key_path.relative_to(base.resolve(strict=False))
            return True
        except ValueError:
            continue
    return False


def _finding_close_error(
    repo: Path,
    run_dir: Path,
    finding: Finding,
    closed_by: str,
    evidence_paths: list[str],
    *,
    policy: dict[str, Any] | None = None,
    actor_proof: str | None = None,
    plan: RunPlan | None = None,
    findings: list[Finding] | None = None,
) -> str | None:
    if closed_by == finding.owner or closed_by == "agent_3_implementation_owner":
        return "Implementer/owner cannot close its own finding"
    if closed_by not in AUTHORIZED_FINDING_CLOSERS:
        return "Finding close requires an authorized independent red-team or human approval actor"
    policy = policy or {}
    if policy.get("actor_proof_required_for_finding_closure") is True and finding.severity in {"CRITICAL", "HIGH"}:
        proof_error = _actor_proof_error(run_dir.name, finding.id, closed_by, actor_proof, repo=repo, run_dir=run_dir)
        if proof_error:
            return proof_error
    if _is_run_state_finding(finding) and plan is not None:
        evidence_text = "\n".join(_evidence_text(repo, item) for item in evidence_paths)
        strict_run_state_finding = finding.id.startswith(("RT-", "CRITICAL-RT", "HIGH-RT"))
        projected_findings = [item for item in (findings or []) if item.id != finding.id]
        projected_verdict = final_verdict(projected_findings, plan)
        if strict_run_state_finding and projected_verdict not in POSITIVE_GATE_VERDICTS:
            return "Run-state finding closure requires the authoritative gate verdict to be positive before closure"
        if _closure_evidence_claims_release_ready(evidence_text) and projected_verdict not in POSITIVE_GATE_VERDICTS:
            return "Run-state finding closure evidence cannot claim release readiness while the computed run state is NO_GO"
    if finding.severity in {"CRITICAL", "HIGH", "MEDIUM"}:
        ledger_backed = _ledger_backed_closure_artifacts(repo, run_dir, evidence_paths)
        if len(ledger_backed) < len(evidence_paths):
            return "CRITICAL/HIGH/MEDIUM closure evidence must be ledger-backed run artifacts with matching sha256 provenance"
        evidence_text = "\n".join(str(item.get("text", "")) for item in ledger_backed).lower()
        lowered = (" ".join(evidence_paths) + "\n" + evidence_text).lower()
        if finding.id.lower() not in lowered and finding.title.lower() not in lowered:
            return "CRITICAL/HIGH/MEDIUM closure evidence must reference the specific finding id or title"
        has_diff = any(
            item.get("event") in {"finding.remediation_diff", "remediation.diff_artifact"}
            and item.get("finding_id") == finding.id
            and "diff --git" in str(item.get("text", "")).lower()
            for item in ledger_backed
        )
        has_summary = any(
            item.get("event") in {"finding.remediation_summary", "remediation.summary"}
            and item.get("finding_id") == finding.id
            and (finding.id.lower() in str(item.get("text", "")).lower() or finding.title.lower() in str(item.get("text", "")).lower())
            for item in ledger_backed
        )
        has_validation = any(
            _valid_independent_remediation_validation(
                item,
                finding=finding,
                closed_by=closed_by,
                actor_proof=actor_proof,
                require_actor_proof=bool(policy.get("actor_proof_required_for_finding_closure"))
                and finding.severity in {"CRITICAL", "HIGH"},
            )
            for item in ledger_backed
        )
        if not has_diff:
            return "CRITICAL/HIGH/MEDIUM closure requires ledger-backed remediation diff evidence for this finding id"
        if not has_validation:
            return "CRITICAL/HIGH/MEDIUM closure requires ledger-backed independent second-validation evidence with returncode: 0 for this finding id"
        if not has_summary:
            return "CRITICAL/HIGH/MEDIUM closure requires a ledger-backed remediation summary for this finding id"
    return None


def _valid_independent_remediation_validation(
    item: dict[str, object],
    *,
    finding: Finding,
    closed_by: str,
    actor_proof: str | None = None,
    require_actor_proof: bool = False,
) -> bool:
    if item.get("event") not in {"finding.remediation_validation", "remediation.validation_artifact"}:
        return False
    if item.get("finding_id") != finding.id or item.get("returncode") != 0:
        return False
    if "returncode: 0" not in str(item.get("text", "")).lower():
        return False
    if closed_by == finding.owner or closed_by == "agent_3_implementation_owner":
        return False
    if closed_by not in AUTHORIZED_FINDING_CLOSERS:
        return False
    if item.get("validated_by") != closed_by:
        return False
    if require_actor_proof:
        proof_hash = item.get("validator_actor_proof_sha256")
        if not isinstance(proof_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", proof_hash):
            return False
        if actor_proof is not None:
            expected = hashlib.sha256(actor_proof.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(proof_hash, expected):
                return False
    return True


def _blocking_acceptance_evidence_error(
    repo: Path,
    run_dir: Path,
    finding: Finding,
    evidence_paths: list[str],
    reason: str,
    *,
    require_origin: bool = True,
) -> str | None:
    ledger_backed = _ledger_backed_closure_artifacts(repo, run_dir, evidence_paths, require_origin=require_origin)
    if len(ledger_backed) < len(evidence_paths):
        return "CRITICAL/HIGH/MEDIUM acceptance evidence must be ledger-backed run artifacts with matching sha256 provenance"
    evidence_text = "\n".join(str(item.get("text", "")) for item in ledger_backed)
    lowered = f"{reason}\n{' '.join(evidence_paths)}\n{evidence_text}".lower()
    if finding.id.lower() not in lowered and finding.title.lower() not in lowered:
        return "CRITICAL/HIGH/MEDIUM acceptance evidence must reference the specific finding id or title"
    if not any(marker in lowered for marker in ["residual risk", "risk acceptance", "accepted risk", "deferred risk"]):
        return "CRITICAL/HIGH/MEDIUM acceptance evidence must include a residual-risk rationale"
    return None


def _run_state_acceptance_error(
    repo: Path,
    plan: RunPlan,
    findings: list[Finding],
    finding: Finding,
    evidence_paths: list[str],
    reason: str,
) -> str | None:
    if not _is_run_state_finding(finding):
        return None
    evidence_text = "\n".join(_evidence_text(repo, item) for item in evidence_paths)
    projected_findings = [item for item in findings if item.id != finding.id]
    projected_verdict = final_verdict(projected_findings, plan)
    if _closure_evidence_claims_release_ready(f"{reason}\n{evidence_text}") and projected_verdict not in POSITIVE_GATE_VERDICTS:
        return "Run-state finding acceptance evidence cannot claim release readiness while the computed run state is NO_GO"
    return None


def _is_run_state_finding(finding: Finding) -> bool:
    text = f"{finding.id} {finding.title} {finding.impact} {finding.required_fix}".lower()
    markers = [
        "run is still no_go",
        "run is still no-go",
        "active release run",
        "active red-team run",
        "release-blocker run",
        "run state",
        "red-team gate remains no_go",
        "red-team gate remains no-go",
        "final verdict",
        "production-grade claims",
    ]
    return any(marker in text for marker in markers) or finding.id.startswith(("RT-", "CRITICAL-RT", "HIGH-RT"))


def _closure_evidence_claims_release_ready(text: str) -> bool:
    lowered = text.lower()
    claim_markers = [
        "production-ready",
        "production ready",
        "release-ready",
        "release ready",
        "run is ready",
        "ready for production",
        "redteam_go_remediation_summary",
        "red-team go",
    ]
    return any(marker in lowered for marker in claim_markers)


def _managed_worker_control_plane_error(repo: Path, run_id: str, actor: str | None = None) -> str | None:
    if os.environ.get("SDLC_WORKER_EXECUTION") != "1":
        return None
    actor_note = f" for actor {actor}" if actor else ""
    return f"Managed worker processes cannot mutate control-plane gates, evidence, or findings{actor_note}; the orchestrator must record those events."


def _ledger_backed_artifacts(repo: Path, run_dir: Path, evidence_paths: list[str], allowed_events: set[str], *, require_origin: bool = True) -> list[dict[str, object]]:
    artifact_index = _canonical_artifact_index(run_dir, allowed_events=allowed_events, require_origin=require_origin)
    backed: list[dict[str, object]] = []
    for rel in evidence_paths:
        path = _resolve_run_evidence_path(repo, run_dir, rel)
        run_rel = _run_relative_path(run_dir, path)
        if run_rel is None or not path.exists() or not path.is_file():
            continue
        digest = _digest_file(path)
        event = artifact_index.get((run_rel, digest))
        if event is None:
            continue
        payload = dict(event)
        payload["text"] = path.read_text(encoding="utf-8", errors="replace")
        backed.append(payload)
    return backed


def _ledger_backed_closure_artifacts(repo: Path, run_dir: Path, evidence_paths: list[str], *, require_origin: bool = True) -> list[dict[str, object]]:
    return _ledger_backed_artifacts(repo, run_dir, evidence_paths, FINDING_CLOSURE_ARTIFACT_EVENTS, require_origin=require_origin)


def _default_feature_branch(run_id: str) -> str:
    return f"sdlc/{slugify(run_id, max_len=64)}"


def _is_protected_branch(branch: str) -> bool:
    return branch in PROTECTED_BRANCHES


def _reject_git_operation(ledger: Ledger, action: str, reason: str, **kwargs: object) -> int:
    ledger.event("git.operation_rejected", action=action, reason=reason, **kwargs)
    eprint(reason)
    return 3


def _protected_branch_allowed(plan: RunPlan, allow_flag: bool) -> bool:
    return allow_flag and plan.direct_main_push_allowed


def _ensure_git_repo(repo: Path, ledger: Ledger, action: str) -> int | None:
    if is_git_repo(repo):
        return None
    return _reject_git_operation(ledger, action, "Repository is not a git repository")


def _git_command_payload(repo: Path, command: list[str], *, timeout: int = 30) -> dict[str, object]:
    result = run_cmd(command, repo, timeout=timeout)
    stdout = str(result.get("stdout", ""))
    stderr = str(result.get("stderr", ""))
    return {
        "command": command,
        "cwd": str(repo),
        "timestamp": now_iso(),
        "returncode": int(result.get("returncode", 1)),
        "stdout": stdout,
        "stderr": stderr,
        "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
        "stdout_truncated": bool(result.get("stdout_truncated", False)),
        "stderr_truncated": bool(result.get("stderr_truncated", False)),
    }


def _latest_git_event(events: list[dict[str, object]], event_name: str, *, branch: str | None = None) -> dict[str, object] | None:
    for event in reversed(events):
        if event.get("event") != event_name:
            continue
        if branch is not None and event.get("branch") != branch:
            continue
        return event
    return None


def _write_git_provenance_artifact(repo: Path, plan: RunPlan, ledger: Ledger) -> str:
    events = _load_run_events(ledger.run_dir)
    commands = {
        "inside_work_tree": _git_command_payload(repo, ["git", "rev-parse", "--is-inside-work-tree"]),
        "current_branch": _git_command_payload(repo, ["git", "branch", "--show-current"]),
        "status_short": _git_command_payload(repo, ["git", "status", "--short", "--branch"]),
        "remote_summary": _git_command_payload(repo, ["git", "remote", "-v"]),
        "head_sha": _git_command_payload(repo, ["git", "rev-parse", "HEAD"]),
        "head_subject": _git_command_payload(repo, ["git", "log", "-1", "--pretty=%s"]),
    }
    current_branch = str(commands["current_branch"].get("stdout", "")).strip()
    head_sha = str(commands["head_sha"].get("stdout", "")).strip()
    head_subject = str(commands["head_subject"].get("stdout", "")).strip()
    commit_event = _latest_git_event(events, "git.commit_created", branch=current_branch)
    pr_created = _latest_git_event(events, "git.pr_created", branch=current_branch)
    pr_planned = _latest_git_event(events, "git.pr_planned", branch=current_branch)
    pr_event = pr_created or pr_planned
    ci_source_gates = {
        gate.id: {"state": gate.state, "verdict": gate.verdict}
        for gate in plan.gates
        if gate.id in {"deterministic_quality", "qa_tests_integration_smoke", "security_scans"}
    }
    ci_passed = all(
        state.get("state") == "GO" and state.get("verdict") in POSITIVE_GATE_VERDICTS
        for state in ci_source_gates.values()
    ) and len(ci_source_gates) == 3
    payload = {
        "schema_version": 1,
        "run_id": plan.run_id,
        "captured_at": now_iso(),
        "repo": str(repo),
        "expected_branch": plan.branch,
        "branch": {
            "current": current_branch,
            "protected": _is_protected_branch(current_branch),
            "matches_plan": bool(current_branch and current_branch == plan.branch),
        },
        "head": {
            "sha": head_sha,
            "subject": head_subject,
            "exists": bool(re.fullmatch(r"[0-9a-fA-F]{40}", head_sha or "")),
        },
        "commit": {
            "message": str(commit_event.get("message", "")) if commit_event else "",
            "created_by_sdlc": bool(commit_event and commit_event.get("commit") == head_sha),
            "artifact": (commit_event.get("evidence") or [""])[0] if commit_event else "",
        },
        "working_tree": {
            "status_short": str(commands["status_short"].get("stdout", "")),
            "clean": not _git_status_dirty_entries(str(commands["status_short"].get("stdout", ""))),
        },
        "pr": {
            "mode": "created" if pr_created else "planned" if pr_planned else "not_available",
            "artifact": (pr_event.get("evidence") or [""])[0] if pr_event else "",
        },
        "ci": {
            "mode": "local_release_gate_state",
            "status": "passed" if ci_passed else "failed",
            "source_gates": ci_source_gates,
        },
        "commands": commands,
        "environment": {
            "ci": bool(os.environ.get("CI")),
            "github_run_id_present": bool(os.environ.get("GITHUB_RUN_ID")),
        },
    }
    artifact = ledger.artifact(
        "artifacts/git/provenance.json",
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        event="git.provenance_artifact",
        branch=current_branch,
        head=head_sha,
    )
    ledger.event("git.provenance_recorded", branch=current_branch, head=head_sha, evidence=[artifact])
    return artifact


def _command_result_error(command: dict[str, object], expected: list[str], label: str) -> str | None:
    if _normalize_command(command.get("command")) != " ".join(expected):
        return f"Git provenance command {label} must be `{shlex.join(expected)}`"
    if command.get("returncode") != 0:
        return f"Git provenance command {label} must record returncode 0"
    if not command.get("cwd"):
        return f"Git provenance command {label} must record cwd"
    if not command.get("timestamp"):
        return f"Git provenance command {label} must record timestamp"
    output = f"{command.get('stdout', '')}\n{command.get('stderr', '')}".lower()
    if "not a git repository" in output or "fatal:" in output:
        return f"Git provenance command {label} records a git failure"
    return None


def _validate_git_provenance_payload(plan: RunPlan, payload: dict[str, object]) -> str | None:
    if payload.get("schema_version") != 1 or payload.get("run_id") != plan.run_id:
        return "Git provenance artifact has the wrong schema_version or run_id"
    commands = payload.get("commands")
    if not isinstance(commands, dict):
        return "Git provenance artifact is missing command captures"
    required_commands = {
        "inside_work_tree": ["git", "rev-parse", "--is-inside-work-tree"],
        "current_branch": ["git", "branch", "--show-current"],
        "status_short": ["git", "status", "--short", "--branch"],
        "remote_summary": ["git", "remote", "-v"],
        "head_sha": ["git", "rev-parse", "HEAD"],
        "head_subject": ["git", "log", "-1", "--pretty=%s"],
    }
    for label, expected in required_commands.items():
        command = commands.get(label)
        if not isinstance(command, dict):
            return f"Git provenance artifact is missing {label}"
        command_error = _command_result_error(command, expected, label)
        if command_error:
            return command_error
    if str(commands["inside_work_tree"].get("stdout", "")).strip() != "true":
        return "Git provenance must prove the workspace is inside a git work tree"
    branch = payload.get("branch")
    if not isinstance(branch, dict):
        return "Git provenance artifact is missing branch metadata"
    current_branch = str(branch.get("current", "")).strip()
    if not current_branch or current_branch in {"HEAD", "unknown", "<unknown>"}:
        return "Git provenance must record a concrete current branch"
    if current_branch != str(commands["current_branch"].get("stdout", "")).strip():
        return "Git provenance branch metadata does not match command output"
    if plan.branch in {"", "unknown", "<unknown>"} or current_branch != plan.branch or branch.get("matches_plan") is not True:
        return f"Git provenance branch {current_branch} does not match run plan branch {plan.branch}"
    if _is_protected_branch(current_branch) and not plan.direct_main_push_allowed:
        return f"Git provenance rejects protected branch {current_branch} without explicit policy"
    status_short = str(commands["status_short"].get("stdout", ""))
    if "## " not in status_short:
        return "Git provenance status command must include branch status output"
    dirty_entries = _git_status_dirty_entries(status_short)
    if dirty_entries:
        return "Git provenance requires a clean working tree; dirty entries: " + ", ".join(dirty_entries[:5])
    working_tree = payload.get("working_tree")
    if isinstance(working_tree, dict) and working_tree.get("clean") is False:
        return "Git provenance requires working_tree.clean=true"
    head = payload.get("head")
    if not isinstance(head, dict) or head.get("exists") is not True:
        return "Git provenance must record an existing HEAD commit"
    head_sha = str(head.get("sha", "")).strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40}", head_sha):
        return "Git provenance HEAD sha is invalid"
    if head_sha != str(commands["head_sha"].get("stdout", "")).strip():
        return "Git provenance HEAD metadata does not match command output"
    commit = payload.get("commit")
    if not isinstance(commit, dict) or commit.get("created_by_sdlc") is not True:
        return "Git provenance must prove the release commit was created by `sdlc git commit`"
    if not COMMIT_MESSAGE_RE.match(str(commit.get("message", ""))):
        return "Git provenance commit message must use `verb: subject` discipline"
    pr = payload.get("pr")
    if not isinstance(pr, dict) or pr.get("mode") not in {"planned", "created"}:
        return "Git provenance must include a PR plan or created PR evidence"
    ci = payload.get("ci")
    if not isinstance(ci, dict) or ci.get("status") != "passed":
        return "Git provenance must record passed local CI/release gate status"
    return None


def _git_status_dirty_entries(status_short: str) -> list[str]:
    dirty: list[str] = []
    for raw_line in status_short.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        if line.startswith("## "):
            continue
        dirty.append(line)
    return dirty


def _release_git_provenance_source_error(store: RunStore, plan: RunPlan, *, audit_workspace: bool) -> str | None:
    repo = store.repo
    if not audit_workspace:
        if _is_git_repo_available(repo):
            return None
        return "Release validation requires the repository root to be a git work tree"

    plan_repo = Path(plan.repo).resolve(strict=False)
    if _is_git_repo_available(plan_repo):
        if _plan_repo_matches_run_created_source(store.run_dir(plan.run_id), plan_repo):
            return None

    snapshot_error = _attested_git_provenance_snapshot_error(plan, store.run_dir(plan.run_id))
    if snapshot_error is None:
        return None
    return "Audit-workspace release validation requires plan.repo to match the ledger-bound run.created source repo or a valid attested git provenance snapshot: " + snapshot_error


def _is_git_repo_available(repo: Path) -> bool:
    try:
        return is_git_repo(repo)
    except OSError:
        return False


def _repo_identity_sha256(repo: Path) -> str:
    return hashlib.sha256(str(repo.resolve(strict=False)).encode("utf-8")).hexdigest()


def _plan_repo_matches_run_created_source(run_dir: Path, plan_repo: Path) -> bool:
    expected = str(plan_repo.resolve(strict=False))
    expected_digest = _repo_identity_sha256(plan_repo)
    for event in _load_run_events(run_dir):
        if event.get("event") != "run.created":
            continue
        repo_value = event.get("repo")
        repo_digest = event.get("repo_sha256")
        if not isinstance(repo_value, str) or not isinstance(repo_digest, str):
            return False
        if str(Path(repo_value).resolve(strict=False)) == expected and hmac.compare_digest(repo_digest, expected_digest):
            return True
        return False
    return False


def _attested_git_provenance_snapshot_error(plan: RunPlan, run_dir: Path) -> str | None:
    provenance_rel = "artifacts/git/provenance.json"
    provenance_path = run_dir / provenance_rel
    manifest_path = run_dir / "artifacts" / "attestations" / "manifest.json"
    verification_path = run_dir / "artifacts" / "attestations" / "verification.json"
    if not provenance_path.exists():
        return f"missing {provenance_rel}"
    if not manifest_path.exists() or not verification_path.exists():
        return "missing attestation manifest or verification artifact"
    try:
        provenance_payload = json.loads(provenance_path.read_text(encoding="utf-8"))
        manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        verification_payload = json.loads(verification_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "git provenance, attestation manifest, or verification artifact is invalid JSON"
    if not isinstance(provenance_payload, dict) or not isinstance(manifest_payload, dict) or not isinstance(verification_payload, dict):
        return "git provenance, attestation manifest, and verification artifact must be JSON objects"
    payload_error = _validate_git_provenance_payload(plan, provenance_payload)
    if payload_error:
        return payload_error
    if verification_payload.get("verified") is not True or verification_payload.get("artifact_integrity_verified") is not True:
        return "attestation verification must record verified=true and artifact_integrity_verified=true"
    manifest_entries = manifest_payload.get("artifacts", [])
    if not isinstance(manifest_entries, list):
        return "attestation manifest artifacts must be a list"
    provenance_sha = _digest_file(provenance_path)
    if not any(isinstance(item, dict) and item.get("path") == provenance_rel and item.get("sha256") == provenance_sha for item in manifest_entries):
        return f"attestation manifest does not bind current {provenance_rel}"
    snapshot_error = _attestation_snapshot_freshness_error(run_dir, manifest_payload)
    if snapshot_error:
        return snapshot_error
    manifest_sha = _digest_file(manifest_path)
    verification_sha = _digest_file(verification_path)
    manifest_event = _ledger_artifact_event(run_dir, manifest_path, manifest_sha)
    verification_event = _ledger_artifact_event(run_dir, verification_path, verification_sha)
    if not manifest_event or manifest_event.get("event") != "attestation.manifest_written":
        return "attestation manifest lacks matching ledger provenance"
    if not verification_event or verification_event.get("event") != "attestation.verification_artifact":
        return "attestation verification lacks matching ledger provenance"
    verified_events = [
        event for event in _load_run_events(run_dir)
        if event.get("event") == "attestation.verified"
        and event.get("verdict") == "GO"
        and "artifacts/attestations/verification.json" in [str(item) for item in event.get("evidence", [])]
    ]
    if not verified_events:
        return "attestation.verified GO ledger event is missing"
    return None


def _post_commit_validation_errors(events: list[dict[str, object]]) -> list[str]:
    latest_commit = max((index for index, event in enumerate(events) if event.get("event") == "git.commit_created"), default=-1)
    if latest_commit < 0:
        return []
    required: dict[str, tuple[str, Any]] = {
        "deterministic_quality": (
            "deterministic quality gate completion",
            lambda event: event.get("event") in {"gate.manually_completed", "gate.completed"}
            and event.get("gate") == "deterministic_quality"
            and event.get("verdict") in POSITIVE_GATE_VERDICTS,
        ),
        "qa_tests_integration_smoke": (
            "QA gate completion",
            lambda event: event.get("event") in {"gate.manually_completed", "gate.completed"}
            and event.get("gate") == "qa_tests_integration_smoke"
            and event.get("verdict") in POSITIVE_GATE_VERDICTS,
        ),
        "security_scans": (
            "security scan completion",
            lambda event: event.get("event") == "security.scans_completed"
            and event.get("verdict") in POSITIVE_GATE_VERDICTS,
        ),
        "independent_redteam_cross_model": (
            "red-team execution completion",
            lambda event: event.get("event") == "redteam.execution_completed"
            and event.get("verdict") in POSITIVE_GATE_VERDICTS,
        ),
    }
    errors: list[str] = []
    for gate_id, (label, predicate) in required.items():
        if not any(predicate(event) for event in events[latest_commit + 1:]):
            errors.append(f"Post-commit release evidence is stale: {gate_id} requires {label} after the latest sdlc git commit")
    return errors


def _validate_git_provenance_gate_completion(
    store: RunStore,
    plan: RunPlan,
    gate: GateState,
    verdict: str,
    evidence_paths: list[str],
    *,
    audit_workspace: bool = False,
) -> str | None:
    if gate.id != "commit_branch_pr_ci" or verdict not in POSITIVE_GATE_VERDICTS:
        return None
    repo = store.repo
    source_error = _release_git_provenance_source_error(store, plan, audit_workspace=audit_workspace)
    if source_error:
        return "Release validation requires git provenance for commit/branch/PR/CI: " + source_error
    run_dir = store.run_dir(plan.run_id)
    for rel in evidence_paths:
        path, canonical, error = _resolve_evidence_reference(repo, run_dir, rel)
        if error or path is None or canonical is None:
            continue
        digest = _digest_file(path)
        provenance, provenance_error = _artifact_provenance(repo, run_dir, path, digest)
        if provenance_error or provenance is None or provenance.get("event") != "git.provenance_artifact":
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return "Git provenance artifact must be valid JSON"
        if not isinstance(payload, dict):
            return "Git provenance artifact must be a JSON object"
        return _validate_git_provenance_payload(plan, payload)
    return "Commit/branch/PR/CI gate requires ledger-backed artifacts/git/provenance.json from `sdlc git provenance`"


def _blocking_finding_ids(findings: list[Finding]) -> list[str]:
    return [finding.id for finding in open_findings(findings, {"CRITICAL", "HIGH", "MEDIUM"})]


def _blocking_commit_gate_ids(plan: RunPlan) -> list[str]:
    blocking: list[str] = []
    for gate in sorted(plan.gates, key=lambda item: item.order):
        if gate.order > 22:
            continue
        if gate.state == "SKIPPED" and gate.verdict == "SKIPPED":
            continue
        if not _gate_satisfied(gate, plan):
            blocking.append(f"{gate.id}={gate.state}/{gate.verdict or 'PENDING'}")
            continue
        if gate.state == "GO" and not gate.evidence:
            blocking.append(f"{gate.id}=missing evidence")
    return blocking


def _worker_execution_policy_error(policy: dict[str, object], *, execute: bool, allow_network: bool) -> str | None:
    if not execute:
        return None
    if not allow_network or not bool(policy.get("network_allowed", False)):
        return "Executed worker commands require --allow-network and policy network_allowed=true"
    return None


def _deny_path_snapshot(repo: Path, deny_paths: list[str]) -> dict[str, bytes]:
    snapshot: dict[str, bytes] = {}
    for pattern in deny_paths:
        for path in repo.glob(pattern):
            if not path.is_file():
                continue
            try:
                rel = str(path.resolve().relative_to(repo))
            except ValueError:
                continue
            snapshot[rel] = path.read_bytes()
    return snapshot


def _deny_path_changes(repo: Path, deny_paths: list[str], before: dict[str, bytes]) -> list[str]:
    after = _deny_path_snapshot(repo, deny_paths)
    changed = [path for path, content in after.items() if before.get(path) != content]
    removed = [path for path in before if path not in after]
    return sorted(set(changed + removed))


def _restore_denied_paths(repo: Path, deny_paths: list[str], before: dict[str, bytes]) -> None:
    after_paths = set(_deny_path_snapshot(repo, deny_paths))
    for rel in sorted(after_paths - set(before)):
        path = repo / rel
        if path.is_file():
            path.unlink()
    for rel, content in before.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def _repo_snapshot(repo: Path) -> dict[str, str]:
    return {
        rel: hashlib.sha256(content).hexdigest()
        for rel, content in _repo_content_snapshot(repo).items()
    }


def _repo_content_snapshot(repo: Path) -> dict[str, bytes]:
    snapshot: dict[str, bytes] = {}
    excluded_roots = {".git", ".venv", "venv", "__pycache__", ".sdlc-redteam-tmp", ".sdlc-worker-tmp"}
    for path in repo.rglob("*"):
        if not path.is_file():
            continue
        rel = str(path.relative_to(repo))
        parts = set(path.relative_to(repo).parts)
        if parts & excluded_roots:
            continue
        snapshot[rel] = path.read_bytes()
    return snapshot


def _restore_repo_snapshot_paths(repo: Path, before: dict[str, bytes], changed_paths: list[str]) -> list[str]:
    restored: list[str] = []
    for rel in sorted(set(changed_paths)):
        if rel.startswith("<"):
            continue
        path = repo / rel
        if rel in before:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(before[rel])
            restored.append(rel)
        elif path.is_file():
            path.unlink()
            restored.append(rel)
    return restored


def _path_allowed(rel: str, allow_paths: list[str]) -> bool:
    for pattern in allow_paths:
        if pattern.endswith("/**") and rel.startswith(pattern[:-3].rstrip("/") + "/"):
            return True
        if fnmatch.fnmatch(rel, pattern):
            return True
    return False


def _ownership_violations(repo: Path, allow_paths: list[str], before: dict[str, str]) -> list[str]:
    if not allow_paths:
        return ["<missing allow_paths policy>"]
    after = _repo_snapshot(repo)
    changed = {path for path, digest in after.items() if before.get(path) != digest}
    changed.update(path for path in before if path not in after)
    return sorted(path for path in changed if not _path_allowed(path, allow_paths))


def _run_git_or_reject(repo: Path, ledger: Ledger, action: str, cmd: list[str]) -> tuple[int, dict[str, object] | None]:
    result = run_cmd(cmd, repo, timeout=120)
    if result["returncode"] != 0:
        _reject_git_operation(ledger, action, result["stderr"] or result["stdout"] or f"Git command failed: {shlex.join(cmd)}", command=cmd, returncode=result["returncode"])
        return int(result["returncode"] or 1), None
    return 0, result


def ensure_sdlc_repo(repo: Path, *, force: bool = False) -> None:
    sdlc = repo / ".sdlc"
    (sdlc / "runs").mkdir(parents=True, exist_ok=True)
    (sdlc / "prompts").mkdir(parents=True, exist_ok=True)
    (sdlc / "templates").mkdir(parents=True, exist_ok=True)
    (sdlc / "schemas").mkdir(parents=True, exist_ok=True)
    _ensure_sdlc_gitignore(repo)
    ensure_policy_files(repo)
    for name, content in SCHEMA_DIR_CONTENT.items():
        path = sdlc / "schemas" / name
        if force or not path.exists():
            write_json(path, content)
    pipeline_path = sdlc / "pipeline.json"
    if force or not pipeline_path.exists():
        write_json(pipeline_path, gates_as_dicts())

    template_path = sdlc / "templates" / "secure_feature_prompt.md"
    if force or not template_path.exists():
        template_path.write_text(
            "# Secure Feature Prompt Template\n\nGenerated prompts live in `.sdlc/runs/<run-id>/prompts/`. "
            "Use `sdlc plan \"FEATURE\"` to render a run-specific execution prompt.\n",
            encoding="utf-8",
        )


def _ensure_sdlc_gitignore(repo: Path) -> None:
    gitignore = repo / ".gitignore"
    existing = gitignore.read_text(encoding="utf-8") if gitignore.exists() else ""
    existing_entries = {line.strip() for line in existing.splitlines()}
    missing = [entry for entry in SDLC_GITIGNORE_ENTRIES if entry not in existing_entries]
    if not missing:
        return
    additions = [SDLC_GITIGNORE_HEADER, *missing]
    prefix = "" if not existing else ("\n" if existing.endswith("\n") else "\n\n")
    gitignore.write_text(existing + prefix + "\n".join(additions) + "\n", encoding="utf-8")


def command_init(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    ensure_sdlc_repo(repo, force=args.force)
    print(f"Initialized Secure SDLC control plane at {repo / '.sdlc'}")
    return 0


def _plan_run_id(feature: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{slugify(feature)}-{stamp}"


def _create_run(
    repo: Path,
    *,
    feature: str,
    risk: str = "auto",
    ui: str = "auto",
    security: str = "auto",
    infra: str = "auto",
    policy_profile: str = "default",
    run_id: str | None = None,
    production_rollout_allowed_flag: bool = False,
    allow_main_push_flag: bool = False,
) -> tuple[RunPlan | None, Path | None, str | None]:
    ensure_sdlc_repo(repo)
    policy = load_policy(repo, policy_profile)
    classification = classify_feature(
        feature,
        repo,
        requested_risk=risk,
        ui=ui,
        security=security,
        infra=infra,
    )
    run_id = run_id or _plan_run_id(feature)
    try:
        validate_run_id(run_id)
    except ValueError as exc:
        return None, None, str(exc)
    branch = git_current_branch(repo)
    context = classification.to_dict()
    production_rollout_allowed = bool(production_rollout_allowed_flag or policy.get("production_rollout_allowed", False))
    direct_main_push_allowed = bool(allow_main_push_flag or policy.get("direct_main_push_allowed", False))

    gates: list[GateState] = []
    for gate in DEFAULT_GATES:
        state = "PENDING"
        if gate.conditional_on == "has_ui" and not classification.has_ui:
            state = "SKIPPED"
        if gate.conditional_on == "production_rollout_allowed" and not production_rollout_allowed:
            state = "SKIPPED"
        gates.append(GateState(
            id=gate.id,
            order=gate.order,
            title=gate.title,
            owner=gate.owner,
            state=state,
            verdict="SKIPPED" if state == "SKIPPED" else None,
            notes=f"Conditional gate skipped because {gate.conditional_on}=false" if state == "SKIPPED" else "",
            conditional_on=gate.conditional_on,
        ))

    plan = RunPlan(
        run_id=run_id,
        created_at=now_iso(),
        feature=feature,
        repo=str(repo),
        branch=branch,
        risk_level=classification.risk_level,
        classification=context,
        production_rollout_allowed=production_rollout_allowed,
        direct_main_push_allowed=direct_main_push_allowed,
        policy_profile=policy_profile,
        gates=gates,
        agents=classification.activated_agents,
        worker_preferences=policy.get("workers", {}),
    )
    store = RunStore(repo)
    run_dir = store.run_dir(run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    store.save_plan(plan)
    store.save_findings(run_id, [])
    write_prompt_bundle(run_dir, plan)
    ledger = Ledger(run_dir, run_id)
    ledger.event(
        "run.created",
        feature=feature,
        risk_level=classification.risk_level,
        policy_profile=policy_profile,
        repo=str(repo),
        repo_sha256=_repo_identity_sha256(repo),
    )
    ledger.event("classification.completed", classification=context)
    return plan, run_dir, None


def command_plan(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    plan, run_dir, error = _create_run(
        repo,
        feature=args.feature,
        risk=args.risk,
        ui=args.ui,
        security=args.security,
        infra=args.infra,
        policy_profile=args.policy,
        run_id=args.run_id,
        production_rollout_allowed_flag=args.production_rollout_allowed,
        allow_main_push_flag=args.allow_main_push,
    )
    if error or plan is None or run_dir is None:
        eprint(error or "Unable to create run")
        return 2
    print(f"Created run: {plan.run_id}")
    print(f"Risk: {plan.risk_level}")
    print(f"Prompt: {run_dir / 'prompts' / 'execution_prompt.md'}")
    print(f"Plan: {run_dir / 'plan.json'}")
    return 0


def _memory_context_for_request(repo: Path, request: str) -> list[dict[str, object]]:
    result = search_memory(repo, request, limit=3)
    return list(result.get("results", [])) if result.get("enabled") else []


def _write_autopilot_artifacts(repo: Path, plan: RunPlan, run_dir: Path, *, include_agent_plan: bool = False, parallel: int | None = None) -> dict[str, object]:
    policy = load_policy(repo, plan.policy_profile)
    memory_context = _memory_context_for_request(repo, plan.feature)
    brief = build_intake_brief(repo, plan.feature, plan.run_id, memory_context=memory_context)
    standards = build_standards_mapping(brief, network_allowed=False)
    artifacts = write_prework_artifacts(run_dir, plan.run_id, brief, standards)
    agent_plan = write_agent_plan(run_dir, plan, policy, requested_parallelism=parallel) if include_agent_plan else None
    recommendation = _next_action_payload(repo, plan.run_id, persist=True)
    return {
        "brief": brief,
        "standards": standards,
        "artifacts": artifacts,
        "agent_plan": agent_plan,
        "next_action": recommendation,
    }


def command_start(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    plan, run_dir, error = _create_run(
        repo,
        feature=args.request,
        risk=args.risk,
        ui=args.ui,
        security=args.security,
        infra=args.infra,
        policy_profile=args.policy,
        run_id=args.run_id,
        production_rollout_allowed_flag=args.production_rollout_allowed,
        allow_main_push_flag=args.allow_main_push,
    )
    if error or plan is None or run_dir is None:
        eprint(error or "Unable to create run")
        return 2
    result = _write_autopilot_artifacts(repo, plan, run_dir, include_agent_plan=True, parallel=args.parallel)
    output = {
        "run_id": plan.run_id,
        "risk_level": plan.risk_level,
        "plan": str(run_dir / "plan.json"),
        "prework": result["artifacts"],
        "agent_plan": result["agent_plan"].get("artifact") if isinstance(result["agent_plan"], dict) else None,
        "next_action": result["next_action"]["top_recommendation"],
    }
    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        print(f"Started run: {plan.run_id}")
        print(f"Risk: {plan.risk_level}")
        print(f"Prework: {run_dir / 'artifacts' / 'prework' / 'expectations.html'}")
        print(f"Next: {output['next_action']['command']}")
        print(f"Reason: {output['next_action']['reason']}")
    return 0


def command_brief(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    plan, run_dir, error = _create_run(
        repo,
        feature=args.request,
        risk=args.risk,
        ui=args.ui,
        security=args.security,
        infra=args.infra,
        policy_profile=args.policy,
        run_id=args.run_id,
        production_rollout_allowed_flag=False,
        allow_main_push_flag=False,
    )
    if error or plan is None or run_dir is None:
        eprint(error or "Unable to create run")
        return 2
    result = _write_autopilot_artifacts(repo, plan, run_dir, include_agent_plan=False)
    output = {
        "run_id": plan.run_id,
        "risk_level": plan.risk_level,
        "artifacts": result["artifacts"],
        "blocking_questions": result["brief"]["blocking_questions"],
        "expectations_html": str(run_dir / "artifacts" / "prework" / "expectations.html"),
    }
    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        print(f"Brief created: {plan.run_id}")
        print(f"Risk: {plan.risk_level}")
        print(f"Questions: {len(output['blocking_questions'])}")
        print(f"HTML: {output['expectations_html']}")
    return 0


def _print_status(plan: RunPlan, readiness: dict[str, object] | None = None) -> None:
    print(f"Run: {plan.run_id}")
    print(f"Feature: {plan.feature}")
    print(f"Risk: {plan.risk_level} | Policy: {plan.policy_profile} | Branch: {plan.branch}")
    if readiness:
        label = "SATISFIED" if readiness.get("release_satisfied") else "NO_GO"
        print(f"Release readiness: {label} | blockers={len(readiness.get('blockers', []))}")
    print("\nGates:")
    gate_status = {item["gate_id"]: item for item in readiness.get("gate_readiness", [])} if readiness else {}
    for gate in sorted(plan.gates, key=lambda item: item.order):
        verdict = f"/{gate.verdict}" if gate.verdict else ""
        release = ""
        if gate.id in gate_status:
            release = f"  release={gate_status[gate.id]['release_state']}"
        print(f"  {gate.order:02d}. {gate.id:<36} local={gate.state}{verdict}{release}  owner={gate.owner}")


def command_status(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    store = RunStore(repo)
    plan = store.load_plan(args.run_id)
    findings = store.load_findings(args.run_id)
    readiness = _release_readiness_payload(repo, plan, findings)
    if args.persist and not _audit_readonly_worker():
        try:
            _persist_release_readiness(store.run_dir(args.run_id), args.run_id, readiness)
        except OSError as exc:
            eprint(f"Unable to persist readiness artifact: {exc}")
            return 3
    elif args.persist and _audit_readonly_worker():
        eprint("Audit-readonly worker mode: status readiness artifact was not written.")
    if args.json:
        print(json.dumps({"run_id": plan.run_id, "plan": plan.to_dict(), "findings": [finding.to_dict() for finding in findings], "readiness": readiness}, indent=2, sort_keys=True))
        return 0
    _print_status(plan, readiness)
    if findings:
        print("\nFindings:")
        for finding in findings:
            print(f"  {finding.id} {finding.severity:<8} {finding.status:<20} {finding.title}")
    return 0


def command_next(args: argparse.Namespace) -> int:
    payload = _next_action_payload(Path(args.repo).resolve(), args.run_id, persist=args.persist and not _audit_readonly_worker())
    if args.persist and _audit_readonly_worker():
        eprint("Audit-readonly worker mode: next-action artifacts were not written.")
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        top = payload["top_recommendation"]
        print(f"Next action: {top['label']}")
        print(f"Command: {top['command']}")
        print(f"Reason: {top['reason']}")
        if payload["blockers"]:
            print(f"Blockers: {len(payload['blockers'])}")
    return 0


def _next_action_payload(repo: Path, run_id: str, *, persist: bool = False) -> dict[str, object]:
    store = RunStore(repo)
    plan = store.load_plan(run_id)
    findings = store.load_findings(run_id)
    readiness = _release_readiness_payload(repo, plan, findings)
    top = _recommend_next_action(plan, findings, readiness)
    payload = {
        "schema_version": 1,
        "run_id": run_id,
        "created_at": now_iso(),
        "release_satisfied": readiness["release_satisfied"],
        "top_recommendation": top,
        "recommendations": [top],
        "blockers": readiness["blockers"],
    }
    if persist:
        run_dir = store.run_dir(run_id)
        _persist_release_readiness(run_dir, run_id, readiness)
        Ledger(run_dir, run_id).artifact("artifacts/release/next_action.json", json.dumps(payload, indent=2, sort_keys=True) + "\n", event="release.next_action_recommended", action=top["action_id"])
    return payload


def _persist_release_readiness(run_dir: Path, run_id: str, readiness: dict[str, object]) -> str:
    payload = dict(readiness)
    payload.setdefault("created_at", now_iso())
    return Ledger(run_dir, run_id).artifact(
        "artifacts/release/readiness.json",
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        event="release.readiness_evaluated",
        release_satisfied=bool(readiness.get("release_satisfied")),
        blockers=len(readiness.get("blockers", [])) if isinstance(readiness.get("blockers"), list) else 0,
    )


def _release_readiness_payload(repo: Path, plan: RunPlan, findings: list[Finding]) -> dict[str, object]:
    store = RunStore(repo)
    errors = _release_readiness_errors(store, plan, findings)
    gate_readiness = []
    for gate in sorted(plan.gates, key=lambda item: item.order):
        reasons = [error for error in errors if f"Gate {gate.id} " in error or error.startswith(f"{gate.id} ")]
        if gate.state == "SKIPPED" and _skipped_gate_valid(gate, plan):
            release_state = "SKIPPED_VALID"
        elif reasons:
            release_state = "BLOCKED"
        elif _gate_satisfied(gate, plan):
            release_state = "SATISFIED"
        else:
            release_state = "UNSATISFIED"
        gate_readiness.append({
            "gate_id": gate.id,
            "local_state": gate.state,
            "local_verdict": gate.verdict,
            "release_state": release_state,
            "reasons": reasons,
        })
    return {
        "schema_version": 1,
        "run_id": plan.run_id,
        "local_verdict": final_verdict(findings, plan),
        "release_verdict": "GO" if not errors else "NO_GO",
        "release_satisfied": not errors,
        "blockers": errors,
        "gate_readiness": gate_readiness,
    }


def _recommend_next_action(plan: RunPlan, findings: list[Finding], readiness: dict[str, object]) -> dict[str, object]:
    open_items = open_findings(findings, {"CRITICAL", "HIGH", "MEDIUM"})
    if open_items:
        finding = open_items[0]
        return {
            "action_id": "resolve-finding",
            "label": f"Resolve {finding.severity} finding {finding.id}",
            "command": f"python -m sdlc finding close {plan.run_id} {finding.id} --closed-by agent_6_redteam_deploy_rollback --evidence <fix-evidence> <second-validation>",
            "reason": "Open blocking findings prevent release, commit, deploy, attestation, and finalization.",
        }
    for gate in sorted(plan.gates, key=lambda item: item.order):
        if gate.state == "SKIPPED" and gate.verdict == "SKIPPED":
            continue
        if not _gate_satisfied(gate, plan):
            return _gate_next_action(plan, gate)
    if not readiness.get("release_satisfied"):
        return {
            "action_id": "release-validation",
            "label": "Resolve release-readiness blockers",
            "command": f"python -m sdlc validate --run-id {plan.run_id} --release",
            "reason": "Local gates are not enough; release validation still reports blockers.",
        }
    return {
        "action_id": "final-report",
        "label": "Generate final report",
        "command": f"python -m sdlc report {plan.run_id} --print",
        "reason": "Release-readiness checks are satisfied.",
    }


def _gate_next_action(plan: RunPlan, gate: GateState) -> dict[str, object]:
    if gate.id == "security_scans":
        command = f"python -m sdlc scan {plan.run_id}"
    elif gate.id == "independent_redteam_cross_model":
        policy = load_policy(Path(plan.repo), plan.policy_profile)
        workers = ",".join(_policy_redteam_workers(policy))
        rounds = int(policy.get("redteam", {}).get("min_rounds_high_stakes", 1) or 1)
        command = f"python -m sdlc redteam execute {plan.run_id} --workers {workers} --rounds {rounds} --execute --allow-network --fail-on-findings"
    elif gate.id == "evidence_traceability_attestations":
        command = f"python -m sdlc attest manifest {plan.run_id}"
    elif gate.id == "commit_branch_pr_ci":
        command = f"python -m sdlc git branch {plan.run_id}"
    elif gate.id == "final_report_reaudit":
        command = f"python -m sdlc report {plan.run_id} --finalize --key <key>"
    elif gate.id == "critical_high_fix_loop":
        command = f"python -m sdlc gate evidence {plan.run_id} critical_high_fix_loop --actor agent_6_redteam_deploy_rollback --artifact fix_tasks=<path> fix_diffs=<path> focused_retests=<path> second_validation=<path> redteam_go=<path>"
    else:
        command = f"python -m sdlc gate evidence {plan.run_id} {gate.id} --actor {gate.owner} --artifact <key>=<path> --source <evidence>"
    return {
        "action_id": f"gate-{gate.id}",
        "label": f"Provide evidence for gate {gate.id}",
        "command": command,
        "reason": f"Gate {gate.id} is not release-satisfied.",
    }


def command_run(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    store = RunStore(repo)
    plan = run_dry_gates(store, args.run_id)
    if args.redteam:
        create_redteam_findings(store, args.run_id)
    _print_status(plan)
    print("\nRun advanced. Real implementation/red-team gates require worker execution or human evidence.")
    return 0


def _refresh_nonfinal_report(repo: Path, store: RunStore, run_id: str, *, reason: str) -> None:
    run_dir = store.run_dir(run_id)
    ledger = Ledger(run_dir, run_id)
    try:
        plan = store.load_plan(run_id)
        final_gate = next((gate for gate in plan.gates if gate.id == "final_report_reaudit"), None)
        if final_gate and final_gate.state == "GO":
            final_gate.state = "BLOCKED"
            final_gate.verdict = "NO_GO"
            final_gate.notes = f"Invalidated by later run state change: {reason}"
            store.save_plan(plan)
            ledger.event("gate.invalidated", gate="final_report_reaudit", reason=reason)
        findings = store.load_findings(run_id)
        readiness = _release_readiness_payload(repo, plan, findings)
        _persist_release_readiness(run_dir, run_id, readiness)
        blockers = [str(item) for item in readiness.get("blockers", [])] if isinstance(readiness.get("blockers"), list) else []
        verdict = final_verdict(findings, plan)
        generate_report(
            repo,
            run_id,
            verdict_override="NO_GO" if verdict in POSITIVE_GATE_VERDICTS and blockers else None,
            readiness_errors=blockers,
        )
        ledger.event("report.auto_refreshed", reason=reason)
    except Exception as exc:  # pragma: no cover - best-effort evidence freshness guard
        ledger.event("report.auto_refresh_failed", reason=reason, error=str(exc))


def _refresh_report_if_materialized(repo: Path, store: RunStore, run_id: str, *, reason: str) -> None:
    if not (store.run_dir(run_id) / "final-report.md").exists():
        return
    _refresh_nonfinal_report(repo, store, run_id, reason=reason)


def command_worker(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    store = RunStore(repo)
    if args.timeout < 1:
        eprint("--timeout must be at least 1 second")
        return 2
    plan = store.load_plan(args.run_id)
    run_dir = store.run_dir(args.run_id)
    prompt_path, prompt_error = resolve_under_base(run_dir / "prompts", Path(args.prompt), must_exist=True)
    if prompt_error or prompt_path is None:
        eprint(prompt_error or f"Invalid prompt path: {args.prompt}")
        return 2
    ledger = Ledger(run_dir, args.run_id)
    policy = load_policy(repo, plan.policy_profile)
    adapter = adapter_from_policy(args.worker, policy)
    if adapter is None:
        eprint(f"Unknown worker: {args.worker}")
        return 2
    policy_error = _worker_execution_policy_error(policy, execute=args.execute, allow_network=args.allow_network)
    if policy_error:
        ledger.event("worker.execution_rejected", worker=args.worker, mode=args.mode, reason=policy_error)
        eprint(policy_error)
        return 3
    implementer_policy = policy.get("permissions", {}).get("implementer", {}) if isinstance(policy.get("permissions"), dict) else {}
    deny_paths = list(implementer_policy.get("deny_paths", []))
    allow_paths = list(implementer_policy.get("allow_paths", []))
    prompt_rel = relpath_under_base(run_dir, prompt_path, must_exist=True)
    ledger.event("worker.started", worker=args.worker, mode=args.mode, execute_requested=args.execute, prompt=prompt_rel)
    deny_before = _deny_path_snapshot(repo, deny_paths) if args.execute and deny_paths else {}
    ownership_before_content = _repo_content_snapshot(repo) if args.execute else {}
    ownership_before = {
        rel: hashlib.sha256(content).hexdigest()
        for rel, content in ownership_before_content.items()
    }
    result = adapter.run(prompt_path, repo, args.mode, execute=args.execute, timeout=args.timeout)
    deny_changes = _deny_path_changes(repo, deny_paths, deny_before) if args.execute and deny_paths else []
    if deny_changes:
        _restore_denied_paths(repo, deny_paths, deny_before)
    ownership_violations = _ownership_violations(repo, allow_paths, ownership_before) if args.execute else []
    restored_ownership = _restore_repo_snapshot_paths(repo, ownership_before_content, ownership_violations) if ownership_violations else []
    result_data = capture_worker_result(
        run_dir=run_dir,
        mode=args.mode,
        prompt_path=prompt_path,
        result=result,
        ledger=ledger,
    )
    if deny_changes:
        ledger.event("worker.policy_violation", worker=args.worker, mode=args.mode, deny_path_changes=deny_changes, resolved=True, restored_paths=deny_changes)
        result_data["policy_violation"] = {"deny_path_changes": deny_changes, "resolved": True, "restored_paths": deny_changes}
    if ownership_violations:
        ledger.event("worker.policy_violation", worker=args.worker, mode=args.mode, ownership_violations=ownership_violations, resolved=True, restored_paths=restored_ownership)
        result_data.setdefault("policy_violation", {})["ownership_violations"] = ownership_violations
        result_data.setdefault("policy_violation", {})["resolved"] = True
        result_data.setdefault("policy_violation", {})["restored_paths"] = sorted(set(result_data["policy_violation"].get("restored_paths", []) + restored_ownership))
    print(json.dumps(result_data, indent=2))
    if deny_changes or ownership_violations:
        return 3
    return 0 if (not args.execute or result.returncode in {0, None}) else int(result.returncode or 1)


def command_redteam(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    store = RunStore(repo)
    if args.redteam_args[0] == "execute":
        if len(args.redteam_args) != 2:
            eprint("Usage: sdlc redteam execute <run-id> [--workers <policy-defaults>] [--rounds N] [--execute]")
            return 2
        if args.timeout < 1:
            eprint("--timeout/--worker-timeout must be at least 1 second")
            return 2
        if args.total_timeout is not None and args.total_timeout < 1:
            eprint("--total-timeout must be at least 1 second")
            return 2
        run_id = args.redteam_args[1]
        plan = store.load_plan(run_id)
        policy = load_policy(repo, plan.policy_profile)
        workers = [worker.strip() for worker in args.workers.split(",") if worker.strip()] if args.workers else _policy_redteam_workers(policy)
        try:
            result = execute_redteam_workers(
                store,
                run_id,
                workers=workers,
                rounds=args.rounds,
                execute=args.execute,
                timeout=args.timeout,
                total_timeout=args.total_timeout,
                allow_network=args.allow_network,
                parallel_per_round=args.parallel_per_round,
                progress=_print_redteam_progress,
            )
        except KeyboardInterrupt:
            ledger = Ledger(store.run_dir(run_id), run_id)
            ledger.event(
                "redteam.execution_interrupted",
                workers=workers,
                rounds=args.rounds,
                execute_requested=args.execute,
                reason="keyboard_interrupt",
            )
            interrupted_plan = store.load_plan(run_id)
            gate = next((item for item in interrupted_plan.gates if item.id == "independent_redteam_cross_model"), None)
            if gate is not None:
                gate.state = "NO_GO"
                gate.verdict = "NO_GO"
                gate.notes = "Red-team execution was interrupted before completion."
                store.save_plan(interrupted_plan)
            _refresh_nonfinal_report(repo, store, run_id, reason="redteam.interrupted")
            eprint("Red-team execution interrupted before completion")
            return 130
        _refresh_nonfinal_report(repo, store, run_id, reason="redteam.execute")
        print(f"Red-team execution -> {result['verdict']}")
        print(f"Summary: {result['summary']}")
        if result.get("timed_out_workers"):
            print(f"Timed out workers: {', '.join(result['timed_out_workers'])}")
        if result.get("skipped_due_total_timeout"):
            print(f"Skipped by total timeout: {', '.join(result['skipped_due_total_timeout'])}")
        if result["unavailable"]:
            print(f"Unavailable workers: {', '.join(result['unavailable'])}")
        for finding in result["parsed_findings"]:
            print(f"  {finding['id']} {finding['severity']:<8} OPEN   {finding['title']}")
        if result["verdict"] == "NO_GO" and args.allow_no_go_exit_zero:
            Ledger(store.run_dir(run_id), run_id).event("redteam.no_go_exit_zero_allowed", evidence=[result["summary"]])
            return 0
        return 1 if result["verdict"] == "NO_GO" else 0

    if len(args.redteam_args) != 1:
        eprint("Usage: sdlc redteam <run-id>")
        return 2
    run_id = args.redteam_args[0]
    findings = create_redteam_findings(store, run_id)
    print(f"Findings for {run_id}:")
    for finding in findings:
        print(f"  {finding.id} {finding.severity:<8} {finding.status:<6} {finding.title}")
    return 0


def _print_redteam_progress(event: dict[str, Any]) -> None:
    event_name = str(event.get("event") or "")
    if event_name == "redteam.execution_started":
        total_timeout = event.get("total_timeout_seconds")
        total_text = f"{total_timeout}s" if total_timeout else "none"
        mode = "execute" if event.get("execute_requested") else "dry-run"
        scheduling = "parallel-per-round" if event.get("parallel_per_round_enabled") else "sequential"
        workers = ", ".join(str(worker) for worker in event.get("workers", [])) or "<none>"
        print(
            f"Red-team {mode} started: rounds={event.get('rounds')} workers={workers} "
            f"worker-timeout={event.get('worker_timeout_seconds')}s total-timeout={total_text} scheduling={scheduling}",
            flush=True,
        )
    elif event_name == "redteam.execution_rejected":
        print(f"Red-team rejected: {event.get('reason')}", flush=True)
    elif event_name == "redteam.round_started":
        print(f"Round {event.get('round')} started", flush=True)
    elif event_name == "redteam.worker_started":
        print(
            f"  {event.get('worker')} round {event.get('round')} started "
            f"timeout={event.get('timeout_seconds')}s scope={event.get('timeout_scope')}",
            flush=True,
        )
    elif event_name == "redteam.worker_completed":
        status = "timed out" if event.get("timed_out") else f"returncode={event.get('returncode')}"
        timeout_scope = event.get("timeout_scope")
        scope_text = f" scope={timeout_scope}" if timeout_scope else ""
        print(f"  {event.get('worker')} round {event.get('round')} completed {status}{scope_text}", flush=True)
    elif event_name == "redteam.worker_skipped":
        print(f"  {event.get('worker')} round {event.get('round')} skipped: {event.get('reason')}", flush=True)
    elif event_name == "redteam.worker_unavailable":
        print(f"  {event.get('worker')} round {event.get('round')} unavailable: {event.get('reason')}", flush=True)
    elif event_name == "redteam.worker_rejected":
        print(f"  {event.get('worker')} round {event.get('round')} rejected: {event.get('reason')}", flush=True)
    elif event_name == "redteam.round_completed":
        print(f"Round {event.get('round')} completed", flush=True)
    elif event_name == "redteam.execution_completed":
        print(f"Red-team execution completed: {event.get('verdict')}", flush=True)


def _policy_redteam_workers(policy: dict[str, Any]) -> list[str]:
    redteam = policy.get("redteam", {})
    configured = redteam.get("default_workers") if isinstance(redteam, dict) else None
    if isinstance(configured, list):
        workers = [str(worker).strip() for worker in configured if str(worker).strip()]
        if workers:
            return workers
    worker_preferences = policy.get("workers", {})
    if isinstance(worker_preferences, dict):
        redteam_worker = str(worker_preferences.get("redteam") or "").strip()
        if redteam_worker:
            return [redteam_worker]
    return ["codex"]


def _find_finding(findings: list[Finding], finding_id: str) -> Finding:
    for finding in findings:
        if finding.id == finding_id:
            return finding
    raise KeyError(f"Finding not found: {finding_id}")


def command_finding(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    store = RunStore(repo)
    findings = store.load_findings(args.run_id)
    run_dir = store.run_dir(args.run_id)
    ledger = Ledger(run_dir, args.run_id)
    plan = store.load_plan(args.run_id)
    policy = load_policy(repo, plan.policy_profile)

    if args.finding_command == "list":
        if not findings:
            print("No findings recorded")
            return 0
        for finding in findings:
            print(f"{finding.id} {finding.severity:<8} {finding.status:<22} {finding.title}")
        return 0

    try:
        finding = _find_finding(findings, args.finding_id)
    except KeyError as exc:
        eprint(str(exc))
        return 2

    if args.finding_command == "show":
        print(json.dumps(finding.to_dict(), indent=2))
        return 0

    if args.finding_command in {"accept", "defer"}:
        closed_by = args.closed_by or "human_product_owner"
        worker_error = _managed_worker_control_plane_error(repo, args.run_id, closed_by)
        if worker_error:
            ledger.event("finding.lifecycle_rejected", finding_id=finding.id, action=args.finding_command, actor=closed_by, reason=worker_error)
            eprint(worker_error)
            return 3
        if closed_by == finding.owner or closed_by == "agent_3_implementation_owner":
            eprint("Implementer/owner cannot accept or defer its own finding")
            return 3
        if closed_by not in HUMAN_GATE_ACTORS:
            eprint("Accept/defer requires an authorized human approval actor")
            return 3
        if finding.severity in {"CRITICAL", "HIGH"} and not args.human_override:
            eprint("CRITICAL/HIGH findings cannot be accepted or deferred without --human-override")
            return 3
        if not args.reason:
            eprint("--reason is required")
            return 2
        evidence_paths, evidence_error = resolve_repo_paths(repo, args.evidence or [], required=True)
        if evidence_error:
            eprint(evidence_error)
            return 2
        if finding.severity in {"CRITICAL", "HIGH", "MEDIUM"}:
            if policy.get("actor_proof_required_for_finding_closure") is True:
                proof_error = _actor_proof_error(args.run_id, finding.id, closed_by, getattr(args, "actor_proof", None), repo=repo, run_dir=run_dir)
                if proof_error:
                    eprint(proof_error)
                    return 3
            acceptance_error = _blocking_acceptance_evidence_error(repo, run_dir, finding, evidence_paths, args.reason)
            if acceptance_error:
                eprint(acceptance_error)
                return 3
        run_state_error = _run_state_acceptance_error(repo, plan, findings, finding, evidence_paths, args.reason)
        if run_state_error:
            ledger.event("finding.lifecycle_rejected", finding_id=finding.id, action=args.finding_command, actor=closed_by, reason=run_state_error)
            eprint(run_state_error)
            return 3
        finding.status = "ACCEPTED" if args.finding_command == "accept" else "DEFERRED"
        finding.closed_by = closed_by
        finding.closure_evidence.append(f"{args.finding_command}: {args.reason}")
        finding.closure_evidence.extend(evidence_paths)
        store.save_findings(args.run_id, findings)
        ledger.event("finding.lifecycle", finding_id=finding.id, action=args.finding_command, severity=finding.severity, closed_by=finding.closed_by, reason=args.reason, evidence=evidence_paths)
        _refresh_nonfinal_report(repo, store, args.run_id, reason=f"finding.{args.finding_command}")
        print(f"{finding.id} -> {finding.status}")
        return 0

    if args.finding_command == "close":
        if not args.evidence:
            eprint("--evidence is required to close a finding")
            return 2
        closed_by = args.closed_by or "agent_6_redteam_deploy_rollback"
        worker_error = _managed_worker_control_plane_error(repo, args.run_id, closed_by)
        if worker_error:
            ledger.event("finding.lifecycle_rejected", finding_id=finding.id, action="close", actor=closed_by, reason=worker_error)
            eprint(worker_error)
            return 3
        evidence_paths, evidence_error = resolve_repo_paths(repo, args.evidence, required=True)
        if evidence_error:
            eprint(evidence_error)
            return 2
        close_error = _finding_close_error(
            repo,
            store.run_dir(args.run_id),
            finding,
            closed_by,
            evidence_paths,
            policy=policy,
            actor_proof=getattr(args, "actor_proof", None),
            plan=plan,
            findings=findings,
        )
        if close_error:
            ledger.event("finding.lifecycle_rejected", finding_id=finding.id, action="close", actor=closed_by, reason=close_error)
            eprint(close_error)
            return 3
        finding.status = "CLOSED"
        finding.closed_by = closed_by
        finding.closure_evidence.extend(evidence_paths)
        store.save_findings(args.run_id, findings)
        ledger.event(
            "finding.lifecycle",
            finding_id=finding.id,
            action="close",
            severity=finding.severity,
            closed_by=closed_by,
            evidence=evidence_paths,
            actor_proof_verified=bool(policy.get("actor_proof_required_for_finding_closure")),
        )
        _refresh_nonfinal_report(repo, store, args.run_id, reason="finding.close")
        print(f"{finding.id} -> CLOSED")
        return 0

    eprint(f"Unknown finding command: {args.finding_command}")
    return 2


def command_gate(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    store = RunStore(repo)
    plan = store.load_plan(args.run_id)
    run_dir = store.run_dir(args.run_id)
    ledger = Ledger(run_dir, args.run_id)

    gate = next((item for item in plan.gates if item.id == args.gate_id), None)
    if gate is None:
        eprint(f"Gate not found: {args.gate_id}")
        return 2
    gate_definition = _gate_definition(gate.id)

    if args.gate_command == "evidence":
        worker_error = _managed_worker_control_plane_error(repo, args.run_id, args.actor)
        if worker_error:
            ledger.event("gate.evidence_rejected", gate=gate.id, actor=args.actor, reason=worker_error)
            eprint(worker_error)
            return 3
        artifacts: dict[str, str] = {}
        for item in args.artifact:
            if "=" not in item:
                eprint("--artifact entries must use key=value")
                return 2
            key, value = item.split("=", 1)
            artifacts[key.strip()] = value.strip()
        required = set(gate_definition.required_artifacts if gate_definition else [])
        missing = [item for item in sorted(required) if not artifacts.get(item)]
        if missing:
            eprint("Gate evidence is missing required artifacts: " + ", ".join(missing))
            return 2
        source_evidence = args.source or []
        artifact_bindings, artifact_error = _build_gate_artifact_bindings(repo, run_dir, args.gate_id, artifacts, source_evidence)
        if artifact_error:
            eprint(artifact_error)
            return 2
        source_evidence_bindings, source_error = _build_source_evidence_bindings(repo, run_dir, source_evidence)
        if source_error:
            eprint(source_error)
            return 2
        payload = {
            "schema_version": 1,
            "run_id": args.run_id,
            "gate_id": args.gate_id,
            "actor": args.actor,
            "required_artifacts": artifacts,
            "artifact_bindings": artifact_bindings,
            "source_evidence": source_evidence,
            "source_evidence_bindings": source_evidence_bindings,
            "notes": args.notes or "",
        }
        rel = f"artifacts/gates/{args.gate_id}-evidence.json"
        artifact = ledger.artifact(
            rel,
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            event="gate.evidence_recorded",
            gate=args.gate_id,
            actor=args.actor,
            artifact_keys=sorted(artifacts),
            artifact_bindings=artifact_bindings,
            source_evidence_bindings=source_evidence_bindings,
        )
        print(f"Gate evidence: .sdlc/runs/{args.run_id}/{artifact}")
        _refresh_report_if_materialized(repo, store, args.run_id, reason=f"gate.evidence.{args.gate_id}")
        return 0

    evidence_paths, evidence_error = resolve_repo_paths(repo, args.evidence or [], required=False)
    if evidence_error:
        eprint(evidence_error)
        return 2
    worker_error = _managed_worker_control_plane_error(repo, args.run_id, args.actor)
    if worker_error:
        return _reject_gate_completion(ledger, gate, args, worker_error, evidence_paths)

    payload = {
        "gate_id": args.gate_id,
        "verdict": args.verdict,
        "evidence": evidence_paths,
        "notes": args.notes or "",
        "actor": args.actor,
    }
    schema = read_json(repo / ".sdlc" / "schemas" / "gate_result.schema.json", SCHEMA_DIR_CONTENT["gate_result.schema.json"])
    schema_errors = validate_json_schema(payload, schema)
    if schema_errors:
        return _reject_gate_completion(ledger, gate, args, f"Gate result schema validation failed: {'; '.join(schema_errors)}", evidence_paths)

    if not _actor_can_complete_gate(gate, args.actor):
        return _reject_gate_completion(ledger, gate, args, f"Actor {args.actor or '<missing>'} is not authorized to complete gate {gate.id}; required actor is {gate.owner} or explicit human approval authority", evidence_paths)

    if gate_definition and args.verdict not in gate_definition.allowed_verdicts:
        return _reject_gate_completion(ledger, gate, args, f"Verdict {args.verdict} is not allowed for gate {gate.id}", evidence_paths)

    dependency_error = _validate_gate_dependencies(plan, gate, args.verdict)
    if dependency_error:
        return _reject_gate_completion(ledger, gate, args, dependency_error, evidence_paths)

    if args.verdict == "SKIPPED" and not gate.conditional_on:
        return _reject_gate_completion(ledger, gate, args, "Only conditional gates can be marked SKIPPED", evidence_paths)
    if args.verdict in POSITIVE_GATE_VERDICTS and not evidence_paths:
        return _reject_gate_completion(ledger, gate, args, "Positive gate verdict requires at least one evidence path", evidence_paths)
    placeholder_error = _validate_non_placeholder_evidence(repo, args.verdict, evidence_paths)
    if placeholder_error:
        return _reject_gate_completion(ledger, gate, args, placeholder_error, evidence_paths)
    release_evidence_error = _validate_release_gate_evidence(repo, store.run_dir(args.run_id), gate, args.verdict, evidence_paths)
    if release_evidence_error:
        return _reject_gate_completion(ledger, gate, args, release_evidence_error, evidence_paths)
    if gate.id == "implementation" and args.verdict == "GO" and not any("diff" in path or "patch" in path for path in evidence_paths):
        return _reject_gate_completion(ledger, gate, args, "Implementation GO requires diff/patch evidence", evidence_paths)
    security_error = _validate_security_gate_completion(store, args.run_id, gate, args.verdict, args.actor, args.notes or "")
    if security_error:
        return _reject_gate_completion(ledger, gate, args, security_error, evidence_paths)
    residual_error = _validate_residual_risk_gate_completion(repo, store.run_dir(args.run_id), gate, args.verdict, args.actor, args.notes or "", evidence_paths)
    if residual_error:
        return _reject_gate_completion(ledger, gate, args, residual_error, evidence_paths)
    redteam_gate_error = _validate_redteam_gate_completion(store, plan, gate, args.verdict, evidence_paths)
    if redteam_gate_error:
        return _reject_gate_completion(ledger, gate, args, redteam_gate_error, evidence_paths)
    deploy_gate_error = _validate_deploy_gate_completion(store, plan, gate, args.verdict)
    if deploy_gate_error:
        return _reject_gate_completion(ledger, gate, args, deploy_gate_error, evidence_paths)
    git_provenance_gate_error = _validate_git_provenance_gate_completion(store, plan, gate, args.verdict, evidence_paths)
    if git_provenance_gate_error:
        return _reject_gate_completion(ledger, gate, args, git_provenance_gate_error, evidence_paths)
    attestation_gate_error = _validate_attestation_gate_completion(store, plan, gate, args.verdict, evidence_paths)
    if attestation_gate_error:
        return _reject_gate_completion(ledger, gate, args, attestation_gate_error, evidence_paths)
    if gate.id == "final_report_reaudit" and args.verdict in POSITIVE_GATE_VERDICTS:
        return _reject_gate_completion(
            ledger,
            gate,
            args,
            "Final report GO must be completed with `sdlc report <run-id> --finalize --key <key>` so report generation and attestation remain atomic.",
            evidence_paths,
        )
    report_error = _validate_final_report_gate_completion(store, args.run_id, gate, args.verdict, evidence_paths)
    if report_error:
        return _reject_gate_completion(ledger, gate, args, report_error, evidence_paths)

    gate.verdict = args.verdict
    gate.state = "GO" if args.verdict in {"GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"} else args.verdict
    gate.evidence.extend(evidence_paths)
    gate.notes = args.notes or gate.notes
    invalidated: list[str] = []
    if args.verdict not in POSITIVE_GATE_VERDICTS:
        invalidated = invalidate_downstream_gates(plan, gate.order, f"Blocked because prerequisite gate {gate.id} is {args.verdict}.")
    store.save_plan(plan)
    ledger.event("gate.manually_completed", gate=gate.id, actor=args.actor, verdict=args.verdict, evidence=evidence_paths, notes=args.notes or "")
    if invalidated:
        ledger.event("gate.downstream_invalidated", gate=gate.id, invalidated=invalidated)
    _refresh_report_if_materialized(repo, store, args.run_id, reason=f"gate.complete.{gate.id}")
    print(f"{gate.id} -> {gate.state}/{gate.verdict}")
    return 0


def command_git(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    store = RunStore(repo)
    plan = store.load_plan(args.run_id)
    run_dir = store.run_dir(args.run_id)
    ledger = Ledger(run_dir, args.run_id)
    action = f"git.{args.git_command}"

    repo_error = _ensure_git_repo(repo, ledger, action)
    if repo_error is not None:
        return repo_error

    if args.git_command == "branch":
        branch = args.name or _default_feature_branch(args.run_id)
        if _is_protected_branch(branch) and not _protected_branch_allowed(plan, args.allow_protected_branch):
            return _reject_git_operation(ledger, action, f"Refusing to use protected branch {branch}; create a feature branch instead", branch=branch)
        exists = run_cmd(["git", "rev-parse", "--verify", f"refs/heads/{branch}"], repo)
        command = ["git", "checkout", branch] if exists["returncode"] == 0 else ["git", "checkout", "-b", branch]
        code, result = _run_git_or_reject(repo, ledger, action, command)
        if result is None:
            return code
        plan.branch = branch
        store.save_plan(plan)
        ledger.event("git.branch_ready", branch=branch, created=exists["returncode"] != 0, command=command)
        artifact = _write_git_provenance_artifact(repo, plan, ledger)
        print(f"Branch ready: {branch}")
        print(f"Git provenance: .sdlc/runs/{args.run_id}/{artifact}")
        return 0

    if args.git_command == "provenance":
        artifact = _write_git_provenance_artifact(repo, plan, ledger)
        print(f"Git provenance: .sdlc/runs/{args.run_id}/{artifact}")
        return 0

    current_branch = git_current_branch(repo)
    if _is_protected_branch(current_branch) and not _protected_branch_allowed(plan, getattr(args, "allow_protected_branch", False)):
        return _reject_git_operation(ledger, action, f"Refusing to run {action} on protected branch {current_branch}; use `sdlc git branch {args.run_id}` first", branch=current_branch)

    blocking = _blocking_finding_ids(store.load_findings(args.run_id))
    if blocking:
        return _reject_git_operation(ledger, action, f"Open CRITICAL/HIGH findings block {action}: {', '.join(blocking)}", findings=blocking)
    blocking_gates = _blocking_commit_gate_ids(plan)
    if blocking_gates:
        return _reject_git_operation(ledger, action, f"Unresolved release gates block {action}: {', '.join(blocking_gates)}", gates=blocking_gates)

    if args.git_command == "commit":
        if not COMMIT_MESSAGE_RE.match(args.message):
            return _reject_git_operation(ledger, action, "Commit message must use `verb: subject` format", message=args.message)
        staged = run_cmd(["git", "diff", "--cached", "--quiet"], repo)
        if staged["returncode"] == 0:
            return _reject_git_operation(ledger, action, "No staged changes to commit")
        if staged["returncode"] not in {0, 1}:
            return _reject_git_operation(ledger, action, staged["stderr"] or "Unable to inspect staged changes", returncode=staged["returncode"])
        code, result = _run_git_or_reject(repo, ledger, action, ["git", "commit", "-m", args.message])
        if result is None:
            return code
        commit = run_cmd(["git", "rev-parse", "HEAD"], repo)
        commit_sha = commit["stdout"].strip()
        artifact = ledger.artifact(
            f"artifacts/git_commit_{commit_sha[:12] or 'unknown'}.md",
            "\n".join([
                f"branch: {current_branch}",
                f"commit: {commit_sha or '<unknown>'}",
                f"message: {args.message}",
                "",
                "stdout:",
                str(result["stdout"] or "<empty>"),
                "stderr:",
                str(result["stderr"] or "<empty>"),
            ]) + "\n",
            event="git.commit_artifact",
            commit=commit_sha,
            branch=current_branch,
        )
        ledger.event("git.commit_created", branch=current_branch, commit=commit_sha, message=args.message, evidence=[artifact])
        provenance = _write_git_provenance_artifact(repo, store.load_plan(args.run_id), ledger)
        print(f"Committed {commit_sha[:12]} on {current_branch}")
        print(f"Git provenance: .sdlc/runs/{args.run_id}/{provenance}")
        return 0

    if args.git_command == "pr":
        base = args.base
        title = args.title or f"{args.run_id}: {plan.feature}"
        body = args.body or f"SDLC run: {args.run_id}\nFeature: {plan.feature}\nReport: .sdlc/runs/{args.run_id}/final-report.md\n"
        if current_branch == base:
            return _reject_git_operation(ledger, action, f"Cannot create a PR from {current_branch} to itself", branch=current_branch, base=base)
        command = ["gh", "pr", "create", "--base", base, "--head", current_branch, "--title", title, "--body", body]
        artifact = ledger.artifact(
            "artifacts/git_pr_plan.md",
            f"branch: {current_branch}\nbase: {base}\ncommand: {shlex.join(command)}\nexecute: {args.execute}\n",
            event="git.pr_plan_artifact",
            branch=current_branch,
            base=base,
            execute=args.execute,
        )
        if not args.execute:
            ledger.event("git.pr_planned", branch=current_branch, base=base, command=command, evidence=[artifact])
            provenance = _write_git_provenance_artifact(repo, plan, ledger)
            print(f"PR dry-run: {shlex.join(command)}")
            print(f"Git provenance: .sdlc/runs/{args.run_id}/{provenance}")
            return 0
        policy = load_policy(repo, plan.policy_profile)
        if not args.allow_network or not policy.get("network_allowed", False):
            return _reject_git_operation(ledger, action, "PR creation requires --allow-network and policy network_allowed=true", branch=current_branch, base=base)
        if shutil.which("gh") is None:
            return _reject_git_operation(ledger, action, "GitHub CLI is not installed: gh", branch=current_branch, base=base)
        code, result = _run_git_or_reject(repo, ledger, action, command)
        if result is None:
            return code
        ledger.event("git.pr_created", branch=current_branch, base=base, stdout=result["stdout"], stderr=result["stderr"], evidence=[artifact])
        provenance = _write_git_provenance_artifact(repo, plan, ledger)
        print(result["stdout"] or "PR created")
        print(f"Git provenance: .sdlc/runs/{args.run_id}/{provenance}")
        return 0

    eprint(f"Unknown git command: {args.git_command}")
    return 2


def command_scan(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    store = RunStore(repo)
    plan = store.load_plan(args.run_id)
    run_dir = store.run_dir(args.run_id)
    policy = load_policy(repo, plan.policy_profile)
    results, artifacts = run_security_scans(
        repo=repo,
        run_dir=run_dir,
        run_id=args.run_id,
        policy=policy,
        risk_level=plan.risk_level,
        allow_network=args.allow_network,
    )
    verdict = scan_verdict(results)
    gate = next((item for item in plan.gates if item.id == "security_scans"), None)
    if gate:
        dependency_error = _validate_gate_dependencies(plan, gate, verdict)
        if verdict == "GO" and dependency_error:
            gate.verdict = "NO_GO"
            gate.state = "BLOCKED"
            gate.notes = dependency_error
            invalidated = invalidate_downstream_gates(plan, gate.order, "Blocked because security scan prerequisites are unresolved.")
            store.save_plan(plan)
            ledger = Ledger(run_dir, args.run_id)
            ledger.event("security.scan_gate_update_blocked", verdict=verdict, reason=dependency_error, evidence=artifacts)
            if invalidated:
                ledger.event("gate.downstream_invalidated", gate=gate.id, invalidated=invalidated)
            _refresh_report_if_materialized(repo, store, args.run_id, reason="security.scan")
            print("Security scans -> NO_GO")
            for result in results:
                print(f"  {result.scanner:<15} {result.status:<18} {result.artifact}")
            return 1
        gate.verdict = verdict
        gate.state = "GO" if verdict == "GO" else "NO_GO"
        gate.evidence.extend(path for path in artifacts if path not in gate.evidence)
        gate.notes = scan_notes(results)
        invalidated = []
        if verdict == "NO_GO":
            invalidated = invalidate_downstream_gates(plan, gate.order, "Blocked because security scans are NO_GO.")
        store.save_plan(plan)
    ledger = Ledger(run_dir, args.run_id)
    ledger.event("security.scan_gate_updated", verdict=verdict, evidence=artifacts)
    if gate and verdict == "NO_GO" and invalidated:
        ledger.event("gate.downstream_invalidated", gate=gate.id, invalidated=invalidated)
    _refresh_report_if_materialized(repo, store, args.run_id, reason="security.scan")
    print(f"Security scans -> {verdict}")
    for result in results:
        print(f"  {result.scanner:<15} {result.status:<18} {result.artifact}")
    if verdict == "NO_GO" and args.allow_no_go_exit_zero:
        ledger.event("security.no_go_exit_zero_allowed", evidence=artifacts)
        return 0
    if verdict == "NO_GO":
        return 1
    return 0


def command_deploy(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    store = RunStore(repo)
    if args.deploy_command == "plan":
        result = plan_deployment(store, args.run_id, env=args.env, rollback_command=args.rollback_command)
    elif args.deploy_command == "approve":
        result = approve_deployment(store, args.run_id, env=args.env, actor=args.actor, evidence=args.evidence, actor_proof=args.actor_proof)
    elif args.deploy_command == "execute":
        plan = store.load_plan(args.run_id)
        findings = store.load_findings(args.run_id)
        release_errors = _release_readiness_errors(
            store,
            plan,
            findings,
            ignore_gate_ids={"deploy_rollout_postdeploy", "final_report_reaudit"},
        ) if args.env == "production" else None
        result = execute_deployment(
            store,
            args.run_id,
            env=args.env,
            execute=args.execute,
            command=args.command,
            release_errors=release_errors,
        )
    elif args.deploy_command == "verify":
        result = verify_deployment(
            store,
            args.run_id,
            env=args.env,
            evidence=args.evidence,
            accepted_residual_risk=args.accepted_residual_risk,
            actor=args.actor,
            actor_proof=args.actor_proof,
        )
    elif args.deploy_command == "rollback":
        result = rollback_deployment(store, args.run_id, env=args.env, execute=args.execute, command=args.command, evidence=args.evidence)
    else:
        eprint(f"Unknown deploy command: {args.deploy_command}")
        return 2
    status = result["status"]
    print(f"Deploy {args.deploy_command} {args.env} -> {status}")
    if result.get("artifact"):
        print(f"Artifact: {result['artifact']}")
        _refresh_report_if_materialized(repo, store, args.run_id, reason=f"deploy.{args.deploy_command}.{args.env}")
    if result.get("reason"):
        eprint(str(result["reason"]))
    return 3 if status in {"REJECTED", "FAILED"} else 0


def command_attest(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    store = RunStore(repo)
    if args.attest_command == "manifest":
        result = write_artifact_manifest(store, args.run_id)
    elif args.attest_command == "sign":
        result = sign_artifact_manifest(store, args.run_id, key=args.key, execute=args.execute)
    elif args.attest_command == "verify":
        result = verify_artifact_manifest(store, args.run_id, key=args.key)
    else:
        eprint(f"Unknown attest command: {args.attest_command}")
        return 2
    print(f"Attest {args.attest_command} -> {result['status']}")
    if result.get("artifact"):
        print(f"Artifact: {result['artifact']}")
    for failure in result.get("failures", []):
        print(f"  failure: {failure}")
    if result.get("reason"):
        eprint(str(result["reason"]))
    return 3 if result["status"] in {"REJECTED", "NO_GO"} else 0


def command_agents(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    store = RunStore(repo)
    policy = load_policy(repo, getattr(args, "policy", "default"))
    if args.agents_command == "doctor":
        result = agents_doctor(policy)
    else:
        plan = store.load_plan(args.run_id)
        policy = load_policy(repo, plan.policy_profile)
        run_dir = store.run_dir(args.run_id)
        if args.agents_command == "plan":
            result = write_agent_plan(run_dir, plan, policy, requested_parallelism=args.parallel)
        elif args.agents_command == "execute":
            policy_error = _worker_execution_policy_error(policy, execute=args.execute, allow_network=args.allow_network)
            if policy_error:
                Ledger(run_dir, args.run_id).event("agents.execution_rejected", reason=policy_error)
                eprint(policy_error)
                return 3
            result = execute_agent_plan(run_dir, plan, policy, execute=args.execute, parallel=args.parallel, timeout=args.timeout)
        elif args.agents_command == "status":
            result = agent_status(run_dir, plan, policy)
        else:
            eprint(f"Unknown agents command: {args.agents_command}")
            return 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if args.agents_command == "doctor":
            print("Worker families:")
            for item in result["workers"]:
                state = "available" if item["available"] else "unavailable"
                print(f"  {item['worker']:<12} {state:<11} command={shlex.join(item['command']) if item['command'] else '<none>'}")
        elif args.agents_command == "plan":
            print(f"Agent plan: {result.get('artifact')}")
            print(f"Parallelism: {result.get('effective_parallelism')}")
            for task in result.get("tasks", []):
                print(f"  {task['agent_id']:<38} {task['worker_family']:<10} {task['mode']:<16} {task['status']}")
        elif args.agents_command == "execute":
            print(f"Agent execution: {result.get('artifact')}")
            for task in result.get("tasks", []):
                print(f"  {task['agent_id']:<38} {task['status']}")
        elif args.agents_command == "status":
            print(f"Agent status for {result['run_id']}:")
            for status, count in sorted(result["counts"].items()):
                print(f"  {status}: {count}")
    if args.agents_command == "execute":
        statuses = {str(task.get("status")) for task in result.get("tasks", [])}
        if statuses & {"failed", "blocked_unavailable_worker", "blocked_by_dependency", "blocked_by_permissions"}:
            return 1
    return 0


def command_ledger(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    store = RunStore(repo)
    run_dir = store.run_dir(args.run_id)
    ledger = Ledger(run_dir, args.run_id)
    if args.ledger_command == "seal-legacy":
        if not run_dir.exists():
            eprint(f"Run not found: {args.run_id}")
            return 2
        events = _load_run_events(run_dir)
        if any(event.get("event") == LEGACY_PREFIX_SEAL_EVENT for event in events) and not args.force:
            eprint("Legacy ledger prefix is already sealed; use --force only for a new explicit boundary.")
            return 3
        if not _ledger_integrity_errors(run_dir) and not args.force:
            eprint("Ledger already has release-valid canonical integrity; no legacy seal is needed.")
            return 3
        ledger.seal_legacy_prefix(reason=args.reason)
        print(f"Legacy ledger prefix sealed for {args.run_id}")
        print("Legacy events remain historical only; release-valid evidence must be written after this boundary.")
        return 0
    eprint(f"Unknown ledger command: {args.ledger_command}")
    return 2


def command_memory(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    result: dict[str, Any]
    if args.memory_command == "init":
        result = init_memory(repo, enabled=not args.disabled)
    elif args.memory_command == "status":
        result = memory_status(repo)
    elif args.memory_command == "record":
        store = RunStore(repo)
        plan = store.load_plan(args.run_id)
        result = record_episode(repo, plan, store.load_findings(args.run_id))
        Ledger(store.run_dir(args.run_id), args.run_id).event("memory.episode_recorded" if result.get("status") == "RECORDED" else "memory.record_rejected", result=result)
    elif args.memory_command == "search":
        result = search_memory(repo, args.query)
    elif args.memory_command == "export":
        result = export_memory(repo)
    elif args.memory_command == "delete":
        if not args.all:
            eprint("Memory delete requires --all")
            return 2
        result = delete_memory(repo)
    elif args.memory_command == "disable":
        result = disable_memory(repo)
    else:
        eprint(f"Unknown memory command: {args.memory_command}")
        return 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") != "REJECTED" else 3


def command_tui(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    store = RunStore(repo)
    plan = store.load_plan(args.run_id)
    findings = store.load_findings(args.run_id)
    readiness = _release_readiness_payload(repo, plan, findings)
    next_action = _recommend_next_action(plan, findings, readiness)
    print("=" * 80)
    print("SDLC CONTROL PLANE")
    print("=" * 80)
    _print_status(plan, readiness)
    print("\nCommand hints:")
    print(f"  {next_action['command']}")
    print(f"  sdlc next {args.run_id}")
    print(f"  sdlc agents status {args.run_id}")
    print(f"  sdlc finding list {args.run_id}")
    print(f"  sdlc report {args.run_id} --print")
    print("\nOpen findings:")
    open_items = [f for f in findings if f.status == "OPEN"]
    if not open_items:
        print("  <none>")
    for finding in open_items:
        print(f"  {finding.id} {finding.severity:<8} {finding.title}")
    print("=" * 80)
    return 0


def command_report(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    store = RunStore(repo)
    if args.finalize:
        return _finalize_report(repo, store, args.run_id, key=args.key, actor=args.actor)
    plan = store.load_plan(args.run_id)
    findings = store.load_findings(args.run_id)
    readiness_errors = _release_readiness_errors(store, plan, findings)
    if _audit_readonly_worker():
        verdict = final_verdict(findings, plan)
        report = build_report(
            repo,
            args.run_id,
            verdict_override="NO_GO" if verdict in POSITIVE_GATE_VERDICTS and readiness_errors else None,
            readiness_errors=readiness_errors,
        )
        if args.print:
            print(report)
        else:
            print("Report: <audit-readonly; not written>")
        return 0
    _persist_release_readiness(store.run_dir(args.run_id), args.run_id, _release_readiness_payload(repo, plan, findings))
    verdict = final_verdict(findings, plan)
    if verdict in POSITIVE_GATE_VERDICTS and readiness_errors:
        report = generate_report(repo, args.run_id, verdict_override="NO_GO", readiness_errors=readiness_errors)
    else:
        report = generate_report(repo, args.run_id, readiness_errors=readiness_errors)
    if args.print:
        print(report)
    else:
        path = repo / ".sdlc" / "runs" / args.run_id / "final-report.md"
        print(f"Report: {path}")
    return 0


def _finalize_report(repo: Path, store: RunStore, run_id: str, *, key: str | None, actor: str) -> int:
    if not key:
        eprint("Report finalization requires --key for artifact signing")
        return 2
    plan = store.load_plan(run_id)
    findings = store.load_findings(run_id)
    final_gate = next((gate for gate in plan.gates if gate.id == "final_report_reaudit"), None)
    if final_gate is None:
        eprint("Run is missing final_report_reaudit gate")
        return 2
    if actor not in {final_gate.owner, "human_release_manager", "human_security_owner"}:
        eprint(f"Actor {actor} is not authorized to finalize the report")
        return 2
    open_items = open_findings(findings)
    if open_items:
        eprint("Open findings block report finalization: " + ", ".join(finding.id for finding in open_items))
        return 1
    blockers = [
        f"{gate.id}={gate.state}/{gate.verdict or 'PENDING'}"
        for gate in sorted(plan.gates, key=lambda item: item.order)
        if gate.id not in {"evidence_traceability_attestations", "final_report_reaudit"} and not _gate_satisfied(gate, plan)
    ]
    if blockers:
        eprint("Unresolved gates block report finalization: " + ", ".join(blockers))
        return 1
    readiness_errors = _release_readiness_errors(store, plan, findings, ignore_gate_ids={"final_report_reaudit"})
    if readiness_errors:
        eprint("Release-readiness evidence blocks report finalization:")
        for error in readiness_errors:
            eprint(f"- {error}")
        return 1

    evidence = f".sdlc/runs/{run_id}/final-report.md"
    final_gate.state = "GO"
    final_gate.verdict = "GO"
    if evidence not in final_gate.evidence:
        final_gate.evidence.append(evidence)
    final_gate.notes = "Final report generated with atomic report/attestation finalization."
    store.save_plan(plan)
    ledger = Ledger(store.run_dir(run_id), run_id)
    ledger.event("gate.final_report_finalized", gate=final_gate.id, actor=actor, verdict="GO", evidence=[evidence])

    last_error = "final report was not finalized"
    for _attempt in range(3):
        generate_report(repo, run_id)
        write_artifact_manifest(store, run_id)
        signed = sign_artifact_manifest(store, run_id, key=key, execute=True)
        if signed.get("status") != "SIGNED":
            last_error = str(signed.get("reason") or "manifest signing failed")
            break
        verified = verify_artifact_manifest(store, run_id, key=key)
        if verified.get("status") != "GO":
            last_error = "; ".join(str(item) for item in verified.get("failures", [])) or "manifest verification failed"
            continue
        current_plan = store.load_plan(run_id)
        current_gate = next(gate for gate in current_plan.gates if gate.id == "final_report_reaudit")
        final_error = _validate_final_report_gate_completion(store, run_id, current_gate, "GO", [evidence])
        if final_error:
            last_error = final_error
            continue
        final_errors = _release_readiness_errors(store, current_plan, store.load_findings(run_id))
        if final_errors:
            last_error = "; ".join(final_errors[:5])
            continue
        print(f"Final report finalized: {store.run_dir(run_id) / 'final-report.md'}")
        return 0

    failed_plan = store.load_plan(run_id)
    failed_gate = next((gate for gate in failed_plan.gates if gate.id == "final_report_reaudit"), None)
    if failed_gate is not None:
        failed_gate.state = "BLOCKED"
        failed_gate.verdict = "NO_GO"
        failed_gate.notes = last_error
        store.save_plan(failed_plan)
    Ledger(store.run_dir(run_id), run_id).event("gate.final_report_finalize_failed", gate="final_report_reaudit", actor=actor, reason=last_error)
    generate_report(repo, run_id, verdict_override="NO_GO", readiness_errors=[last_error])
    eprint("Final report finalization failed: " + last_error)
    return 1


def _release_readiness_errors(
    store: RunStore,
    plan: RunPlan,
    findings: list[Finding],
    *,
    ignore_gate_ids: set[str] | None = None,
    audit_workspace: bool = False,
) -> list[str]:
    repo = store.repo
    run_dir = store.run_dir(plan.run_id)
    events = _load_run_events(run_dir)
    ignore_gate_ids = ignore_gate_ids or set()
    errors: list[str] = []
    plan_repo = Path(plan.repo).resolve(strict=False)
    repo_identity_differs = plan_repo != repo.resolve(strict=False)
    audit_workspace_copy = (
        audit_workspace
        and repo_identity_differs
        and os.environ.get("SDLC_WORKER_EXECUTION") == "1"
        and (repo / ".sdlc" / "runs" / plan.run_id / "plan.json").exists()
    )
    active_redteam_audit = audit_workspace_copy and _audit_readonly_worker()
    errors.extend(_ledger_integrity_errors(run_dir, require_origin=not audit_workspace_copy))
    if repo_identity_differs:
        if not audit_workspace:
            errors.append(f"Release validation repo mismatch: run plan repo {plan_repo} does not match active repo {repo.resolve(strict=False)}")
        elif os.environ.get("SDLC_WORKER_EXECUTION") != "1":
            errors.append("Audit-workspace release validation requires SDLC_WORKER_EXECUTION=1")
        elif not (repo / ".sdlc" / "runs" / plan.run_id / "plan.json").exists():
            errors.append("Audit-workspace release validation requires the reviewed run plan inside the audit workspace")
    if _git_source_provenance_required_for_release(plan, audit_workspace=audit_workspace):
        git_source_error = _release_git_provenance_source_error(store, plan, audit_workspace=audit_workspace)
        if git_source_error:
            errors.append(git_source_error)
    verdict = final_verdict(findings, plan)
    if not ignore_gate_ids and verdict not in POSITIVE_GATE_VERDICTS:
        errors.append(f"Release validation final verdict is {verdict}")
    if open_findings(findings):
        errors.append("Release validation found open findings")
    worker_policy_errors = _worker_policy_integrity_errors(events)
    errors.extend(worker_policy_errors)
    redteam_consistency_errors = _redteam_finding_consistency_errors(events, findings)
    if active_redteam_audit:
        redteam_consistency_errors = [
            error for error in redteam_consistency_errors
            if not error.startswith("Latest red-team execution appears paused or interrupted:")
        ]
    errors.extend(redteam_consistency_errors)
    errors.extend(_post_commit_validation_errors(events))
    for finding in findings:
        finding_error = _terminal_finding_evidence_error(repo, run_dir, finding, require_origin=not audit_workspace_copy)
        if finding_error:
            errors.append(finding_error)
        acceptance_error = _terminal_acceptance_evidence_error(repo, run_dir, finding, require_origin=not audit_workspace_copy)
        if acceptance_error:
            errors.append(acceptance_error)
    for gate in sorted(plan.gates, key=lambda item: item.order):
        if gate.id in ignore_gate_ids:
            continue
        if gate.state == "SKIPPED":
            if not _skipped_gate_valid(gate, plan):
                condition_value = plan_condition_value(plan, gate.conditional_on)
                errors.append(f"Gate {gate.id} has invalid skipped state for condition {gate.conditional_on or '<missing>'}={condition_value!r}")
            continue
        if gate.state == "WAIVED":
            errors.append(f"Gate {gate.id} is WAIVED without a supported waiver workflow")
            continue
        if not _gate_satisfied(gate, plan):
            errors.append(f"Gate {gate.id} is not release-satisfied: {gate.state}/{gate.verdict or 'PENDING'}")
            continue
        if not gate.evidence:
            errors.append(f"Gate {gate.id} is GO without evidence")
            continue
        placeholder_error = _validate_non_placeholder_evidence(repo, gate.verdict or "", gate.evidence)
        if placeholder_error:
            errors.append(placeholder_error)
        release_evidence_error = _validate_release_gate_evidence(repo, run_dir, gate, gate.verdict or "", gate.evidence)
        if release_evidence_error:
            errors.append(release_evidence_error)
        git_context_error = _validate_git_context_gate_release(plan, repo, run_dir, gate)
        if git_context_error:
            errors.append(git_context_error)
        security_error = _validate_security_gate_completion(store, plan.run_id, gate, gate.verdict or "", _latest_gate_actor(events, gate.id), gate.notes)
        if security_error:
            errors.append(security_error)
        redteam_error = _validate_redteam_gate_completion(store, plan, gate, gate.verdict or "", gate.evidence)
        if redteam_error:
            errors.append(redteam_error)
        deploy_error = _validate_deploy_gate_completion(store, plan, gate, gate.verdict or "")
        if deploy_error:
            errors.append(deploy_error)
        git_provenance_error = _validate_git_provenance_gate_completion(store, plan, gate, gate.verdict or "", gate.evidence, audit_workspace=audit_workspace)
        if git_provenance_error:
            errors.append(git_provenance_error)
        attestation_error = _validate_attestation_gate_completion(store, plan, gate, gate.verdict or "", gate.evidence)
        if attestation_error:
            errors.append(attestation_error)
        final_report_error = _validate_final_report_gate_completion(store, plan.run_id, gate, gate.verdict or "", gate.evidence)
        if final_report_error:
            errors.append(final_report_error)
        if gate.id not in {
            "security_scans",
            "independent_redteam_cross_model",
            "critical_high_fix_loop",
            "evidence_traceability_attestations",
            "deploy_rollout_postdeploy",
            "final_report_reaudit",
        } and not _has_gate_completion_event(events, gate.id):
            errors.append(f"Gate {gate.id} lacks ledger-backed completion evidence")
    return errors


def _git_source_provenance_required_for_release(plan: RunPlan, *, audit_workspace: bool) -> bool:
    if not audit_workspace:
        return True
    commit_gate = next((gate for gate in plan.gates if gate.id == "commit_branch_pr_ci"), None)
    return commit_gate is not None and _gate_satisfied(commit_gate, plan)


def _ledger_integrity_errors(run_dir: Path, *, require_origin: bool = True) -> list[str]:
    events_path = run_dir / "events.jsonl"
    if not events_path.exists():
        return []
    errors: list[str] = []
    entries: list[tuple[dict[str, object], int, bytes]] = []
    prefix = b""
    for line_number, raw_line in enumerate(events_path.read_bytes().splitlines(keepends=True), start=1):
        if not raw_line.strip():
            prefix += raw_line
            continue
        try:
            event = json.loads(raw_line.decode("utf-8"))
        except json.JSONDecodeError:
            errors.append(f"Run ledger events.jsonl contains malformed JSON at line {line_number}")
            break
        if not isinstance(event, dict):
            errors.append(f"Run ledger events.jsonl contains non-object event at line {line_number}")
            break
        entries.append((event, line_number, prefix))
        prefix += raw_line
    if errors or not entries:
        return errors

    start_index = 0
    previous_sha256: str | None = None
    if not is_canonical_ledger_event(
        entries[0][0],
        sequence=0,
        previous_sha256=None,
        require_origin=require_origin,
        run_dir=run_dir,
    ):
        boundary = _legacy_prefix_seal_boundary(entries, run_dir, require_origin=require_origin)
        if boundary is None:
            suffix = " or origin-authentication" if require_origin else ""
            errors.append(f"Run ledger event 0 failed canonical hash-chain{suffix} validation")
            return errors
        start_index, previous_sha256 = boundary

    for event_sequence in range(start_index, len(entries)):
        event = entries[event_sequence][0]
        if not is_canonical_ledger_event(
            event,
            sequence=event_sequence,
            previous_sha256=previous_sha256,
            require_origin=require_origin,
            run_dir=run_dir,
        ):
            suffix = " or origin-authentication" if require_origin else ""
            errors.append(f"Run ledger event {event_sequence} failed canonical hash-chain{suffix} validation")
            break
        previous_sha256 = str(event.get("event_sha256"))
    return errors


def _legacy_prefix_seal_boundary(
    entries: list[tuple[dict[str, object], int, bytes]],
    run_dir: Path,
    *,
    require_origin: bool = True,
) -> tuple[int, str | None] | None:
    for index, (event, _line_number, prefix_bytes) in enumerate(entries):
        if event.get("event") != LEGACY_PREFIX_SEAL_EVENT:
            continue
        if event.get("legacy_line_count") != index:
            continue
        if event.get("legacy_prefix_sha256") != hashlib.sha256(prefix_bytes).hexdigest():
            continue
        previous_sha256 = _legacy_previous_hash(entries[index - 1][0]) if index else None
        if not is_canonical_ledger_event(
            event,
            sequence=index,
            previous_sha256=previous_sha256,
            require_origin=require_origin,
            run_dir=run_dir,
        ):
            continue
        return index, previous_sha256
    return None


def _legacy_previous_hash(event: dict[str, object]) -> str:
    event_sha256 = event.get("event_sha256")
    if isinstance(event_sha256, str) and event_sha256:
        return event_sha256
    return ledger_event_digest(event)


def _terminal_acceptance_evidence_error(repo: Path, run_dir: Path, finding: Finding, *, require_origin: bool = True) -> str | None:
    if finding.status not in {"ACCEPTED", "DEFERRED"} or finding.severity not in {"CRITICAL", "HIGH", "MEDIUM"}:
        return None
    evidence_paths = [item for item in finding.closure_evidence if not item.startswith(("accept:", "defer:"))]
    reason = "\n".join(item for item in finding.closure_evidence if item.startswith(("accept:", "defer:")))
    error = _blocking_acceptance_evidence_error(repo, run_dir, finding, evidence_paths, reason, require_origin=require_origin)
    if error:
        return f"{finding.id} accepted/deferred residual risk evidence is invalid: {error}"
    return None


def _worker_policy_integrity_errors(events: list[dict[str, object]]) -> list[str]:
    errors: list[str] = []
    latest_clean_redteam = _latest_clean_redteam_completion_index(events)
    for index, event in enumerate(events):
        if event.get("event") == "worker.policy_violation" and event.get("resolved") is not True:
            worker = event.get("worker", "<unknown>")
            mode = event.get("mode", "<unknown>")
            errors.append(f"Unresolved worker policy violation remains for {worker}/{mode}")
        if event.get("event") == "redteam.worker_policy_violation":
            if index < latest_clean_redteam:
                continue
            worker = event.get("worker", "<unknown>")
            round_number = event.get("round", "<unknown>")
            errors.append(f"Red-team worker mutation violation remains for {worker} round {round_number}")
    return errors


def _latest_clean_redteam_completion_index(events: list[dict[str, object]]) -> int:
    for index in range(len(events) - 1, -1, -1):
        event = events[index]
        if event.get("event") != "redteam.execution_completed":
            continue
        if event.get("execute_requested") is not True:
            continue
        executed_families = event.get("executed_families")
        if not isinstance(executed_families, list) or not executed_families:
            continue
        if event.get("mutation_violations"):
            continue
        if event.get("rejected") is True:
            continue
        return index
    return -1


def _redteam_finding_consistency_errors(events: list[dict[str, object]], findings: list[Finding]) -> list[str]:
    errors: list[str] = []
    last_start = max((index for index, event in enumerate(events) if event.get("event") == "redteam.execution_started"), default=-1)
    last_completion = max((index for index, event in enumerate(events) if event.get("event") == "redteam.execution_completed"), default=-1)
    last_terminal = max((index for index, event in enumerate(events) if event.get("event") in REDTEAM_TERMINAL_EVENTS), default=-1)
    if last_start > last_terminal:
        errors.append(
            "Latest red-team execution appears paused or interrupted: redteam.execution_started has no terminal lifecycle event. "
            "Rerun red-team execution or record redteam.execution_cancelled before release validation."
        )
    elif last_terminal > last_completion and events[last_terminal].get("event") in REDTEAM_NONCOMPLETION_EVENTS:
        event = events[last_terminal]
        state = "cancelled" if event.get("event") == "redteam.execution_cancelled" else "interrupted"
        reason = str(event.get("reason") or "").strip()
        suffix = f" Reason: {reason}" if reason else ""
        errors.append(
            f"Latest red-team execution was {state} after start; Red-team execution was {state} before completion; "
            f"completion evidence is required before release validation.{suffix}"
        )
    canonical = {finding.id for finding in findings}
    parsed_ids: set[str] = set()
    for event in events:
        if event.get("event") != "redteam.findings_parsed":
            continue
        for finding_id in event.get("findings", []):
            parsed_ids.add(str(finding_id))
    missing = sorted(parsed_ids - canonical)
    if missing:
        errors.append("Parsed red-team findings are missing from canonical findings.json: " + ", ".join(missing[:10]))
    return errors


def _latest_gate_actor(events: list[dict[str, object]], gate_id: str) -> str | None:
    for event in reversed(events):
        if event.get("gate") == gate_id and isinstance(event.get("actor"), str):
            return str(event.get("actor"))
    return None


def _has_gate_completion_event(events: list[dict[str, object]], gate_id: str) -> bool:
    for event in events:
        if event.get("gate") != gate_id:
            continue
        if event.get("event") in {"gate.manually_completed", "gate.completed"}:
            return True
    return False


def _terminal_finding_evidence_error(repo: Path, run_dir: Path, finding: Finding, *, require_origin: bool = True) -> str | None:
    if finding.severity not in {"CRITICAL", "HIGH", "MEDIUM"}:
        return None
    if finding.status not in {"CLOSED", "ACCEPTED", "DEFERRED"}:
        return None
    if not finding.closed_by:
        return f"Finding {finding.id} is {finding.status} without closed_by provenance"
    if not finding.closure_evidence:
        return f"Finding {finding.id} is {finding.status} without closure evidence"
    if finding.status == "CLOSED":
        if finding.closed_by == finding.owner or finding.closed_by == "agent_3_implementation_owner":
            return f"Finding {finding.id} closure evidence is not release-valid: implementer/owner closed the finding"
        if finding.closed_by not in AUTHORIZED_FINDING_CLOSERS:
            return f"Finding {finding.id} closure evidence is not release-valid: unauthorized closer {finding.closed_by}"
        if finding.severity in {"CRITICAL", "HIGH", "MEDIUM"}:
            ledger_backed = _ledger_backed_closure_artifacts(repo, run_dir, finding.closure_evidence, require_origin=require_origin)
            evidence_text = "\n".join(str(item.get("text", "")) for item in ledger_backed).lower()
            if finding.id.lower() not in evidence_text and finding.title.lower() not in evidence_text:
                return f"Finding {finding.id} closure evidence is not release-valid: evidence does not reference the finding id or title"
            has_diff = any(
                item.get("event") in {"finding.remediation_diff", "remediation.diff_artifact"}
                and item.get("finding_id") == finding.id
                and "diff --git" in str(item.get("text", "")).lower()
                for item in ledger_backed
            )
            has_summary = any(
                item.get("event") in {"finding.remediation_summary", "remediation.summary"}
                and item.get("finding_id") == finding.id
                for item in ledger_backed
            )
            has_validation = any(
                _valid_independent_remediation_validation(
                    item,
                    finding=finding,
                    closed_by=finding.closed_by,
                    require_actor_proof=finding.severity in {"CRITICAL", "HIGH"},
                )
                for item in ledger_backed
            )
            if not has_diff:
                return f"Finding {finding.id} closure evidence is not release-valid: missing ledger-backed remediation diff"
            if not has_validation:
                return f"Finding {finding.id} closure evidence is not release-valid: missing independent second-validation"
            if not has_summary:
                return f"Finding {finding.id} closure evidence is not release-valid: missing remediation summary"
    elif finding.closed_by not in HUMAN_GATE_ACTORS:
        return f"Finding {finding.id} {finding.status} requires human residual-risk approval provenance"
    return None


def _latest_typed_gate_evidence(repo: Path, run_dir: Path, gate: GateState) -> dict[str, object] | None:
    recorded = _recorded_gate_evidence_records(run_dir, gate.id)
    for rel in reversed(gate.evidence):
        path = _resolve_run_evidence_path(repo, run_dir, rel)
        try:
            run_rel = str(path.resolve(strict=False).relative_to(run_dir.resolve(strict=False)))
        except ValueError:
            run_rel = rel
        if run_rel not in recorded:
            continue
        try:
            if _digest_file(path) != recorded[run_rel]:
                continue
        except OSError:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict) and payload.get("gate_id") == gate.id:
            return payload
    return None


def _typed_gate_artifact_transcript(repo: Path, run_dir: Path, gate: GateState, key: str) -> dict[str, object] | None:
    payload = _latest_typed_gate_evidence(repo, run_dir, gate)
    if not payload:
        return None
    bindings = payload.get("artifact_bindings")
    if not isinstance(bindings, dict):
        return None
    binding = bindings.get(key)
    if not isinstance(binding, dict):
        return None
    bound_path = str(binding.get("path", ""))
    if not bound_path:
        return None
    path = _resolve_run_evidence_path(repo, run_dir, bound_path)
    try:
        return _parse_command_transcript(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None


def _git_status_branch(stdout: str) -> str:
    for line in stdout.splitlines():
        if not line.startswith("## "):
            continue
        value = line[3:].strip()
        if value.startswith("No commits yet on "):
            return value.removeprefix("No commits yet on ").strip()
        branch = value.split("...", 1)[0].split(" ", 1)[0].strip()
        return branch
    return ""


def _validate_git_context_gate_release(plan: RunPlan, repo: Path, run_dir: Path, gate: GateState) -> str | None:
    if gate.id not in {"repo_context_env_branch", "baseline_freeze"}:
        return None
    status_key = "git_status" if gate.id == "repo_context_env_branch" else "git_status_before"
    status = _typed_gate_artifact_transcript(repo, run_dir, gate, status_key)
    if not status:
        return f"{gate.id} requires a typed machine-captured git status artifact"
    status_branch = _git_status_branch(str(status.get("stdout", "")))
    if not status_branch:
        return f"{gate.id} git status artifact must expose the current branch"
    if gate.id == "repo_context_env_branch":
        branch = _typed_gate_artifact_transcript(repo, run_dir, gate, "current_branch")
        if not branch:
            return "repo_context_env_branch requires a typed machine-captured current_branch artifact"
        branch_name = str(branch.get("stdout", "")).strip().splitlines()[0].strip()
        if branch_name != status_branch:
            return "repo_context_env_branch branch artifact does not match git status branch"
    else:
        branch_name = status_branch
    if plan.branch in {"", "unknown", "<unknown>"} or branch_name != plan.branch:
        return f"{gate.id} git branch evidence {branch_name} does not match run plan branch {plan.branch}"
    if _is_protected_branch(branch_name) and not plan.direct_main_push_allowed:
        return f"{gate.id} rejects protected branch {branch_name} without explicit policy"
    return None


def command_validate(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    errors: list[str] = []
    required = [
        repo / ".sdlc" / "pipeline.json",
        repo / ".sdlc" / "schemas" / "gate_result.schema.json",
        repo / ".sdlc" / "schemas" / "finding.schema.json",
    ]
    for path in required:
        if not path.exists():
            errors.append(f"Missing {path}")
    if args.run_id:
        store = RunStore(repo)
        try:
            plan = store.load_plan(args.run_id)
            if len(plan.gates) < 25:
                errors.append("Run plan has fewer than 25 gates")
            prompt = store.run_dir(args.run_id) / "prompts" / "execution_prompt.md"
            if not prompt.exists():
                errors.append("Run prompt missing")
            if not args.release and not args.structural_only:
                findings = store.load_findings(args.run_id)
                blocked_gates = [
                    f"{gate.id}={gate.state}/{gate.verdict}"
                    for gate in plan.gates
                    if gate.state in {"NO_GO", "FIX_REQUIRED", "BLOCKED"} or gate.verdict == "NO_GO"
                ]
                if blocked_gates:
                    errors.append("Run validation found blocked gates; use --structural-only for schema checks: " + ", ".join(blocked_gates))
                if open_findings(findings, {"CRITICAL", "HIGH"}):
                    errors.append("Run validation found open CRITICAL/HIGH findings")
            if args.release:
                findings = store.load_findings(args.run_id)
                release_errors = _release_readiness_errors(store, plan, findings, audit_workspace=args.audit_workspace)
                errors.extend(release_errors)
                if args.persist and not _audit_readonly_worker():
                    readiness = _release_readiness_payload(repo, plan, findings)
                    _persist_release_readiness(store.run_dir(args.run_id), args.run_id, readiness)
                    verdict = final_verdict(findings, plan)
                    generate_report(
                        repo,
                        args.run_id,
                        verdict_override="NO_GO" if verdict in POSITIVE_GATE_VERDICTS and release_errors else None,
                        readiness_errors=release_errors,
                    )
                elif args.persist and _audit_readonly_worker():
                    errors.append("Audit-readonly worker mode: release validation artifacts were not written")
        except Exception as exc:  # noqa: BLE001 - CLI should report any validation exception.
            errors.append(str(exc))
    if errors:
        print("Validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    if not args.run_id:
        print("Validation passed (repository structure only; use --run-id <run-id> --release for release readiness)")
    else:
        print("Validation passed")
    return 0


def _audit_readonly_worker() -> bool:
    return os.environ.get("SDLC_WORKER_EXECUTION") == "1" and os.environ.get("SDLC_WORKER_AUDIT_READONLY") == "1"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sdlc", description="Terminal-native Secure SDLC control plane for AI software delivery")
    parser.add_argument("--repo", default=".", help="Repository root")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize .sdlc structure")
    p_init.add_argument("--force", action="store_true", help="Rewrite default schemas/policies")
    p_init.set_defaults(func=command_init)

    p_plan = sub.add_parser("plan", help="Create a gated SDLC run and execution prompt")
    p_plan.add_argument("feature", help="Feature request")
    p_plan.add_argument("--risk", default="auto", choices=["auto", "low", "medium", "high", "extreme"])
    p_plan.add_argument("--ui", default="auto", choices=["auto", "yes", "no"])
    p_plan.add_argument("--security", default="auto", choices=["auto", "yes", "no"])
    p_plan.add_argument("--infra", default="auto", choices=["auto", "yes", "no"])
    p_plan.add_argument("--policy", default="default")
    p_plan.add_argument("--run-id")
    p_plan.add_argument("--production-rollout-allowed", action="store_true")
    p_plan.add_argument("--allow-main-push", action="store_true")
    p_plan.set_defaults(func=command_plan)

    p_start = sub.add_parser("start", help="Autopilot entrypoint: plan, brief, prework, agents, and next action")
    p_start.add_argument("request", help="Developer request")
    p_start.add_argument("--risk", default="auto", choices=["auto", "low", "medium", "high", "extreme"])
    p_start.add_argument("--ui", default="auto", choices=["auto", "yes", "no"])
    p_start.add_argument("--security", default="auto", choices=["auto", "yes", "no"])
    p_start.add_argument("--infra", default="auto", choices=["auto", "yes", "no"])
    p_start.add_argument("--policy", default="default")
    p_start.add_argument("--run-id")
    p_start.add_argument("--parallel", type=int, default=6)
    p_start.add_argument("--production-rollout-allowed", action="store_true")
    p_start.add_argument("--allow-main-push", action="store_true")
    p_start.add_argument("--json", action="store_true")
    p_start.set_defaults(func=command_start)

    p_brief = sub.add_parser("brief", help="Create intake brief, standards mapping, and prework reports")
    p_brief.add_argument("request", help="Developer request")
    p_brief.add_argument("--risk", default="auto", choices=["auto", "low", "medium", "high", "extreme"])
    p_brief.add_argument("--ui", default="auto", choices=["auto", "yes", "no"])
    p_brief.add_argument("--security", default="auto", choices=["auto", "yes", "no"])
    p_brief.add_argument("--infra", default="auto", choices=["auto", "yes", "no"])
    p_brief.add_argument("--policy", default="default")
    p_brief.add_argument("--run-id")
    p_brief.add_argument("--html", action="store_true", help="Compatibility flag; HTML is generated by default.")
    p_brief.add_argument("--json", action="store_true")
    p_brief.set_defaults(func=command_brief)

    p_status = sub.add_parser("status", help="Show run status")
    p_status.add_argument("run_id")
    p_status.add_argument("--json", action="store_true")
    p_status.add_argument("--persist", action="store_true", help="Write release readiness artifacts while showing status")
    p_status.set_defaults(func=command_status)

    p_next = sub.add_parser("next", help="Recommend the safest next action for a run")
    p_next.add_argument("run_id")
    p_next.add_argument("--json", action="store_true")
    p_next.add_argument("--persist", action="store_true", help="Write release readiness and next-action artifacts.")
    p_next.set_defaults(func=command_next)

    p_run = sub.add_parser("run", help="Advance deterministic/dry gates")
    p_run.add_argument("run_id")
    p_run.add_argument("--redteam", action="store_true", help="Create deterministic red-team findings after gate pass")
    p_run.set_defaults(func=command_run)

    p_worker = sub.add_parser("worker", help="Invoke a worker adapter in dry-run or explicit execution mode")
    p_worker.add_argument("run_id")
    p_worker.add_argument("worker")
    p_worker.add_argument("--mode", default="READ_ONLY", choices=["READ_ONLY", "PLAN", "BUILD", "TEST", "SECURITY_REVIEW", "FIX"])
    p_worker.add_argument("--prompt", default="execution_prompt.md")
    p_worker.add_argument("--execute", action="store_true", help="Actually run the worker command. Default is dry-run.")
    p_worker.add_argument("--allow-network", action="store_true", help="Required with --execute and policy network_allowed=true for external worker CLIs.")
    p_worker.add_argument("--timeout", type=int, default=120, help="Per-worker timeout in seconds. Default: 120.")
    p_worker.set_defaults(func=command_worker)

    p_redteam = sub.add_parser("redteam", help="Run deterministic or explicit worker red-team evidence")
    p_redteam.add_argument("redteam_args", nargs="+", metavar="run_id|execute")
    p_redteam.add_argument("--workers", default="", help="Comma-separated worker families for `redteam execute`; defaults to policy redteam.default_workers")
    p_redteam.add_argument("--rounds", type=int, default=1, help="Worker execution rounds for `redteam execute`")
    p_redteam.add_argument("--execute", action="store_true", help="Actually invoke red-team workers. Default is dry-run evidence capture.")
    p_redteam.add_argument("--allow-network", action="store_true", help="Required with --execute when worker CLIs require network and policy network_allowed=true.")
    p_redteam.add_argument("--timeout", "--worker-timeout", dest="timeout", type=int, default=120, help="Per-worker timeout in seconds. Default: 120.")
    p_redteam.add_argument("--total-timeout", type=int, help="Optional total red-team command timeout in seconds.")
    p_redteam.add_argument("--parallel-per-round", action="store_true", help="Run workers in each round concurrently only when policy redteam.parallel_per_round_allowed=true.")
    p_redteam.add_argument("--fail-on-findings", action="store_true", help="Return non-zero when red-team execution leaves a NO_GO gate")
    p_redteam.add_argument("--allow-no-go-exit-zero", action="store_true", help="Compatibility escape hatch: return zero on NO_GO and record a ledger bypass event.")
    p_redteam.set_defaults(func=command_redteam)

    p_scan = sub.add_parser("scan", help="Run security scanners and capture evidence")
    p_scan.add_argument("run_id")
    p_scan.add_argument("--allow-network", action="store_true", help="Allow policy-approved network scanners")
    p_scan.add_argument("--fail-on-findings", action="store_true", help="Deprecated compatibility flag; NO_GO scans return non-zero by default.")
    p_scan.add_argument("--allow-no-go-exit-zero", action="store_true", help="Compatibility escape hatch: return zero on NO_GO and record a ledger bypass event.")
    p_scan.set_defaults(func=command_scan)

    p_deploy = sub.add_parser("deploy", help="Plan, approve, execute, verify, and rollback locked deployments")
    deploy_sub = p_deploy.add_subparsers(dest="deploy_command", required=True)
    d_plan = deploy_sub.add_parser("plan", help="Capture a deployment plan. Default behavior is dry-run evidence.")
    d_plan.add_argument("run_id")
    d_plan.add_argument("--env", required=True, choices=["staging", "production"])
    d_plan.add_argument("--rollback-command", help="Explicit rollback command plan required before production execution.")
    d_plan.set_defaults(func=command_deploy)
    d_approve = deploy_sub.add_parser("approve", help="Record human deployment approval evidence")
    d_approve.add_argument("run_id")
    d_approve.add_argument("--env", required=True, choices=["staging", "production"])
    d_approve.add_argument("--actor", required=True)
    d_approve.add_argument("--evidence", nargs="+", required=True)
    d_approve.add_argument("--actor-proof", help="HMAC proof for production deployment approval.")
    d_approve.set_defaults(func=command_deploy)
    d_execute = deploy_sub.add_parser("execute", help="Record deployment execution only when explicitly authorized")
    d_execute.add_argument("run_id")
    d_execute.add_argument("--env", required=True, choices=["staging", "production"])
    d_execute.add_argument("--execute", action="store_true", help="Required for execution. Default is dry-run evidence capture.")
    d_execute.add_argument("--command", help="Explicit command to execute with shell parsing disabled. Required with --execute.")
    d_execute.set_defaults(func=command_deploy)
    d_verify = deploy_sub.add_parser("verify", help="Record smoke/monitoring verification evidence")
    d_verify.add_argument("run_id")
    d_verify.add_argument("--env", required=True, choices=["staging", "production"])
    d_verify.add_argument("--evidence", nargs="+", required=True)
    d_verify.add_argument("--accepted-residual-risk")
    d_verify.add_argument("--actor", help="Required human release/security actor when accepting deployment residual risk.")
    d_verify.add_argument("--actor-proof", help="HMAC proof for deployment residual-risk acceptance.")
    d_verify.set_defaults(func=command_deploy)
    d_rollback = deploy_sub.add_parser("rollback", help="Record rollback dry-run or explicit rollback evidence")
    d_rollback.add_argument("run_id")
    d_rollback.add_argument("--env", required=True, choices=["staging", "production"])
    d_rollback.add_argument("--execute", action="store_true", help="Required to record rollback execution. Default is dry-run evidence capture.")
    d_rollback.add_argument("--command", help="Explicit rollback command to execute with shell parsing disabled. Required with --execute.")
    d_rollback.add_argument("--evidence", nargs="+", help="Rollback readiness or staging rollback proof evidence for non-destructive production GO.")
    d_rollback.set_defaults(func=command_deploy)

    p_attest = sub.add_parser("attest", help="Generate, sign, and verify run artifact attestations")
    attest_sub = p_attest.add_subparsers(dest="attest_command", required=True)
    a_manifest = attest_sub.add_parser("manifest", help="Generate a deterministic artifact manifest")
    a_manifest.add_argument("run_id")
    a_manifest.set_defaults(func=command_attest)
    a_sign = attest_sub.add_parser("sign", help="Sign the artifact manifest with a local key")
    a_sign.add_argument("run_id")
    a_sign.add_argument("--key", required=True)
    a_sign.add_argument("--execute", action="store_true", help="Actually sign. Default is dry-run evidence capture.")
    a_sign.set_defaults(func=command_attest)
    a_verify = attest_sub.add_parser("verify", help="Verify artifact manifest digests and signature")
    a_verify.add_argument("run_id")
    a_verify.add_argument("--key")
    a_verify.set_defaults(func=command_attest)

    p_agents = sub.add_parser("agents", help="Plan, execute, inspect, and diagnose role-agent work")
    agents_sub = p_agents.add_subparsers(dest="agents_command", required=True)
    ag_plan = agents_sub.add_parser("plan", help="Create a six-agent task plan")
    ag_plan.add_argument("run_id")
    ag_plan.add_argument("--parallel", type=int, default=6)
    ag_plan.add_argument("--json", action="store_true")
    ag_plan.set_defaults(func=command_agents)
    ag_execute = agents_sub.add_parser("execute", help="Execute or dry-run a planned agent batch")
    ag_execute.add_argument("run_id")
    ag_execute.add_argument("--parallel", type=int, default=6)
    ag_execute.add_argument("--execute", action="store_true")
    ag_execute.add_argument("--allow-network", action="store_true")
    ag_execute.add_argument("--timeout", type=int, default=120)
    ag_execute.add_argument("--json", action="store_true")
    ag_execute.set_defaults(func=command_agents)
    ag_status = agents_sub.add_parser("status", help="Show agent task status")
    ag_status.add_argument("run_id")
    ag_status.add_argument("--json", action="store_true")
    ag_status.set_defaults(func=command_agents)
    ag_doctor = agents_sub.add_parser("doctor", help="Show worker family availability")
    ag_doctor.add_argument("--policy", default="default")
    ag_doctor.add_argument("--json", action="store_true")
    ag_doctor.set_defaults(func=command_agents)

    p_ledger = sub.add_parser("ledger", help="Inspect and seal run ledger integrity boundaries")
    ledger_sub = p_ledger.add_subparsers(dest="ledger_command", required=True)
    l_seal = ledger_sub.add_parser("seal-legacy", help="Sign a boundary after pre-HMAC ledger history")
    l_seal.add_argument("run_id")
    l_seal.add_argument("--reason", required=True)
    l_seal.add_argument("--force", action="store_true", help="Record another explicit boundary even when one exists")
    l_seal.set_defaults(func=command_ledger)

    p_memory = sub.add_parser("memory", help="Manage local consent-based episodic memory")
    memory_sub = p_memory.add_subparsers(dest="memory_command", required=True)
    mem_init = memory_sub.add_parser("init", help="Initialize local memory")
    mem_init.add_argument("--disabled", action="store_true")
    mem_init.add_argument("--json", action="store_true")
    mem_init.set_defaults(func=command_memory)
    mem_status = memory_sub.add_parser("status", help="Show memory status")
    mem_status.add_argument("--json", action="store_true")
    mem_status.set_defaults(func=command_memory)
    mem_record = memory_sub.add_parser("record", help="Record a run episode")
    mem_record.add_argument("run_id")
    mem_record.add_argument("--json", action="store_true")
    mem_record.set_defaults(func=command_memory)
    mem_search = memory_sub.add_parser("search", help="Search local memory")
    mem_search.add_argument("query")
    mem_search.add_argument("--json", action="store_true")
    mem_search.set_defaults(func=command_memory)
    mem_export = memory_sub.add_parser("export", help="Export local memory")
    mem_export.add_argument("--json", action="store_true")
    mem_export.set_defaults(func=command_memory)
    mem_delete = memory_sub.add_parser("delete", help="Delete all local memory")
    mem_delete.add_argument("--all", action="store_true", help="Required for clarity; all memory is deleted.")
    mem_delete.add_argument("--json", action="store_true")
    mem_delete.set_defaults(func=command_memory)
    mem_disable = memory_sub.add_parser("disable", help="Disable local memory")
    mem_disable.add_argument("--json", action="store_true")
    mem_disable.set_defaults(func=command_memory)

    p_finding = sub.add_parser("finding", help="Manage red-team finding lifecycle")
    finding_sub = p_finding.add_subparsers(dest="finding_command", required=True)
    f_list = finding_sub.add_parser("list", help="List findings")
    f_list.add_argument("run_id")
    f_list.set_defaults(func=command_finding)
    f_show = finding_sub.add_parser("show", help="Show one finding as JSON")
    f_show.add_argument("run_id")
    f_show.add_argument("finding_id")
    f_show.set_defaults(func=command_finding)
    for action in ["accept", "defer"]:
        f_action = finding_sub.add_parser(action, help=f"{action} a finding with rationale")
        f_action.add_argument("run_id")
        f_action.add_argument("finding_id")
        f_action.add_argument("--reason", required=True)
        f_action.add_argument("--closed-by")
        f_action.add_argument("--evidence", nargs="+", required=True)
        f_action.add_argument("--human-override", action="store_true")
        f_action.add_argument("--actor-proof", help="HMAC proof for policies requiring authenticated finding acceptance")
        f_action.set_defaults(func=command_finding)
    f_close = finding_sub.add_parser("close", help="Close a finding with independent evidence")
    f_close.add_argument("run_id")
    f_close.add_argument("finding_id")
    f_close.add_argument("--closed-by", default="agent_6_redteam_deploy_rollback")
    f_close.add_argument("--actor-proof", help="HMAC proof for policies requiring authenticated finding closure")
    f_close.add_argument("--evidence", nargs="+", required=True)
    f_close.set_defaults(func=command_finding)

    p_gate = sub.add_parser("gate", help="Manually complete or update a gate with evidence")
    gate_sub = p_gate.add_subparsers(dest="gate_command", required=True)
    g_complete = gate_sub.add_parser("complete", help="Complete a gate with a structured verdict")
    g_complete.add_argument("run_id")
    g_complete.add_argument("gate_id")
    g_complete.add_argument("--verdict", required=True, choices=["GO", "NO_GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS", "SKIPPED"])
    g_complete.add_argument("--evidence", nargs="*")
    g_complete.add_argument("--notes")
    g_complete.add_argument("--actor", help="Required agent or human authority completing the gate")
    g_complete.set_defaults(func=command_gate)
    g_evidence = gate_sub.add_parser("evidence", help="Record typed ledger-backed gate evidence")
    g_evidence.add_argument("run_id")
    g_evidence.add_argument("gate_id")
    g_evidence.add_argument("--actor", required=True)
    g_evidence.add_argument("--artifact", nargs="+", required=True, help="Required artifact mapping as key=value")
    g_evidence.add_argument("--source", nargs="*", help="Optional supporting evidence paths")
    g_evidence.add_argument("--notes")
    g_evidence.set_defaults(func=command_gate)

    p_git = sub.add_parser("git", help="Safe Git branch, commit, and PR helpers")
    git_sub = p_git.add_subparsers(dest="git_command", required=True)
    git_branch = git_sub.add_parser("branch", help="Create or switch to the run feature branch")
    git_branch.add_argument("run_id")
    git_branch.add_argument("--name", help="Override branch name. Defaults to sdlc/<run-id>.")
    git_branch.add_argument("--allow-protected-branch", action="store_true", help="Require plan policy allow-main-push before using a protected branch")
    git_branch.set_defaults(func=command_git)

    git_commit = git_sub.add_parser("commit", help="Commit staged changes for a run")
    git_commit.add_argument("run_id")
    git_commit.add_argument("--message", required=True, help="Commit message in `verb: subject` format")
    git_commit.add_argument("--allow-protected-branch", action="store_true", help="Require plan policy allow-main-push before committing on a protected branch")
    git_commit.set_defaults(func=command_git)

    git_pr = git_sub.add_parser("pr", help="Prepare or explicitly create a pull request")
    git_pr.add_argument("run_id")
    git_pr.add_argument("--base", default="main")
    git_pr.add_argument("--title")
    git_pr.add_argument("--body")
    git_pr.add_argument("--execute", action="store_true", help="Actually run gh pr create. Default is dry-run.")
    git_pr.add_argument("--allow-network", action="store_true", help="Required with --execute and policy network_allowed=true")
    git_pr.set_defaults(func=command_git)

    git_provenance = git_sub.add_parser("provenance", help="Capture ledger-backed Git branch, commit, PR, and local CI provenance")
    git_provenance.add_argument("run_id")
    git_provenance.set_defaults(func=command_git)

    p_tui = sub.add_parser("tui", help="Show a terminal dashboard for a run")
    p_tui.add_argument("run_id")
    p_tui.set_defaults(func=command_tui)

    p_report = sub.add_parser("report", help="Generate final report")
    p_report.add_argument("run_id")
    p_report.add_argument("--print", action="store_true")
    p_report.add_argument("--finalize", action="store_true", help="Atomically mark the final report gate, regenerate the report, and re-attest it.")
    p_report.add_argument("--key", help="Signing key used with --finalize.")
    p_report.add_argument("--actor", default="agent_4_evidence_reporting_owner", help="Actor finalizing the report.")
    p_report.set_defaults(func=command_report)

    p_validate = sub.add_parser("validate", help="Validate repo/run structure")
    p_validate.add_argument("--run-id")
    p_validate.add_argument("--release", action="store_true", help="With --run-id, enforce release-readiness gates and findings instead of only structure.")
    p_validate.add_argument("--audit-workspace", action="store_true", help="Allow plan.repo mismatch only for SDLC_WORKER_EXECUTION disposable audit workspaces.")
    p_validate.add_argument("--persist", action="store_true", help="With --release, persist refreshed readiness and report artifacts.")
    p_validate.add_argument("--structural-only", action="store_true", help="With --run-id, only check files/schema and do not treat blocked gates as command failure.")
    p_validate.set_defaults(func=command_validate)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
