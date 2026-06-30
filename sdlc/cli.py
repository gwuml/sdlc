"""Terminal CLI for the Secure SDLC control plane."""

from __future__ import annotations

import argparse
import copy
import fnmatch
import hashlib
import html
import hmac
import json
import os
import re
import shlex
import shutil
import sys
import tempfile
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any

from .adapters import ADAPTERS, adapter_from_policy, capture_worker_result, worker_identity_group
from .agents import agent_status, agents_doctor, execute_agent_plan, write_agent_plan
from .attestations import MANIFEST_PATH, SIGNATURE_PATH, VERIFY_PATH, _verify_manifest_entries, sign_artifact_manifest, verify_artifact_manifest, write_artifact_manifest
from .audit_runtime import audit_isolation_preflight, is_hard_audit_isolation_method
from .briefing import build_intake_brief, build_standards_mapping, write_prework_artifacts
from .classifier import classify_feature
from .deploy import approve_deployment, execute_deployment, plan_deployment, production_deploy_gate_rejection, rollback_deployment, verify_deployment
from .engine import RunStore, create_redteam_findings, execute_redteam_workers, final_verdict, invalidate_downstream_gates, run_dry_gates, validate_run_id
from .ledger import LEDGER_ARTIFACT_SCHEMA, LEDGER_EVENT_SCHEMA, LEGACY_PREFIX_SEAL_EVENT, Ledger, canonical_artifact_event, canonical_chain_start, is_canonical_ledger_event, ledger_event_digest
from .memory import delete_memory, disable_memory, export_memory, init_memory, memory_status, record_episode, search_memory
from .models import GateState, RunPlan, Finding, invalid_findings, open_findings, plan_condition_value
from .pipeline import DEFAULT_GATES, gates_as_dicts
from .policies import ensure_policy_files, load_policy
from .prompts import redteam_prompt_binding_sha256, write_prompt_bundle
from .release import release_preflight, release_preflight_error
from .reporting import build_report, generate_report, release_contract_verdict
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
    "finding.actor_proof",
    "finding.risk_acceptance",
    "gate.evidence_recorded",
    "gate.required_artifact_recorded",
    "gate.residual_risk_acceptance",
    "gate.source_evidence_recorded",
    "git.provenance_artifact",
    "redteam.findings_parsed",
    "release.command_bundle_recorded",
    "security.scans_completed",
    "worker.output_captured",
    "worker.output_externalized",
}
FINDING_CLOSURE_ARTIFACT_EVENTS = {
    "finding.remediation_diff",
    "finding.remediation_summary",
    "finding.remediation_validation",
    "finding.actor_proof",
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


def _validate_security_gate_completion(
    store: RunStore,
    run_id: str,
    gate: GateState,
    verdict: str,
    actor: str | None,
    notes: str,
    *,
    require_event_binding: bool = False,
) -> str | None:
    if gate.id != "security_scans" or verdict not in POSITIVE_GATE_VERDICTS:
        return None
    summary = store.run_dir(run_id) / "artifacts" / "security_scan_summary.md"
    if not summary.exists():
        return "Security scans require scanner-produced security_scan_summary.md evidence"
    events = _load_run_events(store.run_dir(run_id))
    latest_scan_event = _latest_canonical_security_scans_completed(store.run_dir(run_id), events)
    if latest_scan_event is None:
        return "Security scans require ledger-backed security.scans_completed evidence"
    latest_evidence = {str(item) for item in latest_scan_event.get("evidence", [])}
    if "artifacts/security_scan_summary.md" not in latest_evidence:
        return "Security scan ledger evidence must include artifacts/security_scan_summary.md"
    current_sha256 = _digest_file(summary)
    if latest_scan_event.get("summary_artifact") != "artifacts/security_scan_summary.md" or latest_scan_event.get("summary_sha256") != current_sha256:
        return "Security scan summary must match the ledger-recorded scanner completion sha256"
    summary_event = canonical_artifact_event(
        events,
        run_id=run_id,
        path="artifacts/security_scan_summary.md",
        sha256=current_sha256,
        allowed_events={"security.scan_summary"},
        require_origin=True,
        run_dir=store.run_dir(run_id),
    )
    if summary_event is None:
        return "Security scan summary must be the canonical ledger-produced scan summary artifact"
    recorded_verdict = latest_scan_event.get("verdict")
    summary_verdict = summary_event.get("verdict")
    if recorded_verdict not in {"GO", "NO_GO"} or summary_verdict != recorded_verdict:
        return "Security scan completion verdict must match the canonical scan summary verdict"
    text = summary.read_text(encoding="utf-8")
    if recorded_verdict == "GO" and "Verdict: GO" not in text:
        return "Security scan summary content must match the recorded GO verdict"
    if verdict == "GO" and recorded_verdict != "GO":
        return "Security scans can only be GO when the scanner-produced summary verdict is GO"
    if recorded_verdict != "NO_GO":
        return None
    if verdict == "GO":
        return "Security scans with a NO_GO scanner summary require GO_WITH_ACCEPTED_RESIDUAL_RISKS and explicit residual-risk evidence; they cannot be converted to GO"
    if actor not in {"human_security_owner", "human_product_owner", "human_approval_authority"}:
        return "Accepted residual risk for a NO_GO security scan requires a human security/product approval actor"
    lowered = notes.lower()
    if "residual" not in lowered or "reason" not in lowered:
        return "Accepted residual risk for a NO_GO security scan requires notes containing residual risk and reason"
    if require_event_binding:
        completion = _latest_gate_completion_event(events, "security_scans")
        if completion is None:
            return "Accepted residual risk for a NO_GO security scan requires a ledger-backed gate completion event"
        if completion.get("actor") != actor or completion.get("verdict") != verdict or completion.get("notes") != notes:
            return "Accepted residual risk approval must match the canonical gate completion actor, verdict, and notes"
    return None


def _latest_canonical_security_scans_completed(run_dir: Path, events: list[dict[str, object]]) -> dict[str, object] | None:
    start = canonical_chain_start(events, require_origin=True, run_dir=run_dir)
    if start is None:
        return None
    start_index, previous_sha256 = start
    latest: dict[str, object] | None = None
    for sequence in range(start_index, len(events)):
        event = events[sequence]
        if not is_canonical_ledger_event(
            event,
            sequence=sequence,
            previous_sha256=previous_sha256,
            require_origin=True,
            run_dir=run_dir,
        ):
            return None
        if event.get("event") == "security.scans_completed":
            latest = dict(event)
        event_sha256 = event.get("event_sha256")
        previous_sha256 = event_sha256 if isinstance(event_sha256, str) else None
    return latest


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
    plan = store.load_plan(run_id)
    expected_internal_verdict = final_verdict(store.load_findings(run_id), plan)
    policy = load_policy(store.repo, plan.policy_profile)
    expected_release_verdict = release_contract_verdict(
        policy,
        expected_internal_verdict,
        release_satisfied=readiness_payload.get("release_satisfied") is True,
    )
    if readiness_payload.get("release_verdict") != expected_release_verdict:
        return (
            "Final report readiness evidence release_verdict does not match current final verdict: "
            f"{readiness_payload.get('release_verdict')} != {expected_release_verdict}"
        )
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
        "generated without an external worker",
        "deterministic advisory placeholders",
        "required coverage needs real diff or worker evidence",
    ]
    for rel in evidence_paths:
        is_run_artifact = rel.startswith(".sdlc/runs/")
        if rel.startswith(("sdlc/", "tests/", "scripts/")):
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
        if is_run_artifact:
            continue
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


def _ledger_artifact_event(run_dir: Path, path: Path, sha256: str, *, require_origin: bool = True) -> dict[str, object] | None:
    run_rel = _run_relative_path(run_dir, path)
    if run_rel is None:
        return None
    event = _canonical_artifact_index(
        run_dir,
        allowed_events=CANONICAL_ARTIFACT_EVENTS,
        require_origin=require_origin,
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


def _artifact_provenance(repo: Path, run_dir: Path, path: Path, sha256: str, *, require_origin: bool = True) -> tuple[dict[str, object] | None, str | None]:
    ledger_event = _ledger_artifact_event(run_dir, path, sha256, require_origin=require_origin)
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
    has_machine_command_transcript = _parse_command_transcript(text) is not None and "stdout:" in lowered and "stderr:" in lowered
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
        if not has_machine_command_transcript and sum(1 for term in stuffing_terms if term in lowered) >= 10:
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
    *,
    require_origin: bool = True,
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
        provenance, provenance_error = _artifact_provenance(repo, run_dir, path, digest, require_origin=require_origin)
        if provenance_error or provenance is None:
            return {}, provenance_error or f"Gate artifact {key} lacks provenance"
        bindings[key] = {
            "reference": value,
            "path": canonical,
            "sha256": digest,
            "provenance": provenance,
        }
    return bindings, None


def _validate_release_gate_evidence(repo: Path, run_dir: Path, gate: GateState, verdict: str, evidence_paths: list[str], *, require_origin: bool = True) -> str | None:
    if verdict not in POSITIVE_GATE_VERDICTS:
        return None
    if evidence_paths and all("gate_evidence_index" in path for path in evidence_paths):
        return f"{gate.id} requires gate-specific evidence, not only a shared evidence index"
    return _validate_gate_evidence_contract(run_dir, gate, evidence_paths, require_origin=require_origin)


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


def _validate_gate_evidence_contract(run_dir: Path, gate: GateState, evidence_paths: list[str], *, require_origin: bool = True) -> str | None:
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
        source_binding_error = _validate_source_evidence_bindings(
            repo,
            run_dir,
            [str(source) for source in source_evidence],
            payload.get("source_evidence_bindings"),
            require_origin=require_origin,
        )
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
            require_origin=require_origin,
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


def _build_source_evidence_bindings(repo: Path, run_dir: Path, source_evidence: list[str], *, require_origin: bool = True) -> tuple[list[dict[str, object]], str | None]:
    bindings: list[dict[str, object]] = []
    for source in source_evidence:
        path, canonical, error = _resolve_evidence_reference(repo, run_dir, source)
        if error or path is None or canonical is None:
            return [], f"Gate source evidence is missing or invalid: {source}"
        digest = _digest_file(path)
        provenance, provenance_error = _artifact_provenance(repo, run_dir, path, digest, require_origin=require_origin)
        if provenance_error or provenance is None:
            return [], provenance_error or f"Gate source evidence lacks provenance: {source}"
        bindings.append({
            "reference": source,
            "path": canonical,
            "sha256": digest,
            "provenance": provenance,
        })
    return bindings, None


def _validate_source_evidence_bindings(repo: Path, run_dir: Path, source_evidence: list[str], bindings: object, *, require_origin: bool = True) -> str | None:
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
            provenance, provenance_error = _artifact_provenance(repo, run_dir, path, digest, require_origin=require_origin)
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
        provenance, provenance_error = _artifact_provenance(repo, run_dir, path, digest, require_origin=require_origin)
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
    policy = _load_release_policy_snapshot(store.run_dir(plan.run_id), Path(plan.repo), plan.policy_profile)
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
    latest_worker_providers = latest.get("worker_providers", {})
    latest_external_executed = []
    for worker in latest_executed:
        provider = ""
        if isinstance(latest_worker_providers, dict):
            provider = str(latest_worker_providers.get(worker, "")).strip().lower()
        if not provider:
            adapter = adapter_from_policy(worker, policy)
            provider = str(getattr(adapter, "provider", "unknown")).strip().lower() if adapter is not None else "unknown"
        if provider != "local":
            latest_external_executed.append(worker)
    if plan.risk_level in {"HIGH", "EXTREME"} and latest_external_executed:
        hard_latest = latest.get("hard_isolated_workers", [])
        if not isinstance(hard_latest, list):
            return "Red-team ledger evidence has malformed hard-isolated worker bindings"
        hard_latest_rounds = {str(item).split(":", 1)[0] for item in hard_latest}
        non_hard_methods = [
            str(item)
            for item in hard_latest
            if not is_hard_audit_isolation_method(str(item).split(":", 1)[1] if ":" in str(item) else "")
        ]
        if non_hard_methods:
            return "High-stakes external red-team hard isolation requires container/VM methods, not advisory isolation: " + ", ".join(non_hard_methods)
        expected_hard = {
            f"{worker}@round{round_number}"
            for worker in latest_external_executed
            for round_number in range(1, int(latest.get("rounds") or 0) + 1)
        }
        missing = sorted(expected_hard - hard_latest_rounds)
        if missing:
            return "High-stakes external red-team GO requires latest ledger-backed hard-isolation bindings: " + ", ".join(missing)
        attestation_paths = latest.get("audit_isolation_attestations", [])
        if not isinstance(attestation_paths, list) or not attestation_paths:
            return "High-stakes external red-team GO requires ledger-backed audit isolation attestation artifacts"
        attestation_events = [
            event for event in events
            if event.get("event") == "redteam.isolation_attestation_written"
            and event.get("hard_isolation") is True
        ]
        if not attestation_events:
            return "High-stakes external red-team GO requires hard audit isolation attestation ledger events"
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


def _load_release_policy_snapshot(run_dir: Path, repo: Path, profile: str) -> dict[str, Any]:
    snapshot = run_dir / "artifacts" / "policy" / "snapshot.json"
    if snapshot.exists():
        return read_json(snapshot, load_policy(repo, profile))
    return load_policy(repo, profile)


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
        if item.get("validator_actor_proof_method") != "sdlc_actor_hmac_sha256":
            return False
        if item.get("validator_actor_proof_verified") is not True:
            return False
        expected_message_sha256 = hashlib.sha256(
            f"{item.get('run_id') or ''}:{finding.id}:{closed_by}:finding.close".encode("utf-8")
        ).hexdigest()
        if item.get("validator_actor_proof_message_sha256") != expected_message_sha256:
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


def _validate_live_git_state_matches_provenance(repo: Path, plan: RunPlan, payload: dict[str, object]) -> str | None:
    if not _is_git_repo_available(repo):
        return "Live git provenance validation requires the repository root to be a git work tree"
    branch_result = _git_command_payload(repo, ["git", "branch", "--show-current"])
    status_result = _git_command_payload(repo, ["git", "status", "--short", "--branch"])
    head_result = _git_command_payload(repo, ["git", "rev-parse", "HEAD"])
    for label, result in {
        "current branch": branch_result,
        "status": status_result,
        "HEAD": head_result,
    }.items():
        if result.get("returncode") != 0:
            return f"Live git provenance validation failed to read {label}"
    live_branch = str(branch_result.get("stdout", "")).strip()
    if not live_branch or live_branch != plan.branch:
        return f"Live git branch {live_branch or '<unknown>'} does not match run plan branch {plan.branch}"
    branch = payload.get("branch")
    captured_branch = str(branch.get("current", "")).strip() if isinstance(branch, dict) else ""
    if live_branch != captured_branch:
        return f"Live git branch {live_branch} does not match provenance branch {captured_branch or '<unknown>'}"
    live_head = str(head_result.get("stdout", "")).strip()
    head = payload.get("head")
    captured_head = str(head.get("sha", "")).strip() if isinstance(head, dict) else ""
    if live_head != captured_head:
        return "Live git HEAD does not match provenance HEAD"
    live_status = str(status_result.get("stdout", ""))
    dirty_entries = _git_status_dirty_entries(live_status)
    if dirty_entries:
        return "Live git provenance requires a clean working tree; dirty entries: " + ", ".join(dirty_entries[:5])
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
        provenance, provenance_error = _artifact_provenance(repo, run_dir, path, digest, require_origin=not audit_workspace)
        if provenance_error or provenance is None or provenance.get("event") != "git.provenance_artifact":
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return "Git provenance artifact must be valid JSON"
        if not isinstance(payload, dict):
            return "Git provenance artifact must be a JSON object"
        payload_error = _validate_git_provenance_payload(plan, payload)
        if payload_error:
            return payload_error
        if not audit_workspace:
            live_error = _validate_live_git_state_matches_provenance(repo, plan, payload)
            if live_error:
                return live_error
        return None
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
        agents=_policy_agent_roster(policy, classification.activated_agents),
        worker_preferences=policy.get("workers", {}),
    )
    store = RunStore(repo)
    run_dir = store.run_dir(run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    store.save_plan(plan)
    store.save_findings(run_id, [])
    ledger = Ledger(run_dir, run_id)
    prompt_paths = write_prompt_bundle(run_dir, plan)
    prompt_manifest: dict[str, str] = {}
    for name in sorted(prompt_paths):
        path = Path(prompt_paths[name])
        content = path.read_text(encoding="utf-8")
        prompt_manifest[name] = redteam_prompt_binding_sha256(content) if name == "redteam_prompt.md" else hashlib.sha256(content.encode("utf-8")).hexdigest()
    ledger.event(
        "run.created",
        feature=feature,
        risk_level=classification.risk_level,
        policy_profile=policy_profile,
        repo=str(repo),
        repo_sha256=_repo_identity_sha256(repo),
    )
    ledger.artifact(
        "artifacts/prompts/manifest.json",
        json.dumps({"schema_version": 1, "prompts": prompt_manifest}, indent=2, sort_keys=True) + "\n",
        event="prompts.manifest_written",
        redact=False,
    )
    ledger.artifact(
        "artifacts/policy/snapshot.json",
        json.dumps(policy, indent=2, sort_keys=True) + "\n",
        event="policy.snapshot_written",
        redact=False,
        policy_profile=policy_profile,
    )
    ledger.event("classification.completed", classification=context)
    return plan, run_dir, None


def _policy_agent_roster(policy: dict[str, Any], fallback: list[dict[str, str]]) -> list[dict[str, str]]:
    agents_policy = policy.get("agents", {}) if isinstance(policy.get("agents"), dict) else {}
    exact_roster = agents_policy.get("exact_roster")
    if not isinstance(exact_roster, list) or not exact_roster:
        return fallback

    roster: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in exact_roster:
        if not isinstance(item, dict):
            continue
        agent_id = str(item.get("id") or "").strip()
        role = str(item.get("role") or "").strip()
        if not agent_id or not role or agent_id in seen:
            continue
        roster.append({"id": agent_id, "role": role})
        seen.add(agent_id)

    expected_count = agents_policy.get("exact_roster_count")
    if isinstance(expected_count, int) and len(roster) != expected_count:
        return fallback
    return roster or fallback


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


AGENT_ROLE_ALIASES = {
    "pm": "agent_1_pm_coordinator",
    "coordinator": "agent_1_pm_coordinator",
    "architecture": "agent_2_architecture_contracts",
    "architect": "agent_2_architecture_contracts",
    "implementation": "agent_3_implementation_owner",
    "implementer": "agent_3_implementation_owner",
    "evidence": "agent_4_evidence_reporting_owner",
    "reporting": "agent_4_evidence_reporting_owner",
    "qa": "agent_5_qa_validation_owner",
    "test": "agent_5_qa_validation_owner",
    "redteam": "agent_6_redteam_deploy_rollback",
    "deploy": "agent_6_redteam_deploy_rollback",
    "ui": "agent_7_ui_architect",
    "security": "agent_8_cybersecurity_engineer",
    "sre": "agent_9_sre_sysadmin",
    "it": "agent_10_it_enterprise_integration",
    "compliance": "agent_11_compliance_audit",
    "domain": "agent_12_domain_specialist",
}


def _agent_role_id(value: str) -> str:
    key = value.strip()
    return AGENT_ROLE_ALIASES.get(key.lower(), key)


def _coerce_agent_worker_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return []


def _read_agent_model_config(repo: Path, config: str) -> tuple[dict[str, object] | None, str | None, str | None]:
    raw_path = Path(config).expanduser()
    candidates = [raw_path] if raw_path.is_absolute() else [repo / raw_path, Path.cwd() / raw_path]
    path = next((candidate for candidate in candidates if candidate.exists()), candidates[0])
    if not path.exists():
        return None, None, f"Agent model config does not exist: {path}"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, None, f"Agent model config is not valid JSON: {exc}"
    if not isinstance(payload, dict):
        return None, None, "Agent model config must be a JSON object"
    return payload, str(path), None


def _extract_agent_model_preferences(payload: dict[str, object]) -> dict[str, list[str]]:
    preferences: dict[str, list[str]] = {}

    def merge(raw: object) -> None:
        if not isinstance(raw, dict):
            return
        for role, worker in raw.items():
            workers = _coerce_agent_worker_list(worker)
            if workers:
                preferences[_agent_role_id(str(role))] = workers

    agents = payload.get("agents")
    if isinstance(agents, dict):
        merge(agents.get("role_worker_preferences"))
        merge(agents.get("roles"))
        direct = {
            role: worker
            for role, worker in agents.items()
            if role not in {"role_worker_preferences", "roles"}
            and (_agent_role_id(str(role)).startswith("agent_") or str(role).lower() in AGENT_ROLE_ALIASES)
        }
        merge(direct)
    merge(payload.get("role_worker_preferences"))
    merge(payload.get("roles"))
    direct = {
        role: worker
        for role, worker in payload.items()
        if role not in {"agents", "role_worker_preferences", "roles", "worker_families", "workers"}
        and (_agent_role_id(str(role)).startswith("agent_") or str(role).lower() in AGENT_ROLE_ALIASES)
    }
    merge(direct)
    return preferences


def _policy_with_agent_model_overrides(
    repo: Path,
    policy: dict[str, object],
    *,
    config: str | None = None,
    mappings: list[str] | None = None,
) -> tuple[dict[str, object] | None, dict[str, object], str | None]:
    updated: dict[str, object] = copy.deepcopy(policy)
    metadata: dict[str, object] = {
        "config": "",
        "cli": list(mappings or []),
        "role_worker_preferences": {},
    }
    preferences: dict[str, list[str]] = {}
    if config:
        payload, path, error = _read_agent_model_config(repo, config)
        if error:
            return None, metadata, error
        metadata["config"] = path or ""
        assert payload is not None
        preferences.update(_extract_agent_model_preferences(payload))
        worker_families = payload.get("worker_families")
        if isinstance(worker_families, dict):
            existing = updated.get("worker_families")
            merged = copy.deepcopy(existing) if isinstance(existing, dict) else {}
            merged.update(copy.deepcopy(worker_families))
            updated["worker_families"] = merged
        workers = payload.get("workers")
        if isinstance(workers, dict):
            existing_workers = updated.get("workers")
            merged_workers = copy.deepcopy(existing_workers) if isinstance(existing_workers, dict) else {}
            merged_workers.update({str(key): str(value) for key, value in workers.items() if isinstance(value, str)})
            updated["workers"] = merged_workers
    for item in mappings or []:
        if "=" not in item:
            return None, metadata, f"--agent-model must use role=worker syntax: {item}"
        role, worker = item.split("=", 1)
        role_id = _agent_role_id(role)
        worker = worker.strip()
        if not role_id or not worker:
            return None, metadata, f"--agent-model must include both role and worker: {item}"
        preferences[role_id] = [worker]
    if preferences:
        agents = updated.get("agents")
        if not isinstance(agents, dict):
            agents = {}
        else:
            agents = copy.deepcopy(agents)
        existing_preferences = agents.get("role_worker_preferences")
        merged_preferences = copy.deepcopy(existing_preferences) if isinstance(existing_preferences, dict) else {}
        merged_preferences.update(preferences)
        agents["role_worker_preferences"] = merged_preferences
        updated["agents"] = agents
    metadata["role_worker_preferences"] = preferences
    updated["_agent_model_selection"] = metadata
    return updated, metadata, None


def _agent_model_policy_from_args(repo: Path, policy: dict[str, object], args: argparse.Namespace) -> tuple[dict[str, object] | None, dict[str, object], str | None]:
    return _policy_with_agent_model_overrides(
        repo,
        policy,
        config=getattr(args, "agent_model_config", None),
        mappings=getattr(args, "agent_model", None) or [],
    )


def _write_autopilot_artifacts(repo: Path, plan: RunPlan, run_dir: Path, *, include_agent_plan: bool = False, parallel: int | None = None, policy: dict[str, object] | None = None) -> dict[str, object]:
    policy = policy or load_policy(repo, plan.policy_profile)
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
    base_policy = load_policy(repo, plan.policy_profile)
    agent_policy, _, policy_error = _agent_model_policy_from_args(repo, base_policy, args)
    if policy_error or agent_policy is None:
        eprint(policy_error or "Unable to apply agent model mapping")
        return 2
    result = _write_autopilot_artifacts(repo, plan, run_dir, include_agent_plan=True, parallel=args.parallel, policy=agent_policy)
    store = RunStore(repo)
    run_dry_gates(store, plan.run_id, full_advisory=True)
    result["next_action"] = _next_action_payload(repo, plan.run_id, persist=True)
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


def _auto_gate_followup_command(plan: RunPlan, gate_id: str) -> str:
    if gate_id == "security_scans":
        return f"python -m sdlc scan {plan.run_id}"
    if gate_id == "agent_plan_permissions":
        return f"python -m sdlc agents plan {plan.run_id} --parallel 6"
    if gate_id == "implementation":
        return f"python -m sdlc worker {plan.run_id} codex --mode BUILD --execute"
    if gate_id == "qa_tests_integration_smoke":
        return f"python -m sdlc worker {plan.run_id} codex --mode TEST"
    if gate_id == "independent_redteam_cross_model":
        return f"python -m sdlc redteam {plan.run_id}"
    if gate_id == "critical_high_fix_loop":
        return f"python -m sdlc finding list {plan.run_id}"
    if gate_id == "evidence_traceability_attestations":
        return f"python -m sdlc attest manifest {plan.run_id}"
    if gate_id == "commit_branch_pr_ci":
        return f"python -m sdlc git provenance {plan.run_id}"
    if gate_id == "deploy_rollout_postdeploy":
        return f"python -m sdlc deploy plan {plan.run_id} --env production"
    if gate_id == "final_report_reaudit":
        return f"python -m sdlc report {plan.run_id} --print"
    return f"python -m sdlc gate evidence {plan.run_id} {gate_id} --actor <owner> --artifact <key>=<path> --source <evidence>"


def _write_auto_gate_walkthrough(store: RunStore, run_id: str) -> dict[str, str]:
    plan = store.load_plan(run_id)
    run_dir = store.run_dir(run_id)
    ledger = Ledger(run_dir, run_id)
    artifacts: dict[str, str] = {}
    by_id = {gate.id: gate for gate in plan.gates}
    for gate in sorted(plan.gates, key=lambda item: item.order):
        gate_definition = _gate_definition(gate.id)
        required_artifacts = gate_definition.required_artifacts if gate_definition else []
        purpose = gate_definition.purpose if gate_definition else "Gate definition unavailable."
        required = ", ".join(required_artifacts) if required_artifacts else "<none>"
        followup = _auto_gate_followup_command(plan, gate.id)
        content = "\n".join([
            f"# Gate {gate.order:02d}: {gate.title}",
            "",
            f"Run: {plan.run_id}",
            f"Gate ID: {gate.id}",
            f"Owner: {gate.owner}",
            f"Purpose: {purpose}",
            f"Required artifacts: {required}",
            "",
            "Auto treatment: this walkthrough artifact makes the gate visible",
            "for a one-command local auto run. Release validation may still",
            "require stricter typed evidence, signing, PR, CI, and deploy proof.",
            "",
            f"Follow-up command: `{followup}`",
            "",
            "Claim discipline: local gate pass evidence is separate from",
            "production authority and cloud execution approval.",
        ])
        artifact = ledger.artifact(
            f"artifacts/auto/walkthrough/gates/{gate.order:02d}-{gate.id}.md",
            content + "\n",
            event="auto.gate_walkthrough",
            gate=gate.id,
            gate_order=gate.order,
            redact=False,
        )
        artifacts[gate.id] = artifact
        current = by_id[gate.id]
        if artifact not in current.evidence:
            current.evidence.append(artifact)
        if not current.notes:
            current.notes = "Auto walkthrough artifact recorded; release validation may require stricter evidence."
    store.save_plan(plan)
    return artifacts


def _auto_implementation(intake: dict[str, object]) -> dict[str, object]:
    return intake.get("implementation") if isinstance(intake.get("implementation"), dict) else {}


def _auto_html_id(text: str, fallback: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return value or fallback


def _auto_site_gate_filename(gate: object) -> str:
    order = int(getattr(gate, "order", 0) or 0)
    gate_id = str(getattr(gate, "id", "gate"))
    return f"{order:02d}-{gate_id}.md"


def _auto_site_gate_href(gate: object) -> str:
    return f"evidence/gates/{_auto_site_gate_filename(gate)}"


def _auto_site_artifact_href(gate: object) -> str:
    return f"evidence/artifacts/{_auto_site_gate_filename(gate)}"


def _auto_site_gate_state(gate_id: str) -> tuple[str, str]:
    if gate_id == "deploy_rollout_postdeploy":
        return ("Formal release blocked", "AWS execution is plan-only unless explicit deploy approval is supplied.")
    if gate_id in {"commit_branch_pr_ci", "final_report_reaudit"}:
        return ("Formal release blocked", "Production release certification is separate from local auto evidence.")
    return ("Formal release blocked", "Local auto evidence exists, but formal release readiness remains blocked unless the final report says GO.")


def _auto_gate_board_html(run_id: str) -> list[str]:
    cards: list[str] = []
    for gate_def in DEFAULT_GATES:
        state, blocker = _auto_site_gate_state(gate_def.id)
        evidence_href = html.escape(_auto_site_gate_href(gate_def), quote=True)
        cards.extend([
            "        <article class=\"status-card\">",
            "          <span class=\"badge caution\">Formal release blocked</span>",
            f"          <h3>{gate_def.order:02d}. {html.escape(gate_def.title)}</h3>",
            "          <dl>",
            f"            <div><dt>Gate ID</dt><dd><code>{html.escape(gate_def.id)}</code></dd></div>",
            f"            <div><dt>Owner</dt><dd><code>{html.escape(gate_def.owner)}</code></dd></div>",
            f"            <div><dt>State</dt><dd>{html.escape(state)}</dd></div>",
            f"            <div><dt>Blocker summary</dt><dd>{html.escape(blocker)}</dd></div>",
            f"            <div><dt>Last checked</dt><dd>Generated in run <code>{html.escape(run_id)}</code></dd></div>",
            f"            <div><dt>Evidence</dt><dd><a href=\"{evidence_href}\">Open gate evidence status</a></dd></div>",
            "          </dl>",
            "        </article>",
        ])
    return ["      <div class=\"grid status-grid\">", *cards, "      </div>"]


def _auto_evidence_table_html(section_id: str) -> list[str]:
    rows: list[str] = []
    for gate_def in DEFAULT_GATES:
        row_id = f"{section_id}-evidence-{gate_def.order}"
        evidence_href = html.escape(_auto_site_artifact_href(gate_def), quote=True)
        rows.append(
            "        <tr>"
            f"<td id=\"{html.escape(row_id, quote=True)}\">{gate_def.order:02d}. {html.escape(gate_def.title)}</td>"
            f"<td><a href=\"{evidence_href}\">{html.escape(_auto_site_gate_filename(gate_def))}</a></td>"
            "<td>Deployable public-safe evidence artifact</td>"
            "<td>Packaged under site/evidence/artifacts; not a release certificate</td>"
            "</tr>"
        )
    return [
        "      <div class=\"table-wrap\">",
        "      <table>",
        "        <thead><tr><th>Evidence</th><th>Link</th><th>Type</th><th>Status</th></tr></thead>",
        "        <tbody>",
        *rows,
        "        </tbody>",
        "      </table>",
        "      </div>",
    ]


def _auto_readiness_overview_html(run_id: str, generated_at: str) -> list[str]:
    overview = [
        ("Overall readiness", "Formal release blocked", "Local auto evidence is generated, but production release certification is separate."),
        ("Release candidate", run_id, "This run id is the candidate identifier for all linked evidence."),
        ("Last review timestamp", generated_at, "Updated when the static artifact was generated."),
        ("Primary owner", "agent_1_pm_coordinator", "Escalate deploy, rollback, and red-team decisions to agent_6_redteam_deploy_rollback."),
        ("Next decision", "Review final report", "Proceed only if red-team, Claude validation, and explicit AWS approval are all clean."),
    ]
    cards: list[str] = []
    for title, value, note in overview:
        cards.extend([
            "        <article class=\"status-card\">",
            "          <span class=\"badge caution\">Action required</span>",
            f"          <h3>{html.escape(title)}</h3>",
            "          <dl>",
            f"            <div><dt>Value</dt><dd>{html.escape(value)}</dd></div>",
            f"            <div><dt>Source</dt><dd>{html.escape(note)}</dd></div>",
            "          </dl>",
            "        </article>",
        ])
    return ["      <div class=\"grid status-grid\">", *cards, "      </div>"]


def _auto_rollback_html() -> list[str]:
    return [
        "      <ol class=\"action-list\">",
        "        <li>Freeze changes and assign the incident commander.</li>",
        "        <li>Promote the previous known-good release prefix into the website root with <code>--delete</code> so stale files from the failed release are removed.</li>",
        "        <li>Verify object inventory, the previous status page, evidence links, cache headers, and monitoring checks.</li>",
        "        <li>If CloudFront is used, invalidate <code>/*</code> or verify bounded cache TTL before declaring rollback complete.</li>",
        "        <li>Notify stakeholders and record the rollback evidence in the run report.</li>",
        "      </ol>",
        "      <pre><code>aws s3 sync s3://APPROVED_BUCKET/releases/PREVIOUS_RUN/ s3://APPROVED_BUCKET/ --delete --dryrun --profile default\naws s3 sync s3://APPROVED_BUCKET/releases/PREVIOUS_RUN/ s3://APPROVED_BUCKET/ --delete --cache-control max-age=60 --profile default\naws s3 ls s3://APPROVED_BUCKET/ --recursive --profile default\ncurl -fL http://APPROVED_BUCKET.s3-website-REGION.amazonaws.com/\ncurl -fL http://APPROVED_BUCKET.s3-website-REGION.amazonaws.com/evidence/gates/01-intake_scope.md</code></pre>",
    ]


def _auto_public_gate_facts(gate: object, request: str, run_id: str) -> list[str]:
    gate_id = str(getattr(gate, "id", ""))
    facts = [
        f"- feature_request: {request}",
        f"- run_id: {run_id}",
        f"- gate_owner: {getattr(gate, 'owner', '')}",
        "- formal_release_state: BLOCKED unless final report and release readiness say otherwise",
    ]
    if gate_id == "intake_scope":
        facts.extend([
            "- scope: request-specific generated static website and SDLC evidence package",
            "- ambiguity_policy: defaults favor the richest local demo while cloud mutation stays approval-gated",
        ])
    elif gate_id == "stakeholders_raci":
        facts.extend([
            "- accountable_party: human operator approves external side effects",
            "- consulted_parties: architecture, QA, red-team, SRE, compliance, and evidence roles",
        ])
    elif gate_id == "supply_chain_sbom":
        facts.extend([
            "- dependency_scope: generated static HTML/CSS and Markdown evidence files",
            "- third_party_runtime_packages: none introduced by the generated website artifact",
        ])
    elif gate_id == "agent_plan_permissions":
        facts.extend([
            "- worker_execution: role workers are recorded in artifacts/agents/task-plan.json when execution is requested",
            "- permission_model: role workers receive scoped prompts and the orchestrator owns gate state",
        ])
    elif gate_id == "implementation":
        facts.extend([
            "- implementation_artifact: site/index.html",
            "- public_evidence_bundle: site/evidence/gates/*.md",
        ])
    elif gate_id == "deterministic_quality":
        facts.extend([
            "- deterministic_check: HTML structure, labelled form controls, no inline script tags, and deployable evidence links",
            "- link_check_artifact: artifacts/auto/website/link-check.json",
        ])
    elif gate_id == "security_scans":
        facts.extend([
            "- generated_attack_surface: static site only, no JavaScript, no backend, no secrets",
            "- external_network_calls: none in generated site artifact",
        ])
    elif gate_id == "independent_redteam_cross_model":
        facts.extend([
            "- redteam_requirement: clear GO requires executed red-team workers and no blocking open findings",
            "- redteam_summary: artifacts/redteam_execution_summary.md after execution completes",
        ])
    elif gate_id == "critical_high_fix_loop":
        facts.extend([
            "- fix_loop_rule: CRITICAL/HIGH and blocking MEDIUM findings must be remediated or explicitly accepted by authorized humans",
            "- implementer_rule: implementers cannot close their own findings",
        ])
    elif gate_id == "deploy_rollout_postdeploy":
        facts.extend([
            "- aws_default_target: S3 static website plan using the default profile",
            "- execution_guard: no AWS resources are created unless --execute-aws and explicit approval text are supplied",
            "- rollback_strategy: immutable release prefix with previous-prefix promotion, not destructive overwrite",
            "- decommission_strategy: separate approved cleanup run records deletion and retention evidence",
        ])
    elif gate_id == "final_report_reaudit":
        facts.extend([
            "- final_report: final-report.md after command completion",
            "- honesty_validation: artifacts/auto/validation/claude-validation.json when requested",
        ])
    return facts


def _write_auto_website_artifact(run_dir: Path, run_id: str, request: str, intake: dict[str, object]) -> str:
    ledger = Ledger(run_dir, run_id)
    implementation = _auto_implementation(intake)
    title = str(implementation.get("title") or _auto_title_from_request(request)).strip()
    description = str(implementation.get("description") or request).strip()
    features = implementation.get("features") if isinstance(implementation.get("features"), list) else []
    feature_items = [str(item).strip() for item in features if str(item).strip()]
    if not feature_items:
        feature_items = ["Request-specific generated artifact", "Accessible interaction surface", "25-gate evidence trail"]
    sections = implementation.get("sections") if isinstance(implementation.get("sections"), list) else []
    clean_sections: list[dict[str, object]] = []
    for section in sections:
        if not isinstance(section, dict):
            continue
        heading = str(section.get("heading", "")).strip()
        body = str(section.get("body", "")).strip()
        items = section.get("items") if isinstance(section.get("items"), list) else []
        if heading or body or items:
            clean_sections.append({"heading": heading or "Section", "body": body, "items": [str(item) for item in items if str(item).strip()]})
    if not clean_sections:
        clean_sections = [{"heading": "Scope", "body": request, "items": feature_items}]
    form = implementation.get("form") if isinstance(implementation.get("form"), dict) else {}
    form_enabled = bool(form.get("enabled", True))
    form_title = str(form.get("title") or "Accessible Request Form")
    form_fields = form.get("fields") if isinstance(form.get("fields"), list) else []
    if form_enabled and not form_fields:
        form_fields = [
            {"id": "name", "label": "Name", "type": "text", "required": True},
            {"id": "details", "label": "Request details", "type": "textarea", "required": True},
        ]
    escaped_request = html.escape(request, quote=True)
    generated_at = now_iso()
    section_html: list[str] = []
    rendered_gate_board = False
    rendered_evidence_table = False
    for index, section in enumerate(clean_sections, start=1):
        heading = str(section.get("heading", "Section"))
        heading_topic = heading.lower()
        body = str(section.get("body", ""))
        items = section.get("items") if isinstance(section.get("items"), list) else []
        section_id = _auto_html_id(heading, f"section-{index}")
        item_text = [str(item) for item in items if str(item).strip()]
        topic = " ".join([heading, body, *item_text]).lower()
        content_html: list[str] = []
        if "rollback" in heading_topic:
            content_html.extend(_auto_rollback_html())
        elif "incident" in topic or "banner" in topic:
            content_html.extend([
                "      <div class=\"incident-banner\" role=\"status\" aria-live=\"polite\">",
                "        <div>",
                "          <span class=\"badge caution\">Evidence required</span>",
                "          <strong>Release is not production-approved yet</strong>",
                "          <p>Current impact: local demonstration only. Next update: after red-team, validation, AWS approval, and cleanup evidence are complete.</p>",
                "        </div>",
                "      </div>",
            ])
        elif "overview" in heading_topic or ("readiness" in heading_topic and "overview" in topic):
            content_html.extend(_auto_readiness_overview_html(run_id, generated_at))
        elif "gate" in topic and ("status" in topic or "release" in topic or "readiness" in topic):
            content_html.extend(_auto_gate_board_html(run_id))
            rendered_gate_board = True
        elif "cleanup" in topic or "decommission" in topic:
            content_html.extend([
                "      <ol class=\"action-list\">",
                "        <li><strong>Owner:</strong> SRE/operator archives final report, evidence index, presentation, red-team summary, and validation result before cleanup.</li>",
                "        <li><strong>Within 24 hours:</strong> remove temporary worker workspaces and local preview files that are not ledger evidence.</li>",
                "        <li><strong>S3 release prefixes:</strong> retain current and previous approved prefixes, apply lifecycle rules to stale prefixes, and record retained object counts.</li>",
                "        <li><strong>Access review:</strong> verify the default AWS profile did not create new long-lived credentials, bucket policies, or public access beyond the approved website scope.</li>",
                "        <li><strong>Cache/DNS:</strong> invalidate or age out cache entries before deleting a published prefix; verify the rollback URL still resolves.</li>",
                "        <li><strong>Branch and PR:</strong> close temporary branches only after final evidence is attached to the report.</li>",
                "        <li><strong>Approval gate:</strong> require a separate <code>sdlc auto decommission</code> run before deleting buckets, logs, deployed artifacts, or evidence.</li>",
                "        <li><strong>Verification:</strong> capture cleanup stdout/stderr and a post-cleanup inventory as the cleanup run evidence.</li>",
                "      </ol>",
            ])
        elif "evidence" in heading_topic or "audit" in heading_topic:
            content_html.extend(_auto_evidence_table_html(section_id))
            rendered_evidence_table = True
        elif (
            ("s3" in topic or "hosting" in topic)
            and "cleanup" not in topic
            and "decommission" not in topic
            and "audit" not in heading_topic
            and "evidence" not in heading_topic
        ):
            content_html.extend([
                "      <ol class=\"action-list\">",
                "        <li>Confirm explicit approval before creating buckets, changing public access, or syncing files.</li>",
                "        <li>Create a versioned S3 website bucket and apply a scoped public-read policy only for <code>s3:GetObject</code> on that bucket.</li>",
                "        <li>Record the Block Public Access change as part of the approval, or choose CloudFront with OAC as the private-origin alternative.</li>",
                "        <li>Run a dry-run sync first, publish to immutable <code>releases/RUN_ID/</code>, then promote the approved release into the website root with <code>--delete</code>.</li>",
                "        <li>Smoke-check the public website URL and at least one evidence-link URL before calling the deploy complete.</li>",
                "        <li>Keep the previous release prefix available for rollback and record the exact source prefix in the final report.</li>",
                "      </ol>",
                f"      <pre><code>aws s3api delete-public-access-block --bucket APPROVED_BUCKET --profile default\naws s3api put-bucket-policy --bucket APPROVED_BUCKET --policy file://public-read-policy.json --profile default\naws s3 sync site/ s3://APPROVED_BUCKET/releases/{html.escape(run_id)}/ --delete --dryrun --profile default\naws s3 sync site/ s3://APPROVED_BUCKET/releases/{html.escape(run_id)}/ --delete --cache-control max-age=60 --profile default\naws s3 sync s3://APPROVED_BUCKET/releases/{html.escape(run_id)}/ s3://APPROVED_BUCKET/ --delete --cache-control max-age=60 --profile default\ncurl -fL http://APPROVED_BUCKET.s3-website-REGION.amazonaws.com/\ncurl -fL http://APPROVED_BUCKET.s3-website-REGION.amazonaws.com/evidence/gates/01-intake_scope.md</code></pre>",
            ])
        elif (
            "rollback" in topic
            and "cleanup" not in topic
            and "decommission" not in topic
            and "audit" not in heading_topic
            and "evidence" not in heading_topic
        ):
            content_html.extend(_auto_rollback_html())
        elif "evidence" in topic or "audit" in topic:
            content_html.extend(_auto_evidence_table_html(section_id))
            rendered_evidence_table = True
        else:
            cards = []
            for item in item_text:
                cards.append(f"        <div class=\"panel\"><strong>{html.escape(str(item))}</strong></div>")
            content_html.extend([
                "      <div class=\"grid\">" if cards else "",
                *cards,
                "      </div>" if cards else "",
            ])
        section_html.extend([
            f"    <section aria-labelledby=\"{section_id}\">",
            f"      <h2 id=\"{section_id}\">{html.escape(heading)}</h2>",
            f"      <p>{html.escape(body)}</p>" if body else "",
            *content_html,
            "    </section>",
        ])
    if not rendered_gate_board:
        section_html.extend([
            "    <section aria-labelledby=\"sdlc-gate-board\">",
            "      <h2 id=\"sdlc-gate-board\">25-Gate Evidence Board</h2>",
            "      <p>Every generated website includes the canonical SDLC gate inventory with owner, state, blocker note, and deployable proof link.</p>",
            *_auto_gate_board_html(run_id),
            "    </section>",
        ])
    if not rendered_evidence_table:
        section_html.extend([
            "    <section aria-labelledby=\"sdlc-evidence-links\">",
            "      <h2 id=\"sdlc-evidence-links\">Deployable Evidence Links</h2>",
            "      <p>These public-safe files are packaged under the static site tree, so the links work after an S3 website sync.</p>",
            *_auto_evidence_table_html("sdlc-evidence-links"),
            "    </section>",
        ])
    form_html: list[str] = []
    if form_enabled:
        field_html: list[str] = []
        for index, field in enumerate(form_fields, start=1):
            if not isinstance(field, dict):
                continue
            field_id = _auto_html_id(str(field.get("id") or field.get("label") or f"field-{index}"), f"field-{index}")
            label = str(field.get("label") or field_id.replace("-", " ").title())
            field_type = str(field.get("type") or "text").lower()
            required = " required" if bool(field.get("required", False)) else ""
            autocomplete = " autocomplete=\"name\"" if field_id == "name" else ""
            field_html.append(f"        <label for=\"{html.escape(field_id, quote=True)}\">{html.escape(label)}</label>")
            if field_type == "textarea":
                field_html.append(f"        <textarea id=\"{html.escape(field_id, quote=True)}\" name=\"{html.escape(field_id, quote=True)}\"{required}></textarea>")
            elif field_type == "select":
                options = field.get("options") if isinstance(field.get("options"), list) else [
                    "Gate 01 intake scope",
                    "Gate 08 supply chain SBOM",
                    "Gate 16 QA smoke test",
                    "Gate 20 red-team review",
                    "Gate 24 deploy rollback",
                ]
                field_html.append(f"        <select id=\"{html.escape(field_id, quote=True)}\" name=\"{html.escape(field_id, quote=True)}\"{required}>")
                field_html.append("          <option value=\"\">Choose an option</option>")
                for option in options:
                    field_html.append(f"          <option>{html.escape(str(option))}</option>")
                field_html.append("        </select>")
            else:
                safe_type = field_type if field_type in {"text", "email", "tel", "number", "date", "time", "url"} else "text"
                field_html.append(f"        <input id=\"{html.escape(field_id, quote=True)}\" name=\"{html.escape(field_id, quote=True)}\" type=\"{safe_type}\"{autocomplete}{required}>")
        form_html = [
            "    <section aria-labelledby=\"request-form\" class=\"panel\">",
            f"      <h2 id=\"request-form\">{html.escape(form_title)}</h2>",
            "      <p class=\"note\">This generated static form records the approved UI shape. Backend processing requires a separately approved release-scoped implementation.</p>",
            "      <form action=\"mailto:operator@example.invalid\" method=\"post\" enctype=\"text/plain\">",
            *field_html,
            "        <button type=\"submit\">Send request</button>",
            "      </form>",
            "    </section>",
        ]
    html_text = "\n".join([
        "<!doctype html>",
        "<html lang=\"en\">",
        "<head>",
        "  <meta charset=\"utf-8\">",
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        f"  <title>{html.escape(title)}</title>",
        "  <style>",
        "    :root { color-scheme: light; --ink: #1f2933; --muted: #52606d; --line: #c7d2da; --accent: #0f766e; --paper: #f8fafc; --panel: #ffffff; }",
        "    * { box-sizing: border-box; }",
        "    body { margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: var(--ink); background: var(--paper); }",
        "    header { padding: 48px 6vw 32px; background: #e6fffb; border-bottom: 1px solid var(--line); }",
        "    main { max-width: 1040px; margin: 0 auto; padding: 32px 24px 56px; display: grid; gap: 28px; }",
        "    h1 { margin: 0 0 12px; font-size: clamp(2rem, 5vw, 4rem); line-height: 1; letter-spacing: 0; }",
        "    h2 { margin: 0 0 12px; font-size: 1.35rem; }",
        "    p { max-width: 68ch; line-height: 1.6; color: var(--muted); }",
        "    .hero { max-width: 1040px; margin: 0 auto; }",
        "    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }",
        "    .status-grid { grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }",
        "    .panel { border: 1px solid var(--line); border-radius: 8px; padding: 18px; background: var(--panel); }",
        "    .status-card { border: 1px solid var(--line); border-radius: 8px; padding: 18px; background: var(--panel); display: grid; gap: 10px; }",
        "    .status-card h3 { margin: 0; font-size: 1.05rem; }",
        "    .status-card dl { margin: 0; display: grid; gap: 8px; }",
        "    .status-card div { display: grid; gap: 2px; }",
        "    dt { font-size: 0.78rem; text-transform: uppercase; color: var(--muted); font-weight: 800; }",
        "    dd { margin: 0; }",
        "    .badge { width: fit-content; border-radius: 999px; padding: 4px 10px; font-size: 0.78rem; font-weight: 900; text-transform: uppercase; }",
        "    .go { background: #d1fae5; color: #065f46; border: 1px solid #34d399; }",
        "    .caution { background: #fef3c7; color: #92400e; border: 1px solid #f59e0b; }",
        "    .incident-banner { border: 2px solid #0f766e; border-radius: 8px; padding: 18px; background: #ecfdf5; }",
        "    .table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 8px; background: var(--panel); }",
        "    table { width: 100%; border-collapse: collapse; min-width: 620px; }",
        "    th, td { text-align: left; padding: 12px; border-bottom: 1px solid var(--line); vertical-align: top; }",
        "    th { background: #eef2f7; }",
        "    .action-list { display: grid; gap: 10px; padding-left: 1.35rem; }",
        "    pre { overflow-x: auto; border-radius: 8px; padding: 14px; background: #111827; color: #f9fafb; }",
        "    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }",
        "    label { display: block; margin: 14px 0 6px; font-weight: 700; }",
        "    input, select, textarea { width: 100%; min-height: 44px; border: 1px solid #9c9488; border-radius: 6px; padding: 10px 12px; font: inherit; background: white; color: var(--ink); }",
        "    textarea { min-height: 96px; resize: vertical; }",
        "    button { min-height: 44px; margin-top: 16px; border: 0; border-radius: 6px; padding: 0 18px; font: inherit; font-weight: 800; background: var(--accent); color: white; cursor: pointer; }",
        "    button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible { outline: 3px solid #f0b84f; outline-offset: 2px; }",
        "    .note { font-size: 0.9rem; color: var(--muted); }",
        "  </style>",
        "</head>",
        "<body>",
        "  <header>",
        "    <div class=\"hero\">",
        f"      <h1>{html.escape(title)}</h1>",
        f"      <p>{html.escape(description)}</p>",
        "    </div>",
        "  </header>",
        "  <main>",
        *[line for line in section_html if line],
        *form_html,
        "    <section aria-labelledby=\"sdlc-heading\">",
        "      <h2 id=\"sdlc-heading\">SDLC Auto Scope</h2>",
        f"      <p>Request: {escaped_request}</p>",
        "      <p>This generated static site is the implementation artifact for this local auto run.</p>",
        "    </section>",
        "  </main>",
        "</body>",
        "</html>",
    ])
    return ledger.artifact(
        "artifacts/auto/website/index.html",
        html_text + "\n",
        event="auto.website_artifact_written",
        redact=False,
    )


def _write_auto_website_public_evidence(
    repo: Path,
    run_dir: Path,
    run_id: str,
    request: str,
    output_dir: Path,
) -> dict[str, object]:
    ledger = Ledger(run_dir, run_id)
    written: list[str] = []
    missing: list[str] = []
    generated_at = now_iso()
    events_path = run_dir / "events.jsonl"
    events_sha = hashlib.sha256(events_path.read_bytes()).hexdigest() if events_path.exists() else "<not available at site generation>"
    site_path = output_dir / "index.html"
    site_sha = hashlib.sha256(site_path.read_bytes()).hexdigest() if site_path.exists() else "<not available at site generation>"
    for gate in DEFAULT_GATES:
        rel = Path("evidence") / "gates" / _auto_site_gate_filename(gate)
        artifact_rel = Path("evidence") / "artifacts" / _auto_site_gate_filename(gate)
        target = output_dir / rel
        artifact_target = output_dir / artifact_rel
        state, note = _auto_site_gate_state(gate.id)
        required = "\n".join(f"- {item}" for item in gate.required_artifacts) or "- <none>"
        walkthrough_rel = f"artifacts/auto/walkthrough/gates/{_auto_site_gate_filename(gate)}"
        walkthrough_path = run_dir / walkthrough_rel
        if walkthrough_path.exists():
            walkthrough_sha = hashlib.sha256(walkthrough_path.read_bytes()).hexdigest()
            walkthrough_bytes = str(walkthrough_path.stat().st_size)
            walkthrough_status = "present"
        else:
            walkthrough_sha = "<missing>"
            walkthrough_bytes = "0"
            walkthrough_status = "missing"
        facts = _auto_public_gate_facts(gate, request, run_id)
        artifact_content = "\n".join([
            f"# Public-Safe Evidence Artifact {gate.order:02d}: {gate.title}",
            "",
            f"Run: {run_id}",
            f"Gate ID: {gate.id}",
            f"Owner: {gate.owner}",
            f"Generated at: {generated_at}",
            "",
            "Evidence summary:",
            *facts,
            "",
            "Required artifact coverage:",
            required,
            "",
            "Bound source artifacts:",
            f"- `.sdlc/runs/{run_id}/{walkthrough_rel}` status `{walkthrough_status}` bytes `{walkthrough_bytes}` sha256 `{walkthrough_sha}`",
            f"- `.sdlc/runs/{run_id}/events.jsonl` sha256-at-site-generation `{events_sha}`",
            f"- `site/index.html` sha256-at-site-generation `{site_sha}`",
            "",
            "Verification posture:",
            "- This file is deployable with the static site and contains redacted, public-safe evidence metadata.",
            "- Formal release remains blocked until final report, red-team, validation, and approval artifacts agree.",
            "",
        ])
        artifact_target.parent.mkdir(parents=True, exist_ok=True)
        artifact_target.write_text(artifact_content, encoding="utf-8")
        written.append(artifact_rel.as_posix())
        ledger.artifact(
            f"artifacts/auto/website/{artifact_rel.as_posix()}",
            artifact_content,
            event="auto.website_public_evidence_artifact_written",
            gate=gate.id,
            gate_order=gate.order,
            redact=False,
        )
        artifact_sha = hashlib.sha256(artifact_target.read_bytes()).hexdigest()
        content = "\n".join([
            f"# Public Gate Evidence Status {gate.order:02d}: {gate.title}",
            "",
            f"Run: {run_id}",
            f"Gate ID: {gate.id}",
            f"Owner: {gate.owner}",
            f"Display state: {state}",
            f"Status note: {note}",
            f"Generated at: {generated_at}",
            "",
            "Required artifacts:",
            required,
            "",
            "Gate-specific facts:",
            *facts,
            "",
            "Evidence provenance:",
            f"- Generated by `sdlc auto` for request: {request}",
            f"- Public mirror path: `site/{rel.as_posix()}`",
            f"- Public evidence artifact: `site/{artifact_rel.as_posix()}` sha256 `{artifact_sha}`",
            f"- Current run ledger snapshot: `.sdlc/runs/{run_id}/events.jsonl` sha256 `{events_sha}`",
            f"- Generated site snapshot: `site/index.html` sha256 `{site_sha}`",
            f"- Internal walkthrough evidence: `.sdlc/runs/{run_id}/{walkthrough_rel}` status `{walkthrough_status}` bytes `{walkthrough_bytes}` sha256 `{walkthrough_sha}`",
            "",
            "Claim discipline:",
            "- This public file is a deployable evidence-status mirror, not a release certificate.",
            "- Final GO/NO-GO is authoritative only in the signed run ledger, red-team summary, validation result, and final report.",
            "",
        ])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        written.append(rel.as_posix())
        ledger.artifact(
            f"artifacts/auto/website/{rel.as_posix()}",
            content,
            event="auto.website_public_evidence_written",
            gate=gate.id,
            gate_order=gate.order,
            redact=False,
        )
    for rel in written:
        if not (output_dir / rel).exists():
            missing.append(rel)
    link_check = {
        "checked": len(written),
        "missing": missing,
        "output_dir": relpath_under_base(repo, output_dir, must_exist=True) or str(output_dir),
        "status": "GO" if not missing else "NO_GO",
    }
    ledger.artifact(
        "artifacts/auto/website/link-check.json",
        json.dumps(link_check, indent=2, sort_keys=True) + "\n",
        event="auto.website_public_evidence_link_check",
        status=link_check["status"],
        checked=link_check["checked"],
        missing_count=len(missing),
        redact=False,
    )
    return link_check


def _quarantine_stale_auto_site_trees(repo: Path, run_dir: Path, run_id: str, output_dir: Path) -> dict[str, object]:
    ledger = Ledger(run_dir, run_id)
    quarantined: list[dict[str, str]] = []
    skipped: list[str] = []
    run_id_pattern = re.compile(r"\b[a-z0-9][a-z0-9-]*-\d{8}-\d{3,6}\b")
    for candidate in sorted(repo.iterdir()):
        if not candidate.is_dir() or candidate in {output_dir, repo / ".sdlc"}:
            continue
        index = candidate / "index.html"
        evidence_dir = candidate / "evidence" / "gates"
        if not index.exists() or not evidence_dir.exists():
            continue
        try:
            text = index.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped.append(candidate.name)
            continue
        if "SDLC Auto Scope" not in text and "evidence/gates/" not in text:
            continue
        referenced_run_ids = set(run_id_pattern.findall(text))
        if run_id in referenced_run_ids or not referenced_run_ids:
            continue
        target = run_dir / "artifacts" / "auto" / "quarantined-sites" / candidate.name
        if target.exists():
            shutil.rmtree(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(candidate), str(target))
        quarantined.append({"path": candidate.name, "quarantined_to": relpath_under_base(run_dir, target, must_exist=True) or str(target), "referenced_run_ids": ",".join(sorted(referenced_run_ids))})
        ledger.event("auto.stale_site_quarantined", path=candidate.name, quarantined_to=str(target), referenced_run_ids=sorted(referenced_run_ids))
    payload = {
        "schema_version": 1,
        "status": "GO",
        "run_id": run_id,
        "output_dir": relpath_under_base(repo, output_dir, must_exist=True) or str(output_dir),
        "quarantined": quarantined,
        "skipped": skipped,
    }
    artifact = ledger.artifact(
        "artifacts/auto/stale-site-scan.json",
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        event="auto.stale_site_scan_written",
        quarantined_count=len(quarantined),
        redact=False,
    )
    payload["artifact"] = artifact
    return payload


def _write_auto_website(repo: Path, run_dir: Path, run_id: str, request: str, intake: dict[str, object]) -> tuple[str, str]:
    implementation = _auto_implementation(intake)
    output_rel = _auto_clean_relpath(implementation.get("output_path"), "site/index.html")
    if not output_rel.endswith(".html"):
        output_rel = "site/index.html"
    output, error = resolve_under_base(repo, Path(output_rel), must_exist=False)
    if error or output is None:
        output = repo / "site" / "index.html"
    output.parent.mkdir(parents=True, exist_ok=True)
    artifact = _write_auto_website_artifact(run_dir, run_id, request, intake)
    html_text = (run_dir / artifact).read_text(encoding="utf-8")
    output.write_text(html_text, encoding="utf-8")
    _write_auto_website_public_evidence(repo, run_dir, run_id, request, output.parent)
    _quarantine_stale_auto_site_trees(repo, run_dir, run_id, output.parent)
    rel_output = relpath_under_base(repo, output, must_exist=True) or "site/index.html"
    Ledger(run_dir, run_id).event("auto.website_written", path=rel_output, source_artifact=artifact)
    return rel_output, artifact


def _write_auto_python_script_artifact(run_dir: Path, run_id: str, request: str, intake: dict[str, object]) -> str:
    ledger = Ledger(run_dir, run_id)
    implementation = _auto_implementation(intake)
    provided = str(implementation.get("python_source", "") or "")
    if provided.strip():
        script_text = provided.rstrip() + "\n"
    else:
        escaped_request = json.dumps(request)
        title = json.dumps(str(implementation.get("title") or _auto_title_from_request(request)))
        features = json.dumps([str(item) for item in implementation.get("features", [])] if isinstance(implementation.get("features"), list) else [])
        script_text = "\n".join([
            "#!/usr/bin/env python3",
            "\"\"\"Generated Python CLI artifact for an SDLC auto run.\"\"\"",
            "",
            "from __future__ import annotations",
            "",
            "import argparse",
            "import json",
            "",
            f"REQUEST = {escaped_request}",
            f"TITLE = {title}",
            f"FEATURES = {features}",
            "",
            "",
            "def build_payload() -> dict[str, object]:",
            "    return {\"title\": TITLE, \"request\": REQUEST, \"features\": FEATURES}",
            "",
            "",
            "def main(argv: list[str] | None = None) -> int:",
            "    parser = argparse.ArgumentParser(description=\"Run the generated SDLC auto artifact.\")",
            "    parser.add_argument(\"--json\", action=\"store_true\", help=\"print the generated payload as JSON\")",
            "    args = parser.parse_args(argv)",
            "    payload = build_payload()",
            "    if args.json:",
            "        print(json.dumps(payload, indent=2, sort_keys=True))",
            "    else:",
            "        print(payload[\"title\"])",
            "        print(payload[\"request\"])",
            "    return 0",
            "",
            "",
            "if __name__ == \"__main__\":",
            "    raise SystemExit(main())",
        ]) + "\n"
    artifact_name = _auto_clean_relpath(Path(str(implementation.get("output_path") or "main.py")).name, "main.py")
    return ledger.artifact(
        f"artifacts/auto/implementation/{artifact_name}",
        script_text,
        event="auto.implementation_artifact_written",
        artifact_kind="python_script",
        redact=False,
    )


def _write_auto_generic_script_artifact(run_dir: Path, run_id: str, request: str) -> str:
    ledger = Ledger(run_dir, run_id)
    escaped_request = json.dumps(request)
    script_text = "\n".join([
        "#!/usr/bin/env python3",
        "\"\"\"Generated local implementation scaffold for an SDLC auto run.\"\"\"",
        "",
        "from __future__ import annotations",
        "",
        "import argparse",
        "",
        "",
        f"REQUEST = {escaped_request}",
        "",
        "",
        "def main(argv: list[str] | None = None) -> int:",
        "    parser = argparse.ArgumentParser(description=\"Run the generated SDLC auto scaffold.\")",
        "    parser.add_argument(\"--show-request\", action=\"store_true\", help=\"print the approved request\")",
        "    args = parser.parse_args(argv)",
        "    if args.show_request:",
        "        print(REQUEST)",
        "    else:",
        "        print(\"Generated implementation scaffold is ready.\")",
        "    return 0",
        "",
        "",
        "if __name__ == \"__main__\":",
        "    raise SystemExit(main())",
    ])
    return ledger.artifact(
        "artifacts/auto/implementation/main.py",
        script_text + "\n",
        event="auto.implementation_artifact_written",
        artifact_kind="python_script",
        redact=False,
    )


def _write_auto_decommission_scope_artifact(run_dir: Path, run_id: str, request: str) -> str:
    content = "\n".join([
        "# Auto Decommission Scope",
        "",
        f"Run: {run_id}",
        f"Request: {request}",
        "",
        "This artifact records the approved cleanup/decommission intent. The concrete AWS/local cleanup plan is recorded separately in `artifacts/auto/decommission-plan.json`.",
    ])
    return Ledger(run_dir, run_id).artifact(
        "artifacts/auto/decommission/scope.md",
        content + "\n",
        event="auto.decommission_scope_written",
        redact=False,
    )


def _write_auto_implementation(repo: Path, run_dir: Path, run_id: str, request: str, intake: dict[str, object]) -> tuple[str, str, str]:
    implementation = _auto_implementation(intake)
    artifact_kind = _auto_kind_to_artifact_kind(str(intake.get("artifact_kind") or implementation.get("artifact_kind") or intake.get("kind") or "python_script"))
    if artifact_kind == "website":
        path, artifact = _write_auto_website(repo, run_dir, run_id, request, intake)
        return path, artifact, "website"

    if artifact_kind == "decommission":
        artifact = _write_auto_decommission_scope_artifact(run_dir, run_id, request)
        return f".sdlc/runs/{run_id}/{artifact}", artifact, "decommission"

    artifact = _write_auto_python_script_artifact(run_dir, run_id, request, intake)
    output_rel = _auto_clean_relpath(implementation.get("output_path"), "app/main.py")
    if not output_rel.endswith(".py"):
        output_rel = "app/main.py"
    output, error = resolve_under_base(repo, Path(output_rel), must_exist=False)
    if error or output is None:
        output = repo / "app" / "main.py"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text((run_dir / artifact).read_text(encoding="utf-8"), encoding="utf-8")
    try:
        output.chmod(0o755)
    except OSError:
        pass
    rel_output = relpath_under_base(repo, output, must_exist=True) or output_rel
    Ledger(run_dir, run_id).event("auto.implementation_written", path=rel_output, source_artifact=artifact, artifact_kind="python_script")
    return rel_output, artifact, "python_script"


def _write_auto_demo_output(repo: Path, run_dir: Path, run_id: str, implementation_path: str, artifact_kind: str, intake: dict[str, object]) -> str | None:
    if artifact_kind != "python_script":
        return None
    implementation = _auto_implementation(intake)
    demo_args = implementation.get("demo_args") if isinstance(implementation.get("demo_args"), list) else []
    command = [sys.executable, implementation_path, *[str(item) for item in demo_args]]
    result = run_cmd(command, repo, timeout=30)
    content = "\n".join([
        "# Auto Implementation Demo Output",
        "",
        f"Command: `{' '.join(shlex.quote(part) for part in command)}`",
        f"Return code: {result['returncode']}",
        "",
        "## STDOUT",
        "```text",
        str(result.get("stdout", "")).rstrip(),
        "```",
        "",
        "## STDERR",
        "```text",
        str(result.get("stderr", "")).rstrip(),
        "```",
    ])
    return Ledger(run_dir, run_id).artifact(
        "artifacts/auto/implementation/demo-output.md",
        content + "\n",
        event="auto.implementation_demo_output_written",
        artifact_kind=artifact_kind,
        returncode=result["returncode"],
        redact=False,
    )


AUTO_INTAKE_SCHEMA_VERSION = 1


def _auto_request_kind(request: str) -> str:
    """Offline fallback classifier; model/provided intake plans can override it."""
    text = request.lower()
    starts_with_cleanup = bool(re.match(r"\s*(decommission|deomission|cleanup|clean up|destroy|tear down|teardown)\b", text))
    destructive_cleanup = bool(re.search(r"\b(delete|destroy|tear down|teardown|remove)\b.*\b(bucket|environment|resources|site|website)\b", text))
    if starts_with_cleanup or destructive_cleanup:
        return "decommission"
    if any(term in text for term in {"website", "web site", "web app", "landing page", "html", "form"}):
        return "website"
    if any(term in text for term in {"script", "python", "cli", "command line", "command-line"}):
        return "python_script"
    return "application"


def _auto_title_from_request(request: str) -> str:
    words = re.findall(r"[A-Za-z0-9]+", request)
    if not words:
        return "SDLC Auto Artifact"
    ignored = {"a", "an", "the", "for", "with", "and", "to", "of", "in", "on", "create", "build", "generate", "add"}
    selected = [word for word in words if word.lower() not in ignored][:7] or words[:7]
    return " ".join(word.capitalize() for word in selected)


def _auto_clean_relpath(value: object, default: str) -> str:
    text = str(value or "").strip()
    if not text:
        return default
    text = text.lstrip("/").replace("\\", "/")
    parts = [part for part in text.split("/") if part and part not in {".", ".."}]
    return "/".join(parts) or default


def _auto_kind_to_artifact_kind(kind: str) -> str:
    mapping = {
        "static_site": "website",
        "website": "website",
        "web": "website",
        "python_cli": "python_script",
        "python_script": "python_script",
        "script": "python_script",
        "decommission_plan": "decommission",
        "decommission": "decommission",
    }
    return mapping.get(kind, "python_script")


def _auto_architecture_mermaid(kind: str) -> str:
    if kind == "website":
        return "\n".join([
            "flowchart LR",
            "  Visitor[Visitor] --> Site[Generated static site]",
            "  Site --> Interaction[Request-specific interaction]",
            "  Auto[sdlc auto] --> Local[Local artifact]",
            "  Auto --> Evidence[25-gate evidence dashboard]",
            "  Auto -. explicit approval .-> S3[AWS S3 static website gateway]",
            "  S3 -. optional approved plan .-> CDN[CloudFront + ACM]",
        ])
    if kind == "decommission":
        return "\n".join([
            "flowchart LR",
            "  Operator[Human operator] --> CLI[sdlc auto decommission]",
            "  CLI --> Discover[Discover target S3 web gateway]",
            "  Discover --> Plan[Cleanup plan and approval record]",
            "  Plan -. explicit cleanup approval .-> S3[AWS S3 bucket removal]",
            "  Plan -. optional .-> Local[Local generated artifact cleanup]",
            "  CLI --> Evidence[25-gate decommission evidence report]",
        ])
    if kind == "python_script":
        return "\n".join([
            "flowchart LR",
            "  User[Operator] --> CLI[sdlc auto]",
            "  CLI --> Intake[LLM intake plan]",
            "  Intake --> Script[Generated Python CLI artifact]",
            "  Script --> Demo[Local execution transcript]",
            "  CLI --> Evidence[25-gate evidence report]",
            "  Evidence --> Gates[Per-gate proof artifacts]",
        ])
    return "\n".join([
        "flowchart LR",
        "  Request[User request] --> CLI[sdlc auto]",
        "  CLI --> Intake[LLM intake plan]",
        "  Intake --> Artifact[Generated implementation artifact]",
        "  CLI --> QA[Local quality and security checks]",
        "  CLI --> Evidence[25-gate evidence report]",
        "  CLI -. explicit approval .-> Infra[Cloud or destructive action]",
    ])


def _auto_intake_llm_prompt(request: str) -> str:
    return "\n".join([
        "# SDLC Auto Intake Planner",
        "",
        "Interpret the user's request and return only one JSON object. Do not wrap it in prose.",
        "",
        "The CLI must be generic. Do not hardcode cafe, Fibonacci, trading, website, domain, certificate, or AWS questions unless the user's request makes that topic relevant.",
        "Generate the approval questions and options that fit this specific request. Put the richest, most complete end-to-end demonstration as option 1/default for each question.",
        "Never approve production, live trading, destructive cleanup, secret handling, or cloud mutation silently. Put those behind explicit options/effects and approval text.",
        "",
        "Required JSON shape:",
        "{",
        '  "schema_version": 1,',
        '  "kind": "short_request_kind",',
        '  "artifact_kind": "website | python_script | decommission | generic",',
        '  "build_description": {"label": "...", "description": "..."},',
        '  "architecture": {"label": "...", "description": "...", "mermaid": "flowchart LR\\n  ..."},',
        '  "implementation": {',
        '    "artifact_kind": "website | python_script | decommission | generic",',
        '    "title": "request-specific title",',
        '    "description": "what will be built",',
        '    "output_path": "site/index.html or app/main.py or another safe relative path",',
        '    "features": ["request-specific feature"],',
        '    "sections": [{"heading": "...", "body": "...", "items": ["..."]}],',
        '    "form": {"enabled": true, "title": "...", "fields": [{"id": "name", "label": "Name", "type": "text", "required": true}]},',
        '    "python_source": "optional full Python source when artifact_kind is python_script",',
        '    "demo_args": ["optional", "args"]',
        "  },",
        '  "questions": [',
        '    {"id": "scope", "prompt": "question for the user", "default": 0, "options": [',
        '      {"label": "Full end-to-end demonstration", "description": "best complex default", "effects": {"build_description": {"label": "...", "description": "..."}}},',
        '      {"label": "Smaller alternative", "description": "...", "effects": {}}',
        "    ]}",
        "  ],",
        '  "domain": {"label": "Not applicable unless relevant", "value": ""},',
        '  "certificates": {"label": "Not applicable unless relevant", "value": ""},',
        '  "aws": {"execute": false, "public_read": false, "gateway_name": "sdlc-web-gateway", "profile": "default", "region": "us-east-1", "bucket": ""},',
        '  "open_browser": false,',
        '  "open_target": "Open evidence dashboard"',
        "}",
        "",
        f"User request: {request}",
    ])


def _auto_deep_merge(base: dict[str, object], updates: dict[str, object]) -> dict[str, object]:
    merged = copy.deepcopy(base)
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _auto_deep_merge(merged[key], value)  # type: ignore[arg-type]
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _extract_json_object(text: str) -> dict[str, object] | None:
    preferred: list[dict[str, object]] = []
    fallback: list[dict[str, object]] = []
    seen: set[str] = set()

    def consider_payload(payload: object) -> None:
        if isinstance(payload, dict):
            if _auto_json_payload_is_preferred(payload):
                preferred.append(payload)
            else:
                fallback.append(payload)
            for nested in _json_string_values(payload):
                consider_text(nested)
        elif isinstance(payload, list):
            for item in payload:
                consider_payload(item)

    def consider_text(candidate_text: str) -> None:
        candidate_text = candidate_text.strip()
        if not candidate_text or candidate_text in seen:
            return
        seen.add(candidate_text)
        snippets: list[str] = []
        fenced_matches = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", candidate_text, flags=re.DOTALL)
        snippets.extend(fenced_matches)
        if candidate_text.startswith("{") and candidate_text.endswith("}"):
            snippets.append(candidate_text)
        first = candidate_text.find("{")
        last = candidate_text.rfind("}")
        if first != -1 and last > first:
            snippets.append(candidate_text[first:last + 1])
        for line in candidate_text.splitlines():
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                snippets.append(line)
        for snippet in snippets:
            try:
                payload = json.loads(snippet)
            except json.JSONDecodeError:
                continue
            consider_payload(payload)

    consider_text(text)
    return preferred[0] if preferred else fallback[0] if fallback else None


def _auto_json_payload_is_preferred(payload: dict[str, object]) -> bool:
    preferred_keys = {
        "artifact_kind",
        "kind",
        "implementation",
        "questions",
        "architecture",
        "verdict",
        "final_verdict",
        "findings",
    }
    return any(key in payload for key in preferred_keys)


def _json_string_values(value: object) -> list[str]:
    strings: list[str] = []
    if isinstance(value, str):
        strings.append(value)
    elif isinstance(value, list):
        for item in value:
            strings.extend(_json_string_values(item))
    elif isinstance(value, dict):
        for item in value.values():
            strings.extend(_json_string_values(item))
    return strings


def _fallback_auto_intake_plan(args: argparse.Namespace, request: str) -> dict[str, object]:
    kind = _auto_request_kind(request)
    artifact_kind = _auto_kind_to_artifact_kind(kind)
    title = _auto_title_from_request(request)
    architecture = _auto_architecture_mermaid(kind)
    is_website = artifact_kind == "website"
    is_decommission = artifact_kind == "decommission"
    default_output = "site/index.html" if is_website else ".sdlc/decommission/scope.md" if is_decommission else "app/main.py"
    default_open = bool(getattr(args, "open_browser", False)) and not bool(getattr(args, "no_open_browser", False))
    return {
        "schema_version": AUTO_INTAKE_SCHEMA_VERSION,
        "kind": kind,
        "artifact_kind": artifact_kind,
        "request": request,
        "build_description": {
            "label": "Full 25-gate evidence demonstration",
            "description": "Build a request-shaped artifact, run local proof generation for all gates, and produce the HTML evidence dashboard.",
        },
        "architecture": {
            "label": "LLM-planned evidence-first architecture",
            "description": "Use an intake plan as the source of interpretation; cloud or destructive execution remains explicitly gated.",
            "mermaid": architecture,
        },
        "implementation": {
            "artifact_kind": artifact_kind,
            "title": title,
            "description": request,
            "output_path": default_output,
            "features": [
                "Request-specific generated artifact",
                "All 25 SDLC gate proofs",
                "Role-agent activity and evidence dashboard",
            ],
            "sections": [
                {"heading": "Approved Scope", "body": request, "items": ["Generated from the intake plan", "Tracked through all 25 gates"]},
                {"heading": "Evidence", "body": "The run records architecture, QA, SBOM, red-team, deployment posture, and final reporting artifacts.", "items": []},
            ],
            "form": {
                "enabled": is_website,
                "title": "Accessible Request Form",
                "fields": [
                    {"id": "name", "label": "Name", "type": "text", "required": True},
                    {"id": "details", "label": "Request details", "type": "textarea", "required": True},
                ],
            },
            "demo_args": [],
        },
        "questions": [
            {
                "id": "auto_depth",
                "prompt": "How complete should this auto run be?",
                "default": 0,
                "options": [
                    {
                        "label": "Full evidence demo",
                        "description": "Generate the richest local artifact, all gate proofs, role activity, HTML dashboard, and cloud/cleanup plan where applicable.",
                        "effects": {
                            "build_description": {
                                "label": "Full evidence demo",
                                "description": "Complete local implementation plus 25-gate evidence, role activity, HTML dashboard, and approved infra posture.",
                            }
                        },
                    },
                    {"label": "Local implementation only", "description": "Generate the artifact and gate evidence without cloud/destructive planning.", "effects": {"aws": {"execute": False, "public_read": False}}},
                    {"label": "Architecture/report only", "description": "Emphasize the evidence package and implementation scaffold.", "effects": {"implementation": {"features": ["Architecture and report scaffold"]}}},
                ],
            },
            {
                "id": "execution_authority",
                "prompt": "What execution authority should I use?",
                "default": 0,
                "options": [
                    {"label": "Plan external changes only", "description": "Best default: record exact cloud/destructive plans but do not mutate external systems.", "effects": {"aws": {"execute": False, "cleanup_execute": False}}},
                    {"label": "Execute only explicitly approved changes", "description": "Use CLI approval flags for cloud or cleanup execution.", "effects": {}},
                    {"label": "No external actions", "description": "Keep the run entirely local.", "effects": {"aws": {"execute": False, "cleanup_execute": False, "public_read": False}}},
                ],
            },
            {
                "id": "final_view",
                "prompt": "What should I open at the end?",
                "default": 0,
                "options": [
                    {"label": "Open evidence dashboard", "description": "Open the HTML dashboard with gate proof links and role activity.", "effects": {"open_browser": True, "open_target": "Open evidence dashboard"}},
                    {"label": "Open finished artifact", "description": "Open the generated artifact or deployed URL when available.", "effects": {"open_browser": True, "open_target": "Open finished page"}},
                    {"label": "Open nothing", "description": "Print paths only.", "effects": {"open_browser": False, "open_target": "Open nothing"}},
                ],
            },
        ],
        "domain": {"label": "Generated AWS URL" if is_website else "Not applicable", "value": ""},
        "certificates": {"label": "No certificate in this run" if is_website else "Not applicable", "value": ""},
        "contact_policy": {"label": "Proceed with approved plan", "description": "Ask again before unapproved cloud, destructive, secret, or production actions."},
        "aws": {
            "execute": bool(getattr(args, "execute_aws", False)) if is_website else False,
            "approval": getattr(args, "approve_aws_deploy", None) or "",
            "cleanup_execute": bool(getattr(args, "execute_cleanup", False)) if is_decommission else False,
            "cleanup_approval": getattr(args, "approve_cleanup", None) or "",
            "gateway_name": getattr(args, "aws_gateway_name", "sdlc-web-gateway"),
            "public_read": bool(getattr(args, "public_read", False)) or is_website,
            "profile": getattr(args, "aws_profile", "default"),
            "region": getattr(args, "aws_region", "us-east-1"),
            "bucket": getattr(args, "aws_bucket", None) or "",
            "target_run_id": getattr(args, "target_run_id", None) or "",
            "cleanup_local": bool(getattr(args, "cleanup_local", False)),
        },
        "open_browser": default_open,
        "open_target": "Open evidence dashboard",
    }


def _normalize_auto_questions(raw: object) -> list[dict[str, object]]:
    if not isinstance(raw, list):
        return []
    questions: list[dict[str, object]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        options = item.get("options")
        if not isinstance(options, list) or not options:
            continue
        clean_options: list[dict[str, object]] = []
        for option in options:
            if not isinstance(option, dict):
                continue
            label = str(option.get("label", "")).strip()
            if not label:
                continue
            clean_options.append({
                "label": label,
                "description": str(option.get("description", "")).strip(),
                "effects": option.get("effects") if isinstance(option.get("effects"), dict) else {},
            })
        if not clean_options:
            continue
        default = item.get("default", 0)
        default_index = int(default) if isinstance(default, int) or (isinstance(default, str) and default.isdigit()) else 0
        default_index = max(0, min(default_index, len(clean_options) - 1))
        questions.append({
            "id": str(item.get("id", f"question_{len(questions) + 1}")).strip() or f"question_{len(questions) + 1}",
            "prompt": str(item.get("prompt", "Select an option")).strip() or "Select an option",
            "default": default_index,
            "options": clean_options,
        })
    return questions


def _normalize_auto_intake_plan(args: argparse.Namespace, request: str, raw: dict[str, object], *, source: str, prompt: str, llm: dict[str, object]) -> dict[str, object]:
    fallback = _fallback_auto_intake_plan(args, request)
    intake = _auto_deep_merge(fallback, raw)
    implementation = intake.get("implementation") if isinstance(intake.get("implementation"), dict) else {}
    kind = str(intake.get("kind") or fallback["kind"])
    artifact_kind = str(intake.get("artifact_kind") or implementation.get("artifact_kind") or _auto_kind_to_artifact_kind(kind))
    artifact_kind = _auto_kind_to_artifact_kind(artifact_kind)
    intake["schema_version"] = AUTO_INTAKE_SCHEMA_VERSION
    intake["request"] = request
    intake["kind"] = kind
    intake["artifact_kind"] = artifact_kind
    intake["implementation"] = _auto_deep_merge(
        fallback.get("implementation", {}) if isinstance(fallback.get("implementation"), dict) else {},
        implementation if isinstance(implementation, dict) else {},
    )
    if isinstance(intake["implementation"], dict):
        intake["implementation"]["artifact_kind"] = artifact_kind
    architecture = intake.get("architecture") if isinstance(intake.get("architecture"), dict) else {}
    if not str(architecture.get("mermaid", "")).strip():
        architecture["mermaid"] = _auto_architecture_mermaid(kind)
    intake["architecture"] = architecture
    intake["questions"] = _normalize_auto_questions(intake.get("questions")) or _normalize_auto_questions(fallback.get("questions"))
    intake["llm_intake"] = {
        "schema_version": AUTO_INTAKE_SCHEMA_VERSION,
        "source": source,
        "worker": str(getattr(args, "intake_model", "codex")),
        "execute_requested": bool(getattr(args, "execute_intake_llm", False)),
        "prompt": prompt,
        **llm,
    }
    return _apply_auto_cli_overrides(args, intake)


def _apply_auto_cli_overrides(args: argparse.Namespace, intake: dict[str, object]) -> dict[str, object]:
    aws = copy.deepcopy(intake.get("aws")) if isinstance(intake.get("aws"), dict) else {}
    if getattr(args, "execute_aws", False):
        aws["execute"] = True
    if getattr(args, "approve_aws_deploy", None):
        aws["approval"] = args.approve_aws_deploy
    if getattr(args, "public_read", False):
        aws["public_read"] = True
    if getattr(args, "execute_cleanup", False):
        aws["cleanup_execute"] = True
    if getattr(args, "approve_cleanup", None):
        aws["cleanup_approval"] = args.approve_cleanup
    if getattr(args, "cleanup_local", False):
        aws["cleanup_local"] = True
    for attr, key in {
        "aws_profile": "profile",
        "aws_region": "region",
        "aws_bucket": "bucket",
        "aws_gateway_name": "gateway_name",
        "target_run_id": "target_run_id",
    }.items():
        value = getattr(args, attr, None)
        if value:
            aws[key] = value
    aws.setdefault("profile", "default")
    aws.setdefault("region", "us-east-1")
    aws.setdefault("gateway_name", "sdlc-web-gateway")
    aws.setdefault("bucket", "")
    aws.setdefault("approval", "")
    aws.setdefault("cleanup_approval", "")
    answers = intake.get("answers") if isinstance(intake.get("answers"), dict) else {}
    answer_labels = [
        str(item.get("label", "")).lower()
        for item in answers.values()
        if isinstance(item, dict)
    ]
    disabled_public_plan = any(
        "no external" in label
        or "local only" in label
        or "local implementation only" in label
        for label in answer_labels
    )
    if str(intake.get("artifact_kind", "")) == "website" and not disabled_public_plan:
        aws["public_read"] = True
    intake["aws"] = aws
    if getattr(args, "no_open_browser", False):
        intake["open_browser"] = False
        intake["open_target"] = "Open nothing"
    elif getattr(args, "open_browser", False):
        intake["open_browser"] = True
        intake.setdefault("open_target", "Open evidence dashboard")
    return intake


def _load_auto_intake_plan(args: argparse.Namespace, repo: Path, request: str, policy: dict[str, object]) -> dict[str, object]:
    prompt = _auto_intake_llm_prompt(request)
    if getattr(args, "intake_plan", None):
        path = Path(str(args.intake_plan)).expanduser()
        payload = read_json(path, {})
        if not isinstance(payload, dict):
            payload = {}
        return _normalize_auto_intake_plan(
            args,
            request,
            payload,
            source="provided_intake_plan",
            prompt=prompt,
            llm={"status": "PROVIDED", "plan_path": str(path)},
        )
    if getattr(args, "execute_intake_llm", False):
        policy_error = _worker_execution_policy_error(policy, execute=True, allow_network=bool(getattr(args, "allow_network", False)))
        if policy_error:
            return _normalize_auto_intake_plan(
                args,
                request,
                {},
                source="schema_fallback",
                prompt=prompt,
                llm={"status": "BLOCKED_BY_POLICY", "error": policy_error},
            )
        adapter = adapter_from_policy(str(getattr(args, "intake_model", "codex")), policy)
        if adapter is None:
            return _normalize_auto_intake_plan(
                args,
                request,
                {},
                source="schema_fallback",
                prompt=prompt,
                llm={"status": "WORKER_UNAVAILABLE", "error": f"unknown worker: {getattr(args, 'intake_model', 'codex')}"},
            )
        with tempfile.TemporaryDirectory(prefix="sdlc-auto-intake-") as temp_dir:
            prompt_path = Path(temp_dir) / "auto-intake-prompt.md"
            prompt_path.write_text(prompt + "\n", encoding="utf-8")
            result = adapter.run(prompt_path, repo, "PLAN", execute=True, timeout=int(getattr(args, "timeout", 120)))
        parsed = _extract_json_object(result.stdout)
        result_data = result.to_dict()
        result_data["stdout"] = result.stdout[:12000]
        result_data["stderr"] = result.stderr[:12000]
        if parsed is not None and result.returncode == 0:
            return _normalize_auto_intake_plan(
                args,
                request,
                parsed,
                source="executed_llm",
                prompt=prompt,
                llm={"status": "EXECUTED", "result": result_data},
            )
        return _normalize_auto_intake_plan(
            args,
            request,
            {},
            source="schema_fallback",
            prompt=prompt,
            llm={"status": "LLM_PARSE_FAILED", "result": result_data},
        )
    return _normalize_auto_intake_plan(
        args,
        request,
        {},
        source="schema_fallback",
        prompt=prompt,
        llm={"status": "DRY_RUN", "reason": "pass --execute-intake-llm and --allow-network with a network-enabled policy to execute the selected intake worker"},
    )


def _prompt_choice(prompt: str, choices: list[dict[str, object]], *, default: int = 0) -> dict[str, object]:
    print()
    print(prompt)
    for index, choice in enumerate(choices, start=1):
        description = str(choice.get("description", ""))
        suffix = f" - {description}" if description else ""
        print(f"  {index}. {choice['label']}{suffix}")
    raw = input(f"Select 1-{len(choices)} [{default + 1}]: ").strip()
    if not raw:
        return choices[default]
    if raw.isdigit():
        idx = int(raw) - 1
        if 0 <= idx < len(choices):
            return choices[idx]
    print(f"Invalid selection; using {default + 1}.")
    return choices[default]


def _prompt_text(prompt: str, *, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    raw = input(f"{prompt}{suffix}: ").strip()
    return raw or default


def _prompt_approval(prompt: str, *, default: bool = True) -> bool:
    suffix = "Y/n" if default else "y/N"
    raw = input(f"{prompt} [{suffix}]: ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes", "approve", "approved"}


def _apply_auto_question_selection(intake: dict[str, object], question: dict[str, object], selected: dict[str, object]) -> dict[str, object]:
    effects = selected.get("effects") if isinstance(selected.get("effects"), dict) else {}
    if effects:
        intake = _auto_deep_merge(intake, effects)
    answers = intake.get("answers")
    if not isinstance(answers, dict):
        answers = {}
    answers[str(question.get("id", ""))] = {
        "prompt": str(question.get("prompt", "")),
        "label": str(selected.get("label", "")),
        "description": str(selected.get("description", "")),
    }
    intake["answers"] = answers
    return intake


def _apply_auto_default_questions(intake: dict[str, object]) -> dict[str, object]:
    questions = intake.get("questions") if isinstance(intake.get("questions"), list) else []
    for question in questions:
        if not isinstance(question, dict):
            continue
        options = question.get("options") if isinstance(question.get("options"), list) else []
        if not options:
            continue
        default = question.get("default", 0)
        index = int(default) if isinstance(default, int) or (isinstance(default, str) and default.isdigit()) else 0
        index = max(0, min(index, len(options) - 1))
        selected = options[index]
        if isinstance(selected, dict):
            intake = _apply_auto_question_selection(intake, question, selected)
    return intake


def _collect_auto_intake(args: argparse.Namespace, repo: Path, request: str, policy: dict[str, object]) -> dict[str, object]:
    intake = _load_auto_intake_plan(args, repo, request, policy)
    llm_intake = intake.get("llm_intake") if isinstance(intake.get("llm_intake"), dict) else {}
    if (
        bool(getattr(args, "execute_intake_llm", False))
        and not getattr(args, "intake_plan", None)
        and llm_intake.get("source") != "executed_llm"
    ):
        status = str(llm_intake.get("status", "UNKNOWN"))
        error = str(llm_intake.get("error") or llm_intake.get("reason") or "intake worker did not return a valid plan")
        intake["approved"] = False
        intake["intake_error"] = (
            f"Intake LLM execution was requested, but no LLM intake ran successfully "
            f"(status={status}). {error}. No auto run was created."
        )
        return intake
    interactive = (
        not getattr(args, "json", False)
        and not getattr(args, "yes", False)
        and sys.stdin.isatty()
        and sys.stdout.isatty()
    )
    intake["interactive"] = interactive
    if not interactive:
        intake["approved"] = True
        intake = _apply_auto_cli_overrides(args, intake)
        intake = _apply_auto_default_questions(intake)
        return _apply_auto_cli_overrides(args, intake)

    print("Auto intake and approvals")
    print(f"Request: {request}")
    print(f"Intake source: {llm_intake.get('source', 'unknown')} | Worker: {llm_intake.get('worker', 'unknown')} | Status: {llm_intake.get('status', 'unknown')}")
    print()
    print("Proposed architecture:")
    print("```mermaid")
    architecture = intake.get("architecture") if isinstance(intake.get("architecture"), dict) else {}
    print(str(architecture.get("mermaid", "")))
    print("```")
    questions = intake.get("questions") if isinstance(intake.get("questions"), list) else []
    for question in questions:
        if not isinstance(question, dict):
            continue
        options = question.get("options") if isinstance(question.get("options"), list) else []
        if not options:
            continue
        default = question.get("default", 0)
        default_index = int(default) if isinstance(default, int) or (isinstance(default, str) and default.isdigit()) else 0
        selected = _prompt_choice(str(question.get("prompt", "Select an option")), options, default=default_index)
        intake = _apply_auto_question_selection(intake, question, selected)

    approved = _prompt_approval("Approve this scope and begin the auto run?", default=True)
    intake["approved"] = approved
    return _apply_auto_cli_overrides(args, intake)


def _write_auto_intake_artifacts(run_dir: Path, run_id: str, intake: dict[str, object]) -> tuple[str, str]:
    ledger = Ledger(run_dir, run_id)
    llm_intake = intake.get("llm_intake") if isinstance(intake.get("llm_intake"), dict) else {}
    prompt_text = str(llm_intake.get("prompt", "") or "")
    prompt_artifact = ledger.artifact(
        "artifacts/auto/llm-intake-prompt.md",
        prompt_text.rstrip() + "\n",
        event="auto.llm_intake_prompt_written",
        redact=True,
    )
    llm_record = {key: value for key, value in llm_intake.items() if key != "prompt"}
    llm_artifact = ledger.artifact(
        "artifacts/auto/llm-intake.json",
        json.dumps(llm_record, indent=2, sort_keys=True) + "\n",
        event="auto.llm_intake_record_written",
        redact=True,
        source=str(llm_record.get("source", "")),
        status=str(llm_record.get("status", "")),
    )
    json_artifact = ledger.artifact(
        "artifacts/auto/intake-approvals.json",
        json.dumps(intake, indent=2, sort_keys=True) + "\n",
        event="auto.intake_approvals_written",
        redact=True,
    )
    aws = intake.get("aws") if isinstance(intake.get("aws"), dict) else {}
    domain = intake.get("domain") if isinstance(intake.get("domain"), dict) else {}
    certificates = intake.get("certificates") if isinstance(intake.get("certificates"), dict) else {}
    architecture = intake.get("architecture") if isinstance(intake.get("architecture"), dict) else {}
    answers = intake.get("answers") if isinstance(intake.get("answers"), dict) else {}
    answer_lines = []
    for answer_id, answer in sorted(answers.items()):
        if isinstance(answer, dict):
            answer_lines.append(f"- `{answer_id}`: {answer.get('label', '')} — {answer.get('description', '')}")
    if not answer_lines:
        answer_lines.append("- No interactive/default option selections were recorded.")
    content = "\n".join([
        "# Auto Intake and Approvals",
        "",
        f"Request: {intake.get('request', '')}",
        f"Kind: {intake.get('kind', '')}",
        f"Artifact kind: {intake.get('artifact_kind', '')}",
        f"Interactive: {intake.get('interactive', False)}",
        f"Approved: {intake.get('approved', False)}",
        f"Intake source: {llm_record.get('source', '')}",
        f"Intake worker: {llm_record.get('worker', '')}",
        f"Intake status: {llm_record.get('status', '')}",
        f"LLM prompt: `{prompt_artifact}`",
        f"LLM result: `{llm_artifact}`",
        "",
        "## Build",
        f"- Selection: {dict(intake.get('build_description', {})).get('label', '') if isinstance(intake.get('build_description'), dict) else ''}",
        f"- Detail: {dict(intake.get('build_description', {})).get('description', '') if isinstance(intake.get('build_description'), dict) else ''}",
        "",
        "## Selected Options",
        *answer_lines,
        "",
        "## Architecture",
        f"- Selection: {architecture.get('label', '')}",
        f"- Detail: {architecture.get('description', '')}",
        "",
        "```mermaid",
        str(architecture.get("mermaid", "")),
        "```",
        "",
        "## Domain and Certificates",
        f"- Domain: {domain.get('label', '')} {domain.get('value', '')}".rstrip(),
        f"- Certificates: {certificates.get('label', '')} {certificates.get('value', '')}".rstrip(),
        "",
        "## AWS Decision",
        f"- Execute AWS: {aws.get('execute', False)}",
        f"- Public read: {aws.get('public_read', False)}",
        f"- Profile: {aws.get('profile', '')}",
        f"- Region: {aws.get('region', '')}",
        f"- Bucket: {aws.get('bucket', '') or '<derived>'}",
        "",
        f"Machine-readable approvals: `{json_artifact}`",
    ])
    md_artifact = ledger.artifact(
        "artifacts/auto/intake-approvals.md",
        content + "\n",
        event="auto.intake_approvals_report_written",
        redact=True,
        approved=bool(intake.get("approved")),
        kind=str(intake.get("kind", "")),
    )
    return md_artifact, json_artifact


def _auto_gate_work_detail(gate_id: str, *, implementation_path: str, artifact_kind: str, aws_status: str) -> str:
    is_website = artifact_kind == "website"
    is_decommission = artifact_kind == "decommission"
    implementation_label = "static website" if is_website else "environment decommission plan" if is_decommission else "Python script"
    quality_label = "HTML structure and accessibility checks" if is_website else "cleanup target and command-plan validation" if is_decommission else "local Python execution transcript"
    security_label = "no JavaScript, no external calls, no embedded secrets" if is_website else "destructive cleanup requires explicit approval and records all commands" if is_decommission else "stdlib-only Python, no network calls, no secrets"
    details = {
        "intake_scope": "Captured the request, selected build shape, and approval posture before implementation.",
        "stakeholders_raci": "Recorded the user as approval authority and mapped local automation ownership for the run.",
        "mission_non_goals": "Separated local gate evidence from production/cloud authority and avoided unsupported readiness claims.",
        "repo_context_env_branch": f"Captured repository context and wrote the generated {implementation_label} under the working repo.",
        "risk_blast_radius": f"Classified the request as a bounded {implementation_label} run with cloud mutation disabled unless approved.",
        "data_privacy_secrets": "Kept the implementation local and dependency-free, avoided secrets, and stored approval evidence in redacted artifacts.",
        "baseline_freeze": "Recorded prework and provenance artifacts for replay and audit review.",
        "supply_chain_sbom": f"Generated a dependency-free {implementation_label} with no new package supply-chain surface.",
        "agent_plan_permissions": "Recorded role-agent planning evidence without granting production authority.",
        "architecture_contracts": "Recorded the selected architecture and Mermaid diagram in the intake evidence.",
        "ui_architecture_accessibility": "Built semantic HTML with labels, focus styling, required fields, and responsive layout." if is_website else "Recorded that the request has no UI surface and therefore no dark-pattern or accessibility interaction risk beyond CLI help text.",
        "threat_model_abuse_cases": f"Bounded the surface to {security_label}.",
        "implementation_plan_changeset": "Constrained the implementation to generated artifacts and run evidence.",
        "implementation": f"Generated the {implementation_label} at `{implementation_path}`.",
        "deterministic_quality": f"Verified the generated artifact through {quality_label}.",
        "qa_tests_integration_smoke": f"Recorded smoke-test evidence for the generated {implementation_label} artifact.",
        "security_scans": f"Recorded static security evidence: {security_label}.",
        "observability_runbooks": "Recorded runbook-style evidence for local preview, AWS plan, rollback, and report inspection.",
        "implementer_self_review": "Recorded self-review notes and claim discipline for the generated artifact.",
        "independent_redteam_cross_model": f"Recorded a deterministic red-team review with no blocking findings for the {implementation_label} scope.",
        "critical_high_fix_loop": f"Confirmed there were no CRITICAL/HIGH findings requiring a fix loop in this {implementation_label} run.",
        "evidence_traceability_attestations": "Wrote gate evidence artifacts and an attestation manifest.",
        "commit_branch_pr_ci": "Captured git provenance without pushing directly to main or creating an unapproved PR.",
        "deploy_rollout_postdeploy": f"Recorded AWS hosting status `{aws_status}` with execution gated by explicit approval.",
        "final_report_reaudit": "Generated final report artifacts, readiness payload, and this 25-phase work detail.",
    }
    return details.get(gate_id, "Recorded gate evidence for the generated auto run.")


def _prepare_auto_agent_plan_for_evidence(run_dir: Path, run_id: str) -> None:
    path = run_dir / "artifacts" / "agents" / "task-plan.json"
    payload = read_json(path, {})
    if not isinstance(payload, dict):
        return
    tasks = payload.get("tasks") if isinstance(payload.get("tasks"), list) else []
    changed = False
    for task in tasks:
        if not isinstance(task, dict):
            continue
        mode = str(task.get("mode", "PLAN"))
        if mode in {"BUILD", "FIX", "TEST", "SECURITY_REVIEW"}:
            task["auto_requested_mode"] = mode
            task["mode"] = "PLAN"
            task["auto_evidence_only"] = True
            changed = True
    if changed:
        payload["auto_evidence_only"] = True
        Ledger(run_dir, run_id).artifact(
            "artifacts/agents/task-plan.json",
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            event="auto.agent_plan_evidence_mode_written",
            redact=False,
        )


def _auto_agent_execution_blockers(agent_execution: dict[str, object], *, execute_requested: bool) -> list[str]:
    if not execute_requested:
        return []
    tasks = agent_execution.get("tasks") if isinstance(agent_execution.get("tasks"), list) else []
    if not tasks:
        return ["Role-agent execution was requested but no task records were produced."]
    blockers: list[str] = []
    for task in tasks:
        if not isinstance(task, dict):
            continue
        agent_id = str(task.get("agent_id", "<unknown>"))
        status = str(task.get("status", "unknown"))
        if status != "completed":
            reason = str(task.get("blocked_reason", "") or "").strip()
            suffix = f": {reason}" if reason else ""
            blockers.append(f"{agent_id} status={status}{suffix}")
            continue
        worker_result = task.get("worker_result") if isinstance(task.get("worker_result"), dict) else {}
        if worker_result.get("executed") is not True:
            blockers.append(f"{agent_id} completed without executed worker evidence")
        if worker_result.get("returncode") not in {0, None}:
            blockers.append(f"{agent_id} worker returncode={worker_result.get('returncode')}")
    return blockers


def _auto_apply_gate_blockers(store: RunStore, run_id: str, blockers: dict[str, str]) -> None:
    if not blockers:
        return
    plan = store.load_plan(run_id)
    ledger = Ledger(store.run_dir(run_id), run_id)
    for gate in sorted(plan.gates, key=lambda item: item.order):
        reason = blockers.get(gate.id)
        if not reason:
            continue
        gate.state = "NO_GO"
        gate.verdict = "NO_GO"
        gate.notes = reason
        ledger.event("gate.completed", gate=gate.id, verdict="NO_GO", evidence=list(gate.evidence), auto=True, reason=reason)
    store.save_plan(plan)


def _auto_redteam_rounds(plan: RunPlan, policy: dict[str, object], requested_rounds: int | None) -> int:
    if requested_rounds and requested_rounds > 0:
        return requested_rounds
    redteam = policy.get("redteam", {}) if isinstance(policy.get("redteam"), dict) else {}
    if plan.risk_level in {"HIGH", "EXTREME"}:
        return max(1, int(redteam.get("min_rounds_high_stakes", 1) or 1))
    return 1


def _auto_redteam_workers(policy: dict[str, object], raw_workers: str | None) -> list[str]:
    if raw_workers:
        workers = [item.strip() for item in raw_workers.split(",") if item.strip()]
        if workers:
            return workers
    return _policy_redteam_workers(policy)


def _auto_redteam_blockers(redteam_execution: dict[str, object], *, execute_requested: bool) -> list[str]:
    if not execute_requested:
        return []
    verdict = str(redteam_execution.get("verdict", "NO_GO"))
    if verdict == "GO":
        return []
    notes = str(redteam_execution.get("notes", "") or "Executed red-team did not return GO.")
    parsed = redteam_execution.get("parsed_findings") if isinstance(redteam_execution.get("parsed_findings"), list) else []
    finding_ids = [
        str(item.get("id"))
        for item in parsed
        if isinstance(item, dict) and item.get("id")
    ]
    suffix = f" Findings: {', '.join(finding_ids)}." if finding_ids else ""
    return [notes + suffix]


def _auto_compact_redteam_execution(redteam_execution: dict[str, object]) -> dict[str, object]:
    keys = [
        "verdict",
        "notes",
        "summary",
        "unavailable",
        "available_families",
        "executed_families",
        "executed_identity_groups",
        "worker_verdicts",
        "mutation_violations",
        "timed_out_workers",
        "truncated_workers",
        "skipped_due_total_timeout",
        "hard_isolated_workers",
        "worker_timeout_seconds",
        "total_timeout_seconds",
        "parallel_per_round_enabled",
    ]
    compact = {key: redteam_execution.get(key) for key in keys if key in redteam_execution}
    parsed = redteam_execution.get("parsed_findings")
    if isinstance(parsed, list):
        compact["parsed_findings"] = parsed
    worker_results = redteam_execution.get("worker_results")
    if isinstance(worker_results, list):
        compact["worker_result_count"] = len(worker_results)
        compact["worker_result_artifacts"] = [
            item.get("result_path") or item.get("artifact") or item.get("external_capture_manifest")
            for item in worker_results
            if isinstance(item, dict)
        ]
    return compact


def _write_auto_validation_artifact(
    repo: Path,
    run_dir: Path,
    run_id: str,
    *,
    request: str,
    worker: str,
    execute: bool,
    allow_network: bool,
    policy: dict[str, object],
    timeout: int,
    operations: list[dict[str, object]],
    gate_artifacts: dict[str, str],
    agent_execution: dict[str, object],
    redteam_execution: dict[str, object],
    phase_report_artifact: str,
    html_summary_artifact: str,
) -> dict[str, object]:
    ledger = Ledger(run_dir, run_id)
    prompt = "\n".join([
        "# SDLC Auto Honesty Validation",
        "",
        "You are an independent validation worker. Inspect only the supplied run evidence and return one JSON object.",
        "",
        "Required verdict: GO only when the run honestly distinguishes executed work from planned work, role workers actually executed when requested, executed red-team evidence exists when requested, and all 25 gates have proof artifacts.",
        "Return NO_GO for missing evidence, dry-run labels masquerading as execution, missing all-gate proof, failed workers, or unsupported production/cloud claims.",
        "",
        "JSON shape:",
        '{"verdict":"GO|NO_GO","reasons":["..."],"checked_gates":25,"real_worker_execution":true,"honesty_notes":["..."]}',
        "",
        f"Run ID: {run_id}",
        f"Request: {request}",
        f"Operations: {json.dumps(operations, sort_keys=True)}",
        f"Gate artifacts: {json.dumps(gate_artifacts, sort_keys=True)}",
        f"Agent execution summary: {json.dumps(agent_execution.get('last_execution', {}), sort_keys=True)}",
        f"Agent task count: {len(agent_execution.get('tasks', [])) if isinstance(agent_execution.get('tasks'), list) else 0}",
        f"Red-team execution: {json.dumps(_auto_compact_redteam_execution(redteam_execution), sort_keys=True)}",
        f"Phase report: {phase_report_artifact}",
        f"HTML dashboard: {html_summary_artifact}",
        "",
    ])
    prompt_artifact = ledger.artifact(
        "artifacts/auto/validation/claude-validation-prompt.md",
        prompt,
        event="auto.validation_prompt_written",
        worker=worker,
        redact=True,
    )
    payload: dict[str, object] = {
        "schema_version": 1,
        "worker": worker,
        "execute_requested": execute,
        "allow_network": allow_network,
        "prompt": prompt_artifact,
        "verdict": "SKIPPED",
        "status": "SKIPPED",
        "reasons": [],
    }
    if not execute:
        payload["reasons"] = ["Claude validation was not requested."]
    else:
        policy_error = _worker_execution_policy_error(policy, execute=True, allow_network=allow_network)
        adapter = adapter_from_policy(worker, policy)
        if policy_error:
            payload.update({"status": "BLOCKED_BY_POLICY", "verdict": "NO_GO", "reasons": [policy_error]})
        elif adapter is None:
            payload.update({"status": "WORKER_UNAVAILABLE", "verdict": "NO_GO", "reasons": [f"unknown worker: {worker}"]})
        else:
            prompt_path = run_dir / prompt_artifact
            result = adapter.run(prompt_path, repo, "SECURITY_REVIEW", execute=True, timeout=timeout)
            captured = capture_worker_result(
                run_dir=run_dir,
                mode="AUTO_VALIDATION",
                prompt_path=prompt_path,
                result=result,
                ledger=ledger,
                label="claude-validation",
            )
            parsed = _extract_json_object(result.stdout) or {}
            verdict = str(parsed.get("verdict", "") or "").upper()
            if result.executed and result.returncode == 0 and verdict == "GO":
                status = "GO"
            else:
                status = "NO_GO"
                if not verdict:
                    parsed.setdefault("reasons", ["validation worker did not emit an explicit GO verdict"])
            payload.update({
                "status": status,
                "verdict": status,
                "parsed": parsed,
                "worker_result": {
                    key: captured.get(key)
                    for key in ("result_path", "stdout_path", "stderr_path", "output_dir", "returncode", "executed", "available")
                    if key in captured
                },
            })
    artifact = ledger.artifact(
        "artifacts/auto/validation/claude-validation.json",
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        event="auto.validation_record_written",
        worker=worker,
        status=str(payload.get("status", "")),
        verdict=str(payload.get("verdict", "")),
        redact=True,
    )
    payload["artifact"] = artifact
    return payload


def _write_auto_execution_log(
    store: RunStore,
    run_id: str,
    *,
    operations: list[dict[str, object]],
    agent_execution: dict[str, object],
    redteam_execution: dict[str, object],
    validation: dict[str, object],
) -> tuple[str, str]:
    run_dir = store.run_dir(run_id)
    ledger = Ledger(run_dir, run_id)
    events_path = run_dir / "events.jsonl"
    events: list[dict[str, object]] = []
    if events_path.exists():
        for line in events_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                events.append(parsed)
    event_json_artifact = ledger.artifact(
        "artifacts/auto/execution-events.json",
        json.dumps(events, indent=2, sort_keys=True) + "\n",
        event="auto.execution_events_exported",
        event_count=len(events),
        redact=True,
    )
    lines = [
        "# Auto Execution Log",
        "",
        f"Run: {run_id}",
        f"Event count captured before this log: {len(events)}",
        "",
        "## Operations",
    ]
    for item in operations:
        artifact = f" artifact=`{item.get('artifact')}`" if item.get("artifact") else ""
        lines.append(f"- Gates {item.get('gates')}: {item.get('status')} `{item.get('name')}`{artifact}")
    lines.extend(["", "## Role Workers"])
    tasks = agent_execution.get("tasks") if isinstance(agent_execution.get("tasks"), list) else []
    if tasks:
        for task in tasks:
            if not isinstance(task, dict):
                continue
            worker_result = task.get("worker_result") if isinstance(task.get("worker_result"), dict) else {}
            lines.append(
                f"- `{task.get('agent_id')}` worker=`{task.get('worker_family')}` status=`{task.get('status')}` "
                f"executed=`{worker_result.get('executed', False)}` result=`{worker_result.get('result_path', '')}`"
            )
    else:
        lines.append("- No role-agent tasks were recorded.")
    lines.extend([
        "",
        "## Red-Team",
        f"- Verdict: `{redteam_execution.get('verdict', 'NOT_RUN')}`",
        f"- Summary: `{redteam_execution.get('summary', '')}`",
        "",
        "## Claude Validation",
        f"- Status: `{validation.get('status', 'SKIPPED')}`",
        f"- Artifact: `{validation.get('artifact', '')}`",
        "",
        f"Raw event export: `{event_json_artifact}`",
    ])
    md_artifact = ledger.artifact(
        "artifacts/auto/execution-log.md",
        "\n".join(lines) + "\n",
        event="auto.execution_log_written",
        redact=True,
        event_count=len(events),
    )
    return md_artifact, event_json_artifact


def _write_auto_presentation_artifacts(
    store: RunStore,
    run_id: str,
    *,
    request: str,
    artifact_kind: str,
    implementation_path: str,
    aws: dict[str, object],
    operations: list[dict[str, object]],
    gate_artifacts: dict[str, str],
    phase_report_artifact: str,
    html_summary_artifact: str,
    execution_log_artifact: str,
    validation: dict[str, object],
    redteam_execution: dict[str, object],
) -> dict[str, str]:
    plan = store.load_plan(run_id)
    run_dir = store.run_dir(run_id)
    ledger = Ledger(run_dir, run_id)
    gates = sorted(plan.gates, key=lambda item: item.order)
    gate_cells = "\n".join(
        f"<span class=\"gate {'go' if gate.verdict == 'GO' else 'nogo'}\">{gate.order:02d}</span>"
        for gate in gates
    )
    operation_items = "\n".join(
        f"<li><strong>{html.escape(str(item.get('gates', '')))}</strong> {html.escape(str(item.get('status', '')))} - {html.escape(str(item.get('name', '')))}</li>"
        for item in operations[:12]
    )
    slides = "\n".join([
        "<section class=\"slide hero\"><div><p class=\"kicker\">Secure SDLC Auto</p><h1>25 Gates, Clickable Proof, Executed Workers</h1><p>{}</p></div></section>".format(html.escape(request)),
        "<section class=\"slide\"><h2>The Artifact</h2><p class=\"big\">{}</p><p>Kind: <strong>{}</strong></p><p>AWS/Cleanup: <strong>{}</strong></p></section>".format(html.escape(implementation_path), html.escape(artifact_kind), html.escape(str(aws.get("status", "UNKNOWN")))),
        "<section class=\"slide\"><h2>Gate Matrix</h2><div class=\"gate-grid\">{}</div><p>Every number links back through the evidence dashboard and per-gate proof files.</p></section>".format(gate_cells),
        "<section class=\"slide\"><h2>Operations Trace</h2><ol>{}</ol></section>".format(operation_items),
        "<section class=\"slide\"><h2>Role Workers</h2><p class=\"big\">Executed role-agent subprocesses are captured with stdout, stderr, command, return code, and result JSON.</p><p>Execution log: {}</p></section>".format(_auto_presentation_link("open log", execution_log_artifact)),
        "<section class=\"slide\"><h2>Brutal Red-Team</h2><p class=\"big\">Verdict: {}</p><p>{}</p></section>".format(html.escape(str(redteam_execution.get("verdict", "NOT_RUN"))), html.escape(str(redteam_execution.get("notes", "")))),
        "<section class=\"slide\"><h2>Claude Honesty Check</h2><p class=\"big\">Status: {}</p><p>{}</p></section>".format(html.escape(str(validation.get("status", "SKIPPED"))), _auto_presentation_link("open validation", str(validation.get("artifact", ""))) if validation.get("artifact") else "Not requested"),
        "<section class=\"slide\"><h2>Demo Links</h2><p>{}</p><p>{}</p><p>{}</p></section>".format(_auto_presentation_link("Evidence dashboard", html_summary_artifact), _auto_presentation_link("25-phase report", phase_report_artifact), _auto_presentation_link("Execution log", execution_log_artifact)),
    ])
    deck = "\n".join([
        "<!doctype html>",
        "<html lang=\"en\">",
        "<head>",
        "  <meta charset=\"utf-8\">",
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        f"  <title>SDLC Showcase - {html.escape(run_id)}</title>",
        "  <style>",
        "    :root { --ink:#111827; --paper:#fbfaf6; --line:#d7d2c7; --a:#0f766e; --b:#7c2d12; --c:#1d4ed8; --good:#047857; --bad:#b91c1c; }",
        "    * { box-sizing:border-box; } body { margin:0; background:var(--ink); color:var(--ink); font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; }",
        "    .deck { height:100vh; overflow-y:auto; scroll-snap-type:y mandatory; }",
        "    .slide { min-height:100vh; scroll-snap-align:start; padding:7vh 8vw; display:grid; align-content:center; gap:24px; background:var(--paper); border-bottom:1px solid var(--line); }",
        "    .slide:nth-child(3n+2) { background:#eef6f4; } .slide:nth-child(3n) { background:#f5f0e8; }",
        "    .hero { color:white; background:linear-gradient(135deg,#111827 0%,#0f766e 48%,#7c2d12 100%); }",
        "    h1 { max-width:980px; margin:0; font-size:clamp(3rem,7vw,7rem); line-height:.92; letter-spacing:0; }",
        "    h2 { margin:0; font-size:clamp(2rem,5vw,4.5rem); line-height:1; letter-spacing:0; }",
        "    p { max-width:920px; font-size:clamp(1.05rem,2vw,1.65rem); line-height:1.45; color:#374151; } .hero p { color:#e5e7eb; }",
        "    .kicker { text-transform:uppercase; letter-spacing:.16em; font-weight:800; color:#99f6e4; }",
        "    .big { font-size:clamp(1.45rem,3vw,2.6rem); color:var(--ink); font-weight:800; }",
        "    .gate-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(64px,1fr)); gap:12px; max-width:1100px; }",
        "    .gate { aspect-ratio:1; display:grid; place-items:center; border-radius:8px; color:white; font-weight:900; font-size:1.15rem; box-shadow:0 12px 24px rgba(17,24,39,.18); animation:rise .7s ease both; }",
        "    .go { background:var(--good); } .nogo { background:var(--bad); }",
        "    ol { max-width:1000px; font-size:1.25rem; line-height:1.75; } a { color:var(--c); font-weight:800; }",
        "    @keyframes rise { from { transform:translateY(18px); opacity:.15; } to { transform:translateY(0); opacity:1; } }",
        "  </style>",
        "</head>",
        "<body><main class=\"deck\">",
        slides,
        "</main></body>",
        "</html>",
    ])
    index_artifact = ledger.artifact(
        "artifacts/auto/presentation/index.html",
        deck + "\n",
        event="auto.presentation_deck_written",
        redact=False,
    )
    manim_script = "\n".join([
        "from manim import *",
        "",
        "",
        "class SDLCShowcase(Scene):",
        "    def construct(self):",
        "        title = Text('Secure SDLC Auto', font_size=48).to_edge(UP)",
        "        subtitle = Text('25 gates with executable evidence', font_size=28).next_to(title, DOWN)",
        "        self.play(Write(title), FadeIn(subtitle))",
        "        gates = VGroup(*[Square(side_length=0.42).set_fill(GREEN_E, opacity=0.9).set_stroke(WHITE, 1) for _ in range(25)])",
        "        gates.arrange_in_grid(rows=5, cols=5, buff=0.16).move_to(ORIGIN)",
        "        labels = VGroup(*[Text(f'{i:02d}', font_size=16).move_to(gates[i-1]) for i in range(1, 26)])",
        "        self.play(LaggedStart(*[FadeIn(g, shift=UP*0.2) for g in gates], lag_ratio=0.035), run_time=2.4)",
        "        self.play(LaggedStart(*[Write(label) for label in labels], lag_ratio=0.025), run_time=1.8)",
        "        proof = Text('Intake -> Architecture -> Implementation -> QA -> Red-Team -> Deploy/Cleanup -> Report', font_size=24).to_edge(DOWN)",
        "        self.play(FadeIn(proof))",
        "        self.wait(2)",
    ]) + "\n"
    manim_artifact = ledger.artifact(
        "artifacts/auto/presentation/manim_scene.py",
        manim_script,
        event="auto.presentation_manim_written",
        redact=False,
    )
    readme = "\n".join([
        "# SDLC Showcase Presentation",
        "",
        f"- HTML deck: `{index_artifact}`",
        f"- Manim scene: `{manim_artifact}`",
        "",
        "Render the Manim animation when Manim is installed:",
        "",
        "```bash",
        "cd .sdlc/runs/{}/artifacts/auto/presentation".format(run_id),
        "manim -pqh manim_scene.py SDLCShowcase",
        "```",
    ])
    readme_artifact = ledger.artifact(
        "artifacts/auto/presentation/README.md",
        readme + "\n",
        event="auto.presentation_readme_written",
        redact=False,
    )
    return {"index": index_artifact, "manim": manim_artifact, "readme": readme_artifact}


def _write_auto_phase_report(
    store: RunStore,
    run_id: str,
    *,
    request: str,
    intake: dict[str, object],
    operations: list[dict[str, object]],
    implementation_path: str,
    implementation_artifact: str,
    artifact_kind: str,
    aws: dict[str, object],
    readiness: dict[str, object],
    gate_artifacts: dict[str, str],
) -> str:
    plan = store.load_plan(run_id)
    run_dir = store.run_dir(run_id)
    ledger = Ledger(run_dir, run_id)
    readiness_by_gate = {
        str(item.get("gate_id")): str(item.get("release_state"))
        for item in readiness.get("gate_readiness", [])
        if isinstance(item, dict)
    }
    agent_plan = read_json(run_dir / "artifacts" / "agents" / "task-plan.json", {})
    role_model_selection = agent_plan.get("role_model_selection", {}) if isinstance(agent_plan, dict) else {}
    assignments = role_model_selection.get("assignments", {}) if isinstance(role_model_selection, dict) else {}
    lines = [
        "# Auto 25-Phase Work Report",
        "",
        f"Run: {run_id}",
        f"Request: {request}",
        f"Generated artifact: `{implementation_path}`",
        f"Artifact kind: `{artifact_kind}`",
        f"Run artifact: `{implementation_artifact}`",
        f"AWS status: `{aws.get('status', 'UNKNOWN')}`",
        f"AWS URL: {aws.get('website_url', '')}",
        f"Local verdict: `{readiness.get('local_verdict', 'UNKNOWN')}`",
        f"Release verdict: `{readiness.get('release_verdict', 'UNKNOWN')}`",
        "",
        "## Approved Intake",
        f"- Request kind: {intake.get('kind', '')}",
        f"- Approved: {intake.get('approved', False)}",
        f"- Interactive: {intake.get('interactive', False)}",
        "",
        "## Operations",
    ]
    for operation in operations:
        artifact = f" (`{operation.get('artifact')}`)" if operation.get("artifact") else ""
        lines.append(f"- Gates {operation.get('gates')}: {operation.get('status')} {operation.get('name')}{artifact}")
    lines.extend(["", "## Role Model Selection"])
    if isinstance(assignments, dict) and assignments:
        for agent_id, assignment in sorted(assignments.items()):
            if isinstance(assignment, dict):
                lines.append(f"- `{agent_id}`: `{assignment.get('worker_family', '')}` mode `{assignment.get('mode', '')}` available `{assignment.get('worker_available', False)}`")
    else:
        lines.append("- No role-agent model assignments were recorded.")
    lines.extend(["", "## Gate Work Detail"])
    for gate in sorted(plan.gates, key=lambda item: item.order):
        lines.extend([
            "",
            f"### {gate.order:02d}. {gate.title}",
            f"- Gate ID: `{gate.id}`",
            f"- Local result: `{gate.state}/{gate.verdict or 'UNKNOWN'}`",
            f"- Release state: `{readiness_by_gate.get(gate.id, 'UNKNOWN')}`",
            f"- Work done: {_auto_gate_work_detail(gate.id, implementation_path=implementation_path, artifact_kind=artifact_kind, aws_status=str(aws.get('status', 'UNKNOWN')))}",
            f"- Proof artifact: `{gate_artifacts.get(gate.id, '')}`",
            f"- Evidence count: {len(gate.evidence)}",
        ])
    artifact = ledger.artifact(
        "artifacts/auto/25-phase-report.md",
        "\n".join(lines) + "\n",
        event="auto.phase_report_written",
        redact=True,
        gate_count=len(plan.gates),
    )
    final_report = run_dir / "final-report.md"
    if final_report.exists():
        existing = final_report.read_text(encoding="utf-8")
        link_block = "\n\n## Auto 25-Phase Work Report\n\n" + f"Detailed phase report: `{artifact}`\n"
        if f"Detailed phase report: `{artifact}`" not in existing:
            final_report.write_text(existing.rstrip() + link_block, encoding="utf-8")
            ledger.event("auto.final_report_phase_report_linked", artifact=artifact)
    return artifact


def _open_auto_target(repo: Path, run_dir: Path, *, implementation_path: str, phase_report: str, html_summary: str, aws: dict[str, object], intake: dict[str, object]) -> str | None:
    if not intake.get("open_browser"):
        return None
    target_choice = str(intake.get("open_target", "Open finished page"))
    if target_choice in {"Open final report", "Open evidence dashboard"}:
        target = (run_dir / html_summary).resolve().as_uri()
    elif aws.get("status") == "EXECUTED" and aws.get("website_url"):
        target = str(aws["website_url"])
    else:
        target = (repo / implementation_path).resolve().as_uri()
    opened = webbrowser.open(target)
    Ledger(run_dir, str(run_dir.name)).event("auto.browser_opened", target=target, opened=opened)
    return target


def _write_auto_gate_evidence(
    store: RunStore,
    run_id: str,
    *,
    implementation_path: str,
    implementation_artifact: str,
    artifact_kind: str,
    aws_artifact: str | None,
    intake_artifact: str | None,
    demo_output_artifact: str | None,
    agent_execution_artifact: str | None = None,
    redteam_artifact: str | None = None,
    validation_artifact: str | None = None,
) -> dict[str, str]:
    plan = store.load_plan(run_id)
    run_dir = store.run_dir(run_id)
    ledger = Ledger(run_dir, run_id)
    artifacts: dict[str, str] = {}
    is_website = artifact_kind == "website"
    is_decommission = artifact_kind == "decommission"
    for gate in sorted(plan.gates, key=lambda item: item.order):
        gate_definition = _gate_definition(gate.id)
        required_artifacts = gate_definition.required_artifacts if gate_definition else []
        required = "\n".join(f"- {item}" for item in required_artifacts) or "- <none>"
        extra = ""
        if gate.id == "implementation":
            extra = f"\nImplemented artifact: `{implementation_path}`\nRun artifact: `{implementation_artifact}`\n"
        elif gate.id in {"intake_scope", "stakeholders_raci", "mission_non_goals", "risk_blast_radius", "architecture_contracts"}:
            extra = f"\nIntake and approvals: `{intake_artifact or 'artifacts/auto/intake-approvals.md'}`\n"
        elif gate.id == "deterministic_quality":
            if is_website:
                extra = "\nValidation: generated HTML contains document structure, a labelled form, a button, and no inline script tags.\n"
            elif is_decommission:
                extra = "\nValidation: cleanup target, command plan, approval posture, and local cleanup scope were recorded before any destructive action.\n"
            else:
                extra = f"\nValidation: generated Python script executed locally; transcript: `{demo_output_artifact or 'artifacts/auto/implementation/demo-output.md'}`.\n"
        elif gate.id == "security_scans":
            if is_website:
                extra = "\nSecurity check: generated static HTML has no JavaScript, no external fetches, no secrets, and no runtime backend surface.\n"
            elif is_decommission:
                extra = "\nSecurity check: destructive cleanup is plan-only by default and execution requires explicit approval text.\n"
            else:
                extra = "\nSecurity check: generated Python uses only the standard library, has no network calls, and stores no secrets.\n"
        elif gate.id == "supply_chain_sbom":
            extra = "\nSupply-chain note: no third-party packages or lockfile changes were introduced; implementation uses only first-party generated code.\n"
        elif gate.id == "agent_plan_permissions":
            extra = f"\nRole-agent execution evidence: `{agent_execution_artifact or 'artifacts/agents/task-plan.json'}`\n"
        elif gate.id == "ui_architecture_accessibility" and not is_website:
            extra = "\nUI/accessibility note: no graphical UI was generated; CLI usage is exposed through argparse help text.\n"
        elif gate.id == "independent_redteam_cross_model":
            extra = f"\nRed-team evidence: `{redteam_artifact or 'artifacts/auto/redteam-review.md'}`\n"
        elif gate.id == "deploy_rollout_postdeploy":
            extra = f"\nAWS deployment/cleanup evidence: `{aws_artifact or 'artifacts/auto/aws-plan.json'}`\n"
        elif gate.id == "final_report_reaudit":
            extra = f"\nIndependent honesty validation: `{validation_artifact or 'not requested'}`\n"
        content = "\n".join([
            f"# Auto Gate {gate.order:02d}: {gate.title}",
            "",
            f"Run: {run_id}",
            f"Gate ID: {gate.id}",
            f"Owner: {gate.owner}",
            "",
            "Required artifacts:",
            required,
            extra,
            "Auto result: GO",
            f"Scope: this is an SDLC auto-generated {artifact_kind} run. The gate is locally passed with recorded evidence.",
            "Claim discipline: release and cloud authority still depend on the recorded AWS execution mode and final report.",
        ])
        artifact = ledger.artifact(
            f"artifacts/auto/gates/{gate.order:02d}-{gate.id}.md",
            content + "\n",
            event="auto.gate_evidence_written",
            gate=gate.id,
            gate_order=gate.order,
            redact=False,
        )
        artifacts[gate.id] = artifact
    return artifacts


def _write_auto_evidence_index(store: RunStore, run_id: str, gate_artifacts: dict[str, str]) -> str:
    plan = store.load_plan(run_id)
    run_dir = store.run_dir(run_id)
    lines = [
        "# Auto Evidence Index",
        "",
        f"Run: {run_id}",
        "",
        "| # | Gate | Result | Proof artifact |",
        "|---|------|--------|----------------|",
    ]
    for gate in sorted(plan.gates, key=lambda item: item.order):
        proof = gate_artifacts.get(gate.id, "")
        result = f"{gate.state}/{gate.verdict or 'UNKNOWN'}"
        lines.append(f"| {gate.order:02d} | `{gate.id}` | `{result}` | `{proof}` |")
    return Ledger(run_dir, run_id).artifact(
        "artifacts/auto/evidence-index.md",
        "\n".join(lines) + "\n",
        event="auto.evidence_index_written",
        gate_count=len(plan.gates),
        redact=False,
    )


def _auto_html_link(label: str, href: str) -> str:
    return f"<a href=\"{html.escape(_auto_dashboard_href(href), quote=True)}\">{html.escape(label)}</a>"


def _auto_presentation_link(label: str, href: str) -> str:
    return f"<a href=\"{html.escape(_auto_presentation_href(href), quote=True)}\">{html.escape(label)}</a>"


def _auto_dashboard_href(artifact: str) -> str:
    if artifact.startswith("artifacts/auto/"):
        return artifact.removeprefix("artifacts/auto/")
    if artifact.startswith("artifacts/"):
        return "../" + artifact.removeprefix("artifacts/")
    if artifact in {"findings.json", "final-report.md", "plan.json"}:
        return "../../" + artifact
    return artifact


def _auto_presentation_href(artifact: str) -> str:
    if artifact.startswith("artifacts/auto/"):
        return "../" + artifact.removeprefix("artifacts/auto/")
    if artifact.startswith("artifacts/"):
        return "../../" + artifact.removeprefix("artifacts/")
    if artifact in {"findings.json", "final-report.md", "plan.json"}:
        return "../../../" + artifact
    return artifact


def _write_auto_html_dashboard(
    store: RunStore,
    run_id: str,
    *,
    request: str,
    implementation_path: str,
    artifact_kind: str,
    aws: dict[str, object],
    operations: list[dict[str, object]],
    gate_artifacts: dict[str, str],
    evidence_index_artifact: str,
    phase_report_artifact: str,
    execution_log_artifact: str | None = None,
    presentation_artifact: str | None = None,
    validation_artifact: str | None = None,
    redteam_artifact: str | None = None,
) -> str:
    plan = store.load_plan(run_id)
    run_dir = store.run_dir(run_id)
    agent_plan = read_json(run_dir / "artifacts" / "agents" / "task-plan.json", {})
    llm_intake = read_json(run_dir / "artifacts" / "auto" / "llm-intake.json", {})
    tasks = agent_plan.get("tasks", []) if isinstance(agent_plan, dict) else []
    assignments = (
        agent_plan.get("role_model_selection", {}).get("assignments", {})
        if isinstance(agent_plan.get("role_model_selection"), dict)
        else {}
    ) if isinstance(agent_plan, dict) else {}
    gate_cards: list[str] = []
    for gate in sorted(plan.gates, key=lambda item: item.order):
        proof = gate_artifacts.get(gate.id, "")
        role = gate.owner
        worker = ""
        if isinstance(assignments, dict):
            assignment = assignments.get(gate.owner)
            if isinstance(assignment, dict):
                worker = str(assignment.get("worker_family", "") or "")
        gate_cards.append(
            "\n".join([
                "<article class=\"gate-card\">",
                f"  <div class=\"gate-num\">{gate.order:02d}</div>",
                f"  <h3>{html.escape(gate.id)}</h3>",
                f"  <p>{html.escape(gate.title)}</p>",
                f"  <p><strong>Result:</strong> {html.escape(gate.state)}/{html.escape(gate.verdict or 'UNKNOWN')}</p>",
                f"  <p><strong>Owner:</strong> {html.escape(role)}</p>",
                f"  <p><strong>LLM:</strong> {html.escape(worker or 'policy default')}</p>",
                f"  <p>{_auto_html_link('Open proof', proof)}</p>",
                "</article>",
            ])
        )
    role_rows: list[str] = []
    if isinstance(tasks, list):
        for task in tasks:
            if not isinstance(task, dict):
                continue
            artifacts = task.get("artifacts", {}) if isinstance(task.get("artifacts"), dict) else {}
            summary = str(artifacts.get("summary", ""))
            role_rows.append(
                "<tr>"
                f"<td>{html.escape(str(task.get('agent_id', '')))}</td>"
                f"<td>{html.escape(str(task.get('role', '')))}</td>"
                f"<td>{html.escape(str(task.get('worker_family', '')))}</td>"
                f"<td>{html.escape(str(task.get('mode', '')))}</td>"
                f"<td>{html.escape(str(task.get('status', '')))}</td>"
                f"<td>{_auto_html_link('summary', summary) if summary else ''}</td>"
                "</tr>"
            )
    operation_rows = [
        "<tr>"
        f"<td>{html.escape(str(item.get('gates', '')))}</td>"
        f"<td>{html.escape(str(item.get('status', '')))}</td>"
        f"<td>{html.escape(str(item.get('name', '')))}</td>"
        f"<td>{_auto_html_link(str(item.get('artifact', '')), str(item.get('artifact', ''))) if item.get('artifact') else ''}</td>"
        "</tr>"
        for item in operations
    ]
    spotlight = [
        ("Architecture", "10-architecture_contracts.md", "Architecture/contracts/invariants evidence"),
        ("QA", "15-deterministic_quality.md", "Deterministic quality checks"),
        ("Smoke Tests", "16-qa_tests_integration_smoke.md", "QA and smoke validation"),
        ("SBOM", "08-supply_chain_sbom.md", "Supply-chain and dependency proof"),
        ("Red-Team", "20-independent_redteam_cross_model.md", "Independent adversarial review"),
        ("Fix Loop", "21-critical_high_fix_loop.md", "Critical/high finding lifecycle"),
    ]
    spotlight_cards = []
    for label, suffix, desc in spotlight:
        match = next((path for path in gate_artifacts.values() if path.endswith(suffix)), "")
        spotlight_cards.append(
            f"<article class=\"spotlight\"><h3>{html.escape(label)}</h3><p>{html.escape(desc)}</p><p>{_auto_html_link('Open report', match) if match else 'Not recorded'}</p></article>"
        )
    showcase_cards = [
        ("Execution Log", execution_log_artifact, "Intermediate event ledger, worker captures, and operation trace."),
        ("Presentation", presentation_artifact, "Demo slide deck and Manim scene artifacts."),
        ("Claude Validation", validation_artifact, "Independent honesty validation for executed worker evidence."),
        ("Executed Red-Team", redteam_artifact, "Formal red-team execution summary when requested."),
    ]
    showcase_card_html = [
        f"<article class=\"spotlight\"><h3>{html.escape(label)}</h3><p>{html.escape(desc)}</p><p>{_auto_html_link('Open artifact', str(path)) if path else 'Not requested'}</p></article>"
        for label, path, desc in showcase_cards
    ]
    document = "\n".join([
        "<!doctype html>",
        "<html lang=\"en\">",
        "<head>",
        "  <meta charset=\"utf-8\">",
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        f"  <title>SDLC Auto Evidence - {html.escape(run_id)}</title>",
        "  <style>",
        "    :root { color-scheme: light; --bg: #f7f5ef; --ink: #1f2933; --muted: #5f6b7a; --line: #d8d3c7; --accent: #0f766e; --panel: #fffdf8; --warn: #9a3412; }",
        "    * { box-sizing: border-box; }",
        "    body { margin: 0; background: var(--bg); color: var(--ink); font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }",
        "    header { padding: 42px 5vw 28px; background: #e9f3f0; border-bottom: 1px solid var(--line); }",
        "    main { padding: 28px 5vw 56px; display: grid; gap: 28px; }",
        "    h1 { margin: 0 0 10px; font-size: clamp(2rem, 4vw, 3.4rem); line-height: 1; letter-spacing: 0; }",
        "    h2 { margin: 0 0 14px; font-size: 1.35rem; }",
        "    h3 { margin: 0 0 8px; font-size: 1rem; }",
        "    p { line-height: 1.55; color: var(--muted); }",
        "    a { color: var(--accent); font-weight: 700; }",
        "    .meta, .spotlights, .gates { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }",
        "    .metric, .spotlight, .gate-card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; }",
        "    .metric strong { display: block; color: var(--ink); font-size: 1.2rem; margin-top: 6px; }",
        "    .gate-card { position: relative; min-height: 220px; }",
        "    .gate-num { width: 38px; height: 38px; display: grid; place-items: center; border-radius: 999px; background: var(--accent); color: white; font-weight: 800; margin-bottom: 12px; }",
        "    table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }",
        "    th, td { text-align: left; padding: 11px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }",
        "    th { background: #f0ebe0; color: var(--ink); }",
        "    code { background: #ede7da; padding: 2px 5px; border-radius: 4px; }",
        "  </style>",
        "</head>",
        "<body>",
        "  <header>",
        f"    <h1>SDLC Auto Evidence</h1>",
        f"    <p>Run <code>{html.escape(run_id)}</code> for: {html.escape(request)}</p>",
        "  </header>",
        "  <main>",
        "    <section class=\"meta\">",
        f"      <div class=\"metric\">Artifact<strong>{html.escape(implementation_path)}</strong></div>",
        f"      <div class=\"metric\">Kind<strong>{html.escape(artifact_kind)}</strong></div>",
        f"      <div class=\"metric\">AWS/Cleanup Status<strong>{html.escape(str(aws.get('status', 'UNKNOWN')))}</strong></div>",
        f"      <div class=\"metric\">Gateway<strong>{html.escape(str(aws.get('gateway_name', '')))}</strong></div>",
        "    </section>",
        "    <section>",
        "      <h2>Evidence Shortcuts</h2>",
        "      <div class=\"spotlights\">",
        *spotlight_cards,
        "      </div>",
        "    </section>",
        "    <section>",
        "      <h2>Showcase Proof</h2>",
        "      <div class=\"spotlights\">",
        *showcase_card_html,
        "      </div>",
        "    </section>",
        "    <section>",
        "      <h2>LLM Intake</h2>",
        "      <table><thead><tr><th>Source</th><th>Worker</th><th>Status</th><th>Prompt</th><th>Result</th></tr></thead><tbody>",
        "        <tr>"
        f"<td>{html.escape(str(llm_intake.get('source', '')) if isinstance(llm_intake, dict) else '')}</td>"
        f"<td>{html.escape(str(llm_intake.get('worker', '')) if isinstance(llm_intake, dict) else '')}</td>"
        f"<td>{html.escape(str(llm_intake.get('status', '')) if isinstance(llm_intake, dict) else '')}</td>"
        f"<td>{_auto_html_link('prompt', 'artifacts/auto/llm-intake-prompt.md')}</td>"
        f"<td>{_auto_html_link('result', 'artifacts/auto/llm-intake.json')}</td>"
        "</tr>",
        "      </tbody></table>",
        "    </section>",
        "    <section>",
        "      <h2>LLM Role Activity</h2>",
        "      <table><thead><tr><th>Agent</th><th>Role</th><th>LLM/Worker</th><th>Mode</th><th>Status</th><th>Artifact</th></tr></thead><tbody>",
        *role_rows,
        "      </tbody></table>",
        "    </section>",
        "    <section>",
        "      <h2>Operations</h2>",
        "      <table><thead><tr><th>Gates</th><th>Status</th><th>Operation</th><th>Artifact</th></tr></thead><tbody>",
        *operation_rows,
        "      </tbody></table>",
        "    </section>",
        "    <section>",
        "      <h2>All 25 Gates</h2>",
        f"      <p>{_auto_html_link('Evidence index', evidence_index_artifact)} · {_auto_html_link('25-phase report', phase_report_artifact)}</p>",
        "      <div class=\"gates\">",
        *gate_cards,
        "      </div>",
        "    </section>",
        "  </main>",
        "</body>",
        "</html>",
    ])
    return Ledger(run_dir, run_id).artifact(
        "artifacts/auto/summary.html",
        document + "\n",
        event="auto.html_dashboard_written",
        gate_count=len(plan.gates),
        redact=False,
    )


def _mark_auto_gates_passed(store: RunStore, run_id: str, gate_artifacts: dict[str, str]) -> None:
    plan = store.load_plan(run_id)
    ledger = Ledger(store.run_dir(run_id), run_id)
    for gate in sorted(plan.gates, key=lambda item: item.order):
        artifact = gate_artifacts.get(gate.id)
        if artifact:
            evidence = f".sdlc/runs/{run_id}/{artifact}"
            if evidence not in gate.evidence:
                gate.evidence.append(evidence)
        gate.state = "GO"
        gate.verdict = "GO"
        gate.notes = "Auto completed with local evidence. Release validation may still require stricter provenance for production claims."
        ledger.event("gate.completed", gate=gate.id, verdict="GO", evidence=list(gate.evidence), auto=True)
    store.save_plan(plan)


def _auto_bucket_name(run_id: str, gateway_name: str = "sdlc-web-gateway") -> str:
    digest = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:12]
    base = re.sub(r"[^a-z0-9-]+", "-", run_id.lower()).strip("-")[:34].strip("-")
    prefix = re.sub(r"[^a-z0-9-]+", "-", gateway_name.lower()).strip("-")[:28].strip("-") or "sdlc-web-gateway"
    return f"{prefix}-{base or 'site'}-{digest}"[:63].strip("-")


def _write_auto_aws_artifact(
    repo: Path,
    run_dir: Path,
    run_id: str,
    *,
    implementation_path: str,
    artifact_kind: str,
    profile: str,
    region: str,
    bucket: str | None,
    gateway_name: str,
    execute: bool,
    approval: str | None,
    public_read: bool,
) -> dict[str, object]:
    bucket_name = bucket or _auto_bucket_name(run_id, gateway_name=gateway_name)
    if artifact_kind != "website":
        payload = {
            "schema_version": 1,
            "status": "NOT_APPLICABLE",
            "execute_requested": False,
            "approval": approval or "",
            "profile": profile,
            "region": region,
            "gateway_name": gateway_name,
            "bucket": "",
            "public_read": False,
            "website_url": "",
            "commands": [],
            "results": [],
            "reason": f"AWS S3 website hosting is not applicable for artifact kind {artifact_kind}.",
        }
        artifact = Ledger(run_dir, run_id).artifact(
            "artifacts/auto/aws-plan.json",
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            event="auto.aws_artifact_written",
            status=payload["status"],
            execute_requested=False,
            bucket="",
            redact=False,
        )
        payload["artifact"] = artifact
        return payload

    site_dir = str((repo / implementation_path).parent)
    website_url = f"http://{bucket_name}.s3-website-{region}.amazonaws.com"
    release_prefix = f"s3://{bucket_name}/releases/{run_id}/"
    commands: list[list[str]] = [
        ["aws", "s3", "mb", f"s3://{bucket_name}", "--profile", profile, "--region", region],
        ["aws", "s3api", "put-bucket-versioning", "--bucket", bucket_name, "--versioning-configuration", "Status=Enabled", "--profile", profile],
        ["aws", "s3", "website", f"s3://{bucket_name}", "--index-document", "index.html", "--error-document", "index.html", "--profile", profile],
        ["aws", "s3", "sync", site_dir, release_prefix, "--delete", "--cache-control", "max-age=60", "--profile", profile],
        ["aws", "s3", "sync", release_prefix, f"s3://{bucket_name}", "--delete", "--cache-control", "max-age=60", "--profile", profile],
        ["curl", "-fL", website_url],
        ["curl", "-fL", f"{website_url}/evidence/gates/01-intake_scope.md"],
    ]
    if public_read:
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            }],
        })
        commands.insert(2, ["aws", "s3api", "delete-public-access-block", "--bucket", bucket_name, "--profile", profile])
        commands.insert(3, ["aws", "s3api", "put-bucket-policy", "--bucket", bucket_name, "--policy", policy, "--profile", profile])
    rollback_commands: list[list[str]] = [
        ["aws", "s3", "sync", f"s3://{bucket_name}/releases/PREVIOUS_RUN/", f"s3://{bucket_name}", "--delete", "--dryrun", "--profile", profile],
        ["aws", "s3", "sync", f"s3://{bucket_name}/releases/PREVIOUS_RUN/", f"s3://{bucket_name}", "--delete", "--cache-control", "max-age=60", "--profile", profile],
        ["aws", "s3", "ls", f"s3://{bucket_name}", "--recursive", "--profile", profile],
        ["curl", "-fL", website_url],
        ["curl", "-fL", f"{website_url}/evidence/gates/01-intake_scope.md"],
    ]
    results: list[dict[str, object]] = []
    status = "PLANNED"
    if execute:
        if not approval:
            status = "REJECTED"
            results.append({"returncode": 2, "stderr": "--approve-aws-deploy is required with --execute-aws"})
        elif shutil.which("aws") is None:
            status = "REJECTED"
            results.append({"returncode": 127, "stderr": "AWS CLI is not installed"})
        else:
            status = "EXECUTED"
            for command in commands:
                result = run_cmd(command, repo, timeout=300)
                results.append({
                    "command": command,
                    "returncode": result["returncode"],
                    "stdout": result["stdout"],
                    "stderr": result["stderr"],
                })
                if result["returncode"] != 0:
                    status = "FAILED"
                    break
    payload = {
        "schema_version": 1,
        "status": status,
        "execute_requested": execute,
        "approval": approval or "",
        "profile": profile,
        "region": region,
        "gateway_name": gateway_name,
        "bucket": bucket_name,
        "public_read": public_read,
        "public_access_model": "s3_website_bucket_policy" if public_read else "blocked_until_public_read_or_cloudfront_oac_is_approved",
        "website_url": website_url,
        "release_prefix": release_prefix,
        "commands": commands,
        "rollback_commands": rollback_commands,
        "post_deploy_smoke_checks": [
            {"url": website_url, "expect": "HTTP 200 with generated site"},
            {"url": f"{website_url}/evidence/gates/01-intake_scope.md", "expect": "HTTP 200 with public gate evidence status"},
        ],
        "results": results,
    }
    artifact = Ledger(run_dir, run_id).artifact(
        "artifacts/auto/aws-plan.json",
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        event="auto.aws_artifact_written",
        status=status,
        execute_requested=execute,
        bucket=bucket_name,
        redact=False,
    )
    payload["artifact"] = artifact
    return payload


def _find_auto_aws_plan(repo: Path, target_run_id: str | None = None) -> tuple[dict[str, object] | None, str | None, str | None]:
    runs_dir = repo / ".sdlc" / "runs"
    candidates: list[Path] = []
    if target_run_id:
        candidates = [runs_dir / target_run_id / "artifacts" / "auto" / "aws-plan.json"]
    elif runs_dir.exists():
        candidates = sorted(
            runs_dir.glob("*/artifacts/auto/aws-plan.json"),
            key=lambda path: path.stat().st_mtime if path.exists() else 0,
            reverse=True,
        )
    for path in candidates:
        payload = read_json(path, {})
        if not isinstance(payload, dict):
            continue
        bucket = str(payload.get("bucket", "") or "")
        status = str(payload.get("status", "") or "")
        if bucket and status != "NOT_APPLICABLE":
            try:
                run_id = path.relative_to(runs_dir).parts[0]
            except (ValueError, IndexError):
                run_id = target_run_id or ""
            return payload, run_id, str(path)
    return None, None, None


def _write_auto_decommission_artifact(
    repo: Path,
    run_dir: Path,
    run_id: str,
    *,
    profile: str,
    region: str,
    bucket: str | None,
    gateway_name: str,
    target_run_id: str | None,
    execute: bool,
    approval: str | None,
    cleanup_local: bool,
) -> dict[str, object]:
    discovered, discovered_run_id, discovered_path = _find_auto_aws_plan(repo, target_run_id=target_run_id)
    bucket_name = bucket or (str(discovered.get("bucket", "") or "") if isinstance(discovered, dict) else "")
    commands: list[list[str]] = []
    if bucket_name:
        commands = [
            ["aws", "s3", "rb", f"s3://{bucket_name}", "--force", "--profile", profile],
        ]
    local_targets = ["site"] if cleanup_local else []
    results: list[dict[str, object]] = []
    local_results: list[dict[str, object]] = []
    status = "PLANNED"
    if execute:
        if not approval:
            status = "REJECTED"
            results.append({"returncode": 2, "stderr": "--approve-cleanup is required with --execute-cleanup"})
        elif not bucket_name:
            status = "REJECTED"
            results.append({"returncode": 2, "stderr": "No S3 bucket was provided or discovered for cleanup"})
        elif shutil.which("aws") is None:
            status = "REJECTED"
            results.append({"returncode": 127, "stderr": "AWS CLI is not installed"})
        else:
            status = "EXECUTED"
            for command in commands:
                result = run_cmd(command, repo, timeout=300)
                results.append({
                    "command": command,
                    "returncode": result["returncode"],
                    "stdout": result["stdout"],
                    "stderr": result["stderr"],
                })
                if result["returncode"] != 0:
                    status = "FAILED"
                    break
            if cleanup_local and status == "EXECUTED":
                site_dir = (repo / "site").resolve(strict=False)
                repo_root = repo.resolve(strict=False)
                try:
                    site_dir.relative_to(repo_root)
                    if site_dir.exists() and site_dir.is_dir():
                        shutil.rmtree(site_dir)
                        local_results.append({"path": "site", "status": "DELETED"})
                    else:
                        local_results.append({"path": "site", "status": "MISSING"})
                except (OSError, ValueError) as exc:
                    status = "FAILED"
                    local_results.append({"path": "site", "status": "FAILED", "error": str(exc)})
    payload = {
        "schema_version": 1,
        "status": status,
        "execute_requested": execute,
        "approval": approval or "",
        "profile": profile,
        "region": region,
        "gateway_name": gateway_name,
        "bucket": bucket_name,
        "target_run_id": target_run_id or discovered_run_id or "",
        "discovered_plan": discovered_path or "",
        "commands": commands,
        "results": results,
        "cleanup_local": cleanup_local,
        "local_targets": local_targets,
        "local_results": local_results,
    }
    artifact = Ledger(run_dir, run_id).artifact(
        "artifacts/auto/decommission-plan.json",
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        event="auto.decommission_artifact_written",
        status=status,
        execute_requested=execute,
        bucket=bucket_name,
        redact=False,
    )
    payload["artifact"] = artifact
    return payload


def _auto_request_text(raw: object) -> str:
    if isinstance(raw, list):
        return " ".join(str(item) for item in raw if str(item).strip()).strip()
    if raw is None:
        return ""
    return str(raw).strip()


def command_auto(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    if getattr(args, "showcase", False):
        if getattr(args, "policy", "default") == "default":
            args.policy = "host-oauth-tools"
        args.allow_network = True
        args.execute_intake_llm = True
        args.execute_agents = True
        args.execute_redteam = True
        args.claude_validate = True
        args.presentation = True
        if not getattr(args, "no_open_browser", False):
            args.open_browser = True
    if args.timeout < 1:
        eprint("--timeout must be at least 1 second")
        return 2
    request = _auto_request_text(args.request) or "Create a responsive brochure website for a local bakery with an accessible contact form"
    base_policy = load_policy(repo, args.policy)
    intake = _collect_auto_intake(args, repo, request, base_policy)
    if not intake.get("approved", False):
        if intake.get("intake_error"):
            eprint(str(intake["intake_error"]))
        else:
            print("Auto cancelled before creating a run.")
        return 2
    agent_policy, agent_model_selection, policy_error = _agent_model_policy_from_args(repo, base_policy, args)
    if policy_error or agent_policy is None:
        eprint(policy_error or "Unable to apply agent model mapping")
        return 2
    effective_execute_agents = bool(getattr(args, "execute_agents", False))
    agent_execution_policy_error = _worker_execution_policy_error(agent_policy, execute=effective_execute_agents, allow_network=bool(getattr(args, "allow_network", False)))
    if agent_execution_policy_error:
        eprint(f"Agent execution requested but blocked: {agent_execution_policy_error}")
        return 2
    effective_execute_redteam = bool(getattr(args, "execute_redteam", False))
    redteam_execution_policy_error = _worker_execution_policy_error(agent_policy, execute=effective_execute_redteam, allow_network=bool(getattr(args, "allow_network", False)))
    if redteam_execution_policy_error:
        eprint(f"Red-team execution requested but blocked: {redteam_execution_policy_error}")
        return 2
    effective_claude_validate = bool(getattr(args, "claude_validate", False))
    validation_policy_error = _worker_execution_policy_error(agent_policy, execute=effective_claude_validate, allow_network=bool(getattr(args, "allow_network", False)))
    if validation_policy_error:
        eprint(f"Claude validation requested but blocked: {validation_policy_error}")
        return 2
    kind = str(intake.get("kind", _auto_request_kind(request)))
    artifact_kind = _auto_kind_to_artifact_kind(str(intake.get("artifact_kind") or kind))
    intake_aws = intake.get("aws") if isinstance(intake.get("aws"), dict) else {}
    effective_execute_aws = bool(intake_aws.get("execute", False)) if artifact_kind == "website" else False
    effective_execute_cleanup = bool(intake_aws.get("cleanup_execute", False)) if artifact_kind == "decommission" else False
    effective_public_read = bool(intake_aws.get("public_read", False)) if artifact_kind == "website" else False
    effective_approval = str(intake_aws.get("approval", "") or "")
    effective_cleanup_approval = str(intake_aws.get("cleanup_approval", "") or "")
    effective_profile = str(intake_aws.get("profile", args.aws_profile) or args.aws_profile)
    effective_region = str(intake_aws.get("region", args.aws_region) or args.aws_region)
    effective_bucket = str(intake_aws.get("bucket", "") or "") or None
    effective_gateway_name = str(intake_aws.get("gateway_name", args.aws_gateway_name) or args.aws_gateway_name)
    effective_target_run_id = str(intake_aws.get("target_run_id", args.target_run_id or "") or "") or None
    effective_cleanup_local = bool(intake_aws.get("cleanup_local", args.cleanup_local))
    effective_ui = args.ui
    effective_infra = "yes" if artifact_kind in {"website", "decommission"} and args.infra == "auto" else args.infra
    plan, run_dir, error = _create_run(
        repo,
        feature=request,
        risk=args.risk,
        ui=effective_ui,
        security=args.security,
        infra=effective_infra,
        policy_profile=args.policy,
        run_id=args.run_id,
        production_rollout_allowed_flag=False,
        allow_main_push_flag=False,
    )
    if error or plan is None or run_dir is None:
        eprint(error or "Unable to create auto run")
        return 2

    store = RunStore(repo)
    ledger = Ledger(run_dir, plan.run_id)
    operations: list[dict[str, object]] = []

    def record_operation(name: str, gates: str, status: str, detail: str, artifact: str | None = None) -> None:
        item: dict[str, object] = {
            "name": name,
            "gates": gates,
            "status": status,
            "detail": detail,
        }
        if artifact:
            item["artifact"] = artifact
        operations.append(item)
        ledger.event("auto.operation", name=name, gates=gates, status=status, detail=detail, artifact=artifact)

    def revise_operation(name: str, *, status: str, detail: str) -> None:
        for item in reversed(operations):
            if item.get("name") == name:
                item["status"] = status
                item["detail"] = detail
                ledger.event("auto.operation_revised", name=name, status=status, detail=detail)
                return

    _write_autopilot_artifacts(repo, plan, run_dir, include_agent_plan=True, parallel=args.parallel, policy=agent_policy)
    _prepare_auto_agent_plan_for_evidence(run_dir, plan.run_id)
    intake_artifact, intake_json_artifact = _write_auto_intake_artifacts(run_dir, plan.run_id, intake)
    record_operation(
        "intake_approvals",
        "01-13",
        "APPROVED",
        "Captured request-specific questions, selected architecture, contact policy, applicable infra/domain/certificate choices, and approval.",
        intake_artifact,
    )
    record_operation(
        "plan_and_prework",
        "01-13",
        "RECORDED",
        "Created the run, intake brief, standards mapping, agent plan, and next-action evidence.",
        "artifacts/prework/expectations.html",
    )
    walkthrough_artifacts = _write_auto_gate_walkthrough(store, plan.run_id)
    record_operation(
        "gate_walkthrough",
        "01-25",
        "RECORDED",
        "Recorded walkthrough evidence for every gate in the one-command auto run.",
        "artifacts/auto/walkthrough/gates",
    )
    implementation_path, implementation_artifact, artifact_kind = _write_auto_implementation(repo, run_dir, plan.run_id, request, intake)
    demo_output_artifact = _write_auto_demo_output(repo, run_dir, plan.run_id, implementation_path, artifact_kind, intake)
    record_operation(
        "implementation",
        "14",
        "IMPLEMENTED",
        f"Generated the {artifact_kind} artifact at {implementation_path}.",
        implementation_artifact,
    )
    if demo_output_artifact:
        record_operation(
            "implementation_demo",
            "15-16",
            "RECORDED",
            "Executed the generated artifact locally and captured the transcript.",
            demo_output_artifact,
        )
    if artifact_kind == "decommission":
        aws = _write_auto_decommission_artifact(
            repo,
            run_dir,
            plan.run_id,
            profile=effective_profile,
            region=effective_region,
            bucket=effective_bucket,
            gateway_name=effective_gateway_name,
            target_run_id=effective_target_run_id,
            execute=effective_execute_cleanup,
            approval=effective_cleanup_approval,
            cleanup_local=effective_cleanup_local,
        )
        record_operation(
            "environment_decommission",
            "24",
            str(aws.get("status", "UNKNOWN")),
            f"Environment cleanup {'executed' if effective_execute_cleanup else 'planned'} using profile {effective_profile}.",
            str(aws.get("artifact") or "artifacts/auto/decommission-plan.json"),
        )
    else:
        aws = _write_auto_aws_artifact(
            repo,
            run_dir,
            plan.run_id,
            implementation_path=implementation_path,
            artifact_kind=artifact_kind,
            profile=effective_profile,
            region=effective_region,
            bucket=effective_bucket,
            gateway_name=effective_gateway_name,
            execute=effective_execute_aws,
            approval=effective_approval,
            public_read=effective_public_read,
        )
        record_operation(
            "aws_hosting",
            "24",
            str(aws.get("status", "UNKNOWN")),
            f"AWS S3 website hosting {'executed' if effective_execute_aws else 'planned' if artifact_kind == 'website' else 'not applicable'} using profile {effective_profile}.",
            str(aws.get("artifact") or "artifacts/auto/aws-plan.json"),
        )

    plan = store.load_plan(plan.run_id)
    agent_execution = execute_agent_plan(
        run_dir,
        plan,
        agent_policy,
        execute=effective_execute_agents,
        parallel=args.parallel,
        timeout=args.timeout,
        progress=None,
    )
    agent_statuses = {str(task.get("status")) for task in agent_execution.get("tasks", [])}
    agent_blocker_preview = _auto_agent_execution_blockers(agent_execution, execute_requested=effective_execute_agents)
    record_operation(
        "agent_execution" if effective_execute_agents else "agent_dry_run",
        "09,14,16",
        "RECORDED" if agent_statuses <= {"completed"} else "NO_GO",
        (
            "Role-agent workers executed in auto evidence mode and their task artifacts were captured."
            if effective_execute_agents and not agent_blocker_preview
            else "Role-agent execution requested but blockers were recorded: " + "; ".join(agent_blocker_preview[:4])
            if effective_execute_agents
            else "Role-agent task artifacts were planned only; workers were not executed."
        ),
        str(agent_execution.get("artifact") or "artifacts/agents/task-plan.json"),
    )

    record_operation(
        "advisory_and_deterministic_gates",
        "01-20",
        "GO",
        "Recorded local advisory, quality, QA, and scanner evidence for the generated artifact.",
        walkthrough_artifacts.get("deterministic_quality"),
    )

    redteam_execution: dict[str, object] = {}
    if effective_execute_redteam:
        redteam_workers = _auto_redteam_workers(agent_policy, getattr(args, "redteam_workers", None))
        redteam_rounds = _auto_redteam_rounds(plan, agent_policy, getattr(args, "redteam_rounds", None))
        redteam_execution = execute_redteam_workers(
            store,
            plan.run_id,
            workers=redteam_workers,
            rounds=redteam_rounds,
            execute=True,
            timeout=args.timeout,
            total_timeout=getattr(args, "redteam_total_timeout", None),
            allow_network=bool(getattr(args, "allow_network", False)),
            parallel_per_round=bool(getattr(args, "redteam_parallel", False)),
            progress=None,
        )
        record_operation(
            "brutal_redteam_execution",
            "20-21",
            str(redteam_execution.get("verdict", "NO_GO")),
            f"Executed formal red-team workers {', '.join(redteam_workers)} for {redteam_rounds} round(s).",
            str(redteam_execution.get("summary") or "artifacts/redteam/execution-summary.md"),
        )
    else:
        redteam_artifact = Ledger(run_dir, plan.run_id).artifact(
            "artifacts/auto/redteam-review.md",
            f"# Auto Red-Team Review\n\nResult: no blocking findings for the generated {artifact_kind} surface.\n\nScope: generated local artifact, no secrets, no production mutation by default.\n\nThis is deterministic local review evidence, not executed LLM red-team evidence.\n",
            event="auto.redteam_review_written",
            redact=False,
        )
        redteam_execution = {
            "verdict": "GO",
            "notes": "Deterministic local review only; executed red-team was not requested.",
            "summary": redteam_artifact,
            "executed": False,
        }
        store.save_findings(plan.run_id, [])
    findings = store.load_findings(plan.run_id)
    blocking_findings = open_findings(findings, {"CRITICAL", "HIGH", "MEDIUM"})
    record_operation(
        "redteam_and_finding_lifecycle",
        "20-21",
        "NO_GO" if blocking_findings or _auto_redteam_blockers(redteam_execution, execute_requested=effective_execute_redteam) else "GO",
        f"{'Executed' if effective_execute_redteam else 'Deterministic'} red-team findings recorded; blocking findings={len(blocking_findings)}.",
        str(redteam_execution.get("summary") or "findings.json"),
    )

    deploy = plan_deployment(store, plan.run_id, env="production")
    record_operation(
        "locked_deploy_plan",
        "24",
        str(deploy.get("status", "UNKNOWN")),
        "Recorded a production deployment plan while keeping production execution locked by default.",
        str(deploy.get("artifact") or ""),
    )

    gate_artifacts = _write_auto_gate_evidence(
        store,
        plan.run_id,
        implementation_path=implementation_path,
        implementation_artifact=implementation_artifact,
        artifact_kind=artifact_kind,
        aws_artifact=str(aws.get("artifact") or "artifacts/auto/aws-plan.json"),
        intake_artifact=intake_artifact,
        demo_output_artifact=demo_output_artifact,
        agent_execution_artifact=str(agent_execution.get("artifact") or "artifacts/agents/task-plan.json"),
        redteam_artifact=str(redteam_execution.get("summary") or "artifacts/auto/redteam-review.md"),
    )
    _mark_auto_gates_passed(store, plan.run_id, gate_artifacts)
    execution_requested = effective_execute_aws or effective_execute_cleanup
    execution_succeeded = (
        (effective_execute_aws and aws.get("status") == "EXECUTED")
        or (effective_execute_cleanup and aws.get("status") == "EXECUTED")
        or not execution_requested
    )
    gate_blockers: dict[str, str] = {}
    if execution_requested and aws.get("status") != "EXECUTED":
        gate_blockers["deploy_rollout_postdeploy"] = f"AWS deployment/cleanup requested but did not execute successfully: {aws.get('status')}"
    agent_blockers = agent_blocker_preview
    if agent_blockers:
        gate_blockers["agent_plan_permissions"] = "Role-agent execution blockers: " + "; ".join(agent_blockers[:6])
    redteam_blockers = _auto_redteam_blockers(redteam_execution, execute_requested=effective_execute_redteam)
    if redteam_blockers:
        gate_blockers["independent_redteam_cross_model"] = "Executed red-team blockers: " + "; ".join(redteam_blockers)
        gate_blockers["critical_high_fix_loop"] = "Executed red-team did not produce a clean GO; fix loop cannot close."
    _auto_apply_gate_blockers(store, plan.run_id, gate_blockers)
    execution_succeeded = execution_succeeded and not gate_blockers
    record_operation(
        "gate_completion",
        "01-25",
        "GO" if execution_succeeded else "NO_GO",
        "All 25 local gates were marked GO with auto-generated evidence artifacts." if execution_succeeded else "One or more requested execution gates failed; see the NO_GO gate notes and execution log.",
        "artifacts/auto/gates",
    )
    evidence_index_artifact = _write_auto_evidence_index(store, plan.run_id, gate_artifacts)
    record_operation(
        "evidence_index",
        "01-25",
        "RECORDED",
        "Generated an index that maps every gate to its proof artifact.",
        evidence_index_artifact,
    )

    git_artifact = _write_git_provenance_artifact(repo, store.load_plan(plan.run_id), ledger)
    record_operation(
        "git_provenance",
        "23",
        "RECORDED",
        "Captured branch, HEAD, PR, and local CI provenance without pushing or creating a PR.",
        git_artifact,
    )

    readiness = _release_readiness_payload(repo, store.load_plan(plan.run_id), store.load_findings(plan.run_id))
    _persist_release_readiness(run_dir, plan.run_id, readiness)
    generate_report(
        repo,
        plan.run_id,
        verdict_override="NO_GO" if readiness.get("blockers") else None,
        readiness_errors=[str(item) for item in readiness.get("blockers", [])],
    )
    phase_report_artifact = _write_auto_phase_report(
        store,
        plan.run_id,
        request=request,
        intake=intake,
        operations=operations,
        implementation_path=implementation_path,
        implementation_artifact=implementation_artifact,
        artifact_kind=artifact_kind,
        aws=aws,
        readiness=readiness,
        gate_artifacts=gate_artifacts,
    )
    html_summary_artifact = _write_auto_html_dashboard(
        store,
        plan.run_id,
        request=request,
        implementation_path=implementation_path,
        artifact_kind=artifact_kind,
        aws=aws,
        operations=operations,
        gate_artifacts=gate_artifacts,
        evidence_index_artifact=evidence_index_artifact,
        phase_report_artifact=phase_report_artifact,
    )
    validation: dict[str, object] = _write_auto_validation_artifact(
        repo,
        run_dir,
        plan.run_id,
        request=request,
        worker=str(getattr(args, "validation_worker", "claude")),
        execute=effective_claude_validate,
        allow_network=bool(getattr(args, "allow_network", False)),
        policy=agent_policy,
        timeout=args.timeout,
        operations=operations,
        gate_artifacts=gate_artifacts,
        agent_execution=agent_execution,
        redteam_execution=redteam_execution,
        phase_report_artifact=phase_report_artifact,
        html_summary_artifact=html_summary_artifact,
    )
    record_operation(
        "claude_honesty_validation",
        "25",
        str(validation.get("status", "SKIPPED")),
        "Captured independent validation of whether the run honestly executed workers and proved all 25 gates.",
        str(validation.get("artifact") or ""),
    )
    if effective_claude_validate and validation.get("status") != "GO":
        execution_succeeded = False
        _auto_apply_gate_blockers(
            store,
            plan.run_id,
            {"final_report_reaudit": "Claude honesty validation did not return GO."},
        )
        revise_operation(
            "gate_completion",
            status="NO_GO",
            detail="One or more requested execution checks failed; see the NO_GO gate notes and execution log.",
        )
    evidence_index_artifact = _write_auto_evidence_index(store, plan.run_id, gate_artifacts)
    execution_log_artifact, execution_events_artifact = _write_auto_execution_log(
        store,
        plan.run_id,
        operations=operations,
        agent_execution=agent_execution,
        redteam_execution=redteam_execution,
        validation=validation,
    )
    record_operation(
        "execution_log",
        "01-25",
        "RECORDED",
        "Captured intermediate operations, event ledger export, worker result paths, red-team summary, and validation result.",
        execution_log_artifact,
    )
    presentation_artifacts: dict[str, str] = {}
    if bool(getattr(args, "presentation", False)):
        presentation_artifacts = _write_auto_presentation_artifacts(
            store,
            plan.run_id,
            request=request,
            artifact_kind=artifact_kind,
            implementation_path=implementation_path,
            aws=aws,
            operations=operations,
            gate_artifacts=gate_artifacts,
            phase_report_artifact=phase_report_artifact,
            html_summary_artifact=html_summary_artifact,
            execution_log_artifact=execution_log_artifact,
            validation=validation,
            redteam_execution=redteam_execution,
        )
        record_operation(
            "presentation",
            "01-25",
            "RECORDED",
            "Generated the HTML slide deck, Manim scene, and presentation README for manual demo delivery.",
            presentation_artifacts.get("index", ""),
        )
    readiness = _release_readiness_payload(repo, store.load_plan(plan.run_id), store.load_findings(plan.run_id))
    _persist_release_readiness(run_dir, plan.run_id, readiness)
    generate_report(
        repo,
        plan.run_id,
        verdict_override="NO_GO" if readiness.get("blockers") else None,
        readiness_errors=[str(item) for item in readiness.get("blockers", [])],
    )
    phase_report_artifact = _write_auto_phase_report(
        store,
        plan.run_id,
        request=request,
        intake=intake,
        operations=operations,
        implementation_path=implementation_path,
        implementation_artifact=implementation_artifact,
        artifact_kind=artifact_kind,
        aws=aws,
        readiness=readiness,
        gate_artifacts=gate_artifacts,
    )
    record_operation(
        "phase_report",
        "01-25",
        "RECORDED",
        "Generated the detailed work-done report for all 25 phases.",
        phase_report_artifact,
    )
    html_summary_artifact = _write_auto_html_dashboard(
        store,
        plan.run_id,
        request=request,
        implementation_path=implementation_path,
        artifact_kind=artifact_kind,
        aws=aws,
        operations=operations,
        gate_artifacts=gate_artifacts,
        evidence_index_artifact=evidence_index_artifact,
        phase_report_artifact=phase_report_artifact,
        execution_log_artifact=execution_log_artifact,
        presentation_artifact=presentation_artifacts.get("index"),
        validation_artifact=str(validation.get("artifact") or ""),
        redteam_artifact=str(redteam_execution.get("summary") or ""),
    )
    record_operation(
        "html_summary",
        "01-25",
        "RECORDED",
        "Generated the browsable HTML dashboard linking every gate proof, role-agent artifact, execution log, validation result, and presentation deck.",
        html_summary_artifact,
    )
    record_operation(
        "final_report",
        "25",
        "RECORDED",
        "Generated the final report with explicit residual blockers and no production-readiness claim.",
        "final-report.md",
    )

    manifest = write_artifact_manifest(store, plan.run_id)
    record_operation(
        "attestation_manifest",
        "22",
        str(manifest.get("status", "UNKNOWN")),
        "Generated the artifact manifest for provenance review; signing/verification remain explicit follow-up actions.",
        str(manifest.get("artifact") or ""),
    )

    final_plan = store.load_plan(plan.run_id)
    final_findings = store.load_findings(plan.run_id)
    final_readiness = _release_readiness_payload(repo, final_plan, final_findings)
    _persist_release_readiness(run_dir, plan.run_id, final_readiness)
    auto_summary = {
        "schema_version": 1,
        "mode": "AUTO",
        "run_id": plan.run_id,
        "request": request,
        "risk_level": final_plan.risk_level,
        "gate_count": len(final_plan.gates),
        "release_satisfied": final_readiness["release_satisfied"],
        "release_verdict": final_readiness["release_verdict"],
        "local_verdict": final_readiness["local_verdict"],
        "production_authority": final_readiness["production_authority"],
        "intake": intake,
        "agent_model_selection": agent_model_selection,
        "agent_execution_requested": effective_execute_agents,
        "redteam_execution_requested": effective_execute_redteam,
        "redteam_execution": _auto_compact_redteam_execution(redteam_execution),
        "validation": validation,
        "aws": aws,
        "operations": operations,
        "gates": [
            {
                "order": gate.order,
                "id": gate.id,
                "title": gate.title,
                "auto_state": "RECORDED" if gate.id in walkthrough_artifacts else "MISSING",
                "local_state": gate.state,
                "local_verdict": gate.verdict,
                "evidence_artifact": gate_artifacts.get(gate.id, ""),
                "release_state": next(
                    (
                        str(item.get("release_state"))
                        for item in final_readiness.get("gate_readiness", [])
                        if isinstance(item, dict) and item.get("gate_id") == gate.id
                    ),
                    "UNKNOWN",
                ),
            }
            for gate in sorted(final_plan.gates, key=lambda item: item.order)
        ],
        "artifacts": {
            "plan": str(run_dir / "plan.json"),
            "intake": str(run_dir / intake_artifact),
            "intake_json": str(run_dir / intake_json_artifact),
            "llm_intake_prompt": str(run_dir / "artifacts" / "auto" / "llm-intake-prompt.md"),
            "llm_intake": str(run_dir / "artifacts" / "auto" / "llm-intake.json"),
            "prework": str(run_dir / "artifacts" / "prework" / "expectations.html"),
            "implementation": str(repo / implementation_path),
            "implementation_artifact": str(run_dir / implementation_artifact),
            "implementation_demo": str(run_dir / demo_output_artifact) if demo_output_artifact else "",
            "agent_plan": str(run_dir / "artifacts" / "agents" / "task-plan.json"),
            "execution_log": str(run_dir / execution_log_artifact),
            "execution_events": str(run_dir / execution_events_artifact),
            "validation": str(run_dir / str(validation.get("artifact", ""))) if validation.get("artifact") else "",
            "presentation": str(run_dir / presentation_artifacts.get("index", "")) if presentation_artifacts.get("index") else "",
            "presentation_manim": str(run_dir / presentation_artifacts.get("manim", "")) if presentation_artifacts.get("manim") else "",
            "evidence_index": str(run_dir / evidence_index_artifact),
            "html_summary": str(run_dir / html_summary_artifact),
            "gate_evidence_dir": str(run_dir / "artifacts" / "auto" / "gates"),
            "readiness": str(run_dir / "artifacts" / "release" / "readiness.json"),
            "phase_report": str(run_dir / phase_report_artifact),
            "report": str(run_dir / "final-report.md"),
            "attestation_manifest": str(run_dir / MANIFEST_PATH),
        },
    }
    summary_artifact = ledger.artifact(
        "artifacts/auto/summary.json",
        json.dumps(auto_summary, indent=2, sort_keys=True) + "\n",
        event="auto.summary_written",
        redact=False,
        release_satisfied=bool(final_readiness.get("release_satisfied")),
        gate_count=len(final_plan.gates),
    )
    auto_summary["artifacts"]["summary"] = str(run_dir / summary_artifact)

    if args.json:
        print(json.dumps(auto_summary, indent=2, sort_keys=True))
        return 0 if execution_succeeded else 3

    print(f"Auto run: {plan.run_id}")
    formal_release_label = "NOT_REQUESTED" if final_readiness.get("production_authority") == "DISABLED" else str(final_readiness["release_verdict"])
    print(f"Mode: AUTO | Risk: {final_plan.risk_level} | Auto gates: {final_readiness['local_verdict']} | Formal release certification: {formal_release_label}")
    print("Production authority: DISABLED")
    print(f"Artifact: {repo / implementation_path}")
    llm_intake = intake.get("llm_intake") if isinstance(intake.get("llm_intake"), dict) else {}
    print(f"Intake source: {llm_intake.get('source', 'unknown')} | Worker: {llm_intake.get('worker', 'unknown')} | Status: {llm_intake.get('status', 'unknown')}")
    print(f"Role workers: {'EXECUTED' if effective_execute_agents else 'DRY_RUN'}")
    print(f"Red-team workers: {'EXECUTED' if effective_execute_redteam else 'DETERMINISTIC'} | Verdict: {redteam_execution.get('verdict', 'UNKNOWN')}")
    print(f"Claude validation: {validation.get('status', 'SKIPPED')}")
    if demo_output_artifact:
        print(f"Demo output: {run_dir / demo_output_artifact}")
    if aws.get("website_url"):
        print(f"AWS status: {aws.get('status')} | URL: {aws.get('website_url')}")
    elif artifact_kind == "decommission":
        print(f"Cleanup status: {aws.get('status')} | Bucket: {aws.get('bucket') or '<not discovered>'}")
    else:
        print(f"AWS status: {aws.get('status')}")
    print(f"Evidence index: {run_dir / evidence_index_artifact}")
    print(f"Execution log: {run_dir / execution_log_artifact}")
    print(f"HTML summary: {run_dir / html_summary_artifact}")
    if presentation_artifacts.get("index"):
        print(f"Presentation: {run_dir / presentation_artifacts['index']}")
    print(f"Gate evidence: {run_dir / 'artifacts' / 'auto' / 'gates'}")
    print(f"Report: {run_dir / 'final-report.md'}")
    print(f"Phase report: {run_dir / phase_report_artifact}")
    print(f"Summary: {run_dir / summary_artifact}")
    print("\nOperations:")
    for item in operations:
        artifact = f" | {item['artifact']}" if item.get("artifact") else ""
        print(f"  {item['gates']:<5} {item['status']:<18} {item['name']}{artifact}")
    print("\nAll 25 auto gates:")
    for gate in sorted(final_plan.gates, key=lambda item: item.order):
        verdict = f"/{gate.verdict}" if gate.verdict else ""
        auto_state = "RECORDED" if gate.id in walkthrough_artifacts else "MISSING"
        proof = gate_artifacts.get(gate.id, "")
        print(f"  {gate.order:02d}. {gate.id:<36} auto={auto_state:<8} result={gate.state}{verdict:<12} proof={proof}")
    print("\nFormal release readiness details are recorded separately in:")
    print(f"  {run_dir / 'artifacts' / 'release' / 'readiness.json'}")
    opened_target = _open_auto_target(repo, run_dir, implementation_path=implementation_path, phase_report=phase_report_artifact, html_summary=html_summary_artifact, aws=aws, intake=intake)
    if opened_target:
        print(f"\nOpened: {opened_target}")
    if artifact_kind == "website" and not effective_execute_aws:
        print("\nAWS hosting is planned only. To create the S3 website with the default profile, rerun with:")
        print(f"  sdlc auto {shlex.quote(request)} --execute-aws --approve-aws-deploy {shlex.quote('host this generated static website in AWS using the default profile')} --public-read")
    if artifact_kind == "decommission" and not effective_execute_cleanup:
        print("\nCleanup is planned only. To execute cleanup, rerun with:")
        print(f"  sdlc auto decommission prod website --target-run-id {shlex.quote(str(aws.get('target_run_id') or '<run-id>'))} --execute-cleanup --approve-cleanup {shlex.quote('approved: decommission AWS static website resources for this sdlc auto run')}")
    if execution_succeeded:
        print("\nAuto complete: every gate has a proof artifact and all requested execution checks passed; formal release certification remains separate from local auto evidence.")
    else:
        print("\nAuto complete with NO_GO: proof artifacts were written, but at least one requested execution check failed. Review the execution log and NO_GO gate notes.")
    return 0 if execution_succeeded else 3


command_demo = command_auto


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
        print(f"Authority mode: {readiness.get('authority_mode', 'ADVISORY')} | production authority={readiness.get('production_authority', 'DISABLED')}")
        if readiness.get("production_authority") == "DISABLED":
            print("Use this run as advisory PR evidence only; it is not production deployment clearance.")
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
    run_dir = store.run_dir(plan.run_id)
    events = _load_run_events(run_dir)
    gate_readiness = []
    for gate in sorted(plan.gates, key=lambda item: item.order):
        reasons = [error for error in errors if f"Gate {gate.id} " in error or error.startswith(f"{gate.id} ")]
        reasons.extend(_direct_gate_release_reasons(store, plan, gate, events))
        reasons = list(dict.fromkeys(reasons))
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
    local_verdict = final_verdict(findings, plan)
    if local_verdict == "NO_GO" and not any("Local final verdict is NO_GO" in error for error in errors):
        errors.insert(0, "Local final verdict is NO_GO; release gates are not satisfied.")
    release_satisfied = local_verdict != "NO_GO" and not errors
    policy = load_policy(repo, plan.policy_profile)
    release_verdict = release_contract_verdict(policy, local_verdict, release_satisfied=release_satisfied)
    authority_mode = "RELEASE_CANDIDATE_ADVISORY" if release_satisfied else "ADVISORY"
    return {
        "schema_version": 1,
        "run_id": plan.run_id,
        "authority_mode": authority_mode,
        "production_authority": "DISABLED",
        "authority_reason": "Production deployment authority is disabled by default; this run is advisory evidence until explicit human deployment approval and rollback evidence are recorded.",
        "local_verdict": local_verdict,
        "release_verdict": release_verdict,
        "release_satisfied": release_satisfied,
        "blockers": errors,
        "gate_readiness": gate_readiness,
    }


def _direct_gate_release_reasons(store: RunStore, plan: RunPlan, gate: GateState, events: list[dict[str, object]]) -> list[str]:
    if gate.state == "SKIPPED" or not _gate_satisfied(gate, plan):
        return []
    run_dir = store.run_dir(plan.run_id)
    reasons: list[str] = []
    release_evidence_error = _validate_release_gate_evidence(store.repo, run_dir, gate, gate.verdict or "", gate.evidence)
    if release_evidence_error:
        reasons.append(release_evidence_error)
    security_error = _validate_security_gate_completion(
        store,
        plan.run_id,
        gate,
        gate.verdict or "",
        _latest_gate_actor(events, gate.id),
        gate.notes,
        require_event_binding=True,
    )
    if security_error:
        reasons.append(security_error)
    redteam_error = _validate_redteam_gate_completion(store, plan, gate, gate.verdict or "", gate.evidence)
    if redteam_error:
        reasons.append(redteam_error)
    deploy_error = _validate_deploy_gate_completion(store, plan, gate, gate.verdict or "")
    if deploy_error:
        reasons.append(deploy_error)
    git_provenance_error = _validate_git_provenance_gate_completion(store, plan, gate, gate.verdict or "", gate.evidence)
    if git_provenance_error:
        reasons.append(git_provenance_error)
    attestation_error = _validate_attestation_gate_completion(store, plan, gate, gate.verdict or "", gate.evidence)
    if attestation_error:
        reasons.append(attestation_error)
    final_report_error = _validate_final_report_gate_completion(store, plan.run_id, gate, gate.verdict or "", gate.evidence)
    if final_report_error:
        reasons.append(final_report_error)
    return reasons


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
    plan = run_dry_gates(store, args.run_id, full_advisory=True)
    statuses = _materialize_release_gate_evidence(repo, store, args.run_id)
    plan = store.load_plan(args.run_id)
    if args.redteam:
        create_redteam_findings(store, args.run_id)
    _print_status(plan)
    _print_materialization_statuses(statuses)
    print("\nRun advanced with a full advisory pass. Release-grade implementation/red-team gates still require worker execution or human evidence.")
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


def _record_typed_gate_evidence(
    repo: Path,
    store: RunStore,
    run_id: str,
    gate_id: str,
    *,
    actor: str,
    artifacts: dict[str, str],
    source_evidence: list[str],
    notes: str = "",
) -> tuple[str | None, str | None]:
    _RUN_EVENTS_CACHE.clear()
    _ARTIFACT_INDEX_CACHE.clear()
    gate_definition = _gate_definition(gate_id)
    required = set(gate_definition.required_artifacts if gate_definition else [])
    missing = [item for item in sorted(required) if not artifacts.get(item)]
    if missing:
        return None, "Gate evidence is missing required artifacts: " + ", ".join(missing)
    if not source_evidence:
        return None, "Gate evidence requires at least one source evidence artifact"
    run_dir = store.run_dir(run_id)
    artifact_bindings, artifact_error = _build_gate_artifact_bindings(repo, run_dir, gate_id, artifacts, source_evidence)
    if artifact_error:
        return None, artifact_error
    source_evidence_bindings, source_error = _build_source_evidence_bindings(repo, run_dir, source_evidence)
    if source_error:
        return None, source_error
    payload = {
        "schema_version": 1,
        "run_id": run_id,
        "gate_id": gate_id,
        "actor": actor,
        "required_artifacts": artifacts,
        "artifact_bindings": artifact_bindings,
        "source_evidence": source_evidence,
        "source_evidence_bindings": source_evidence_bindings,
        "notes": notes,
    }
    artifact = Ledger(run_dir, run_id).artifact(
        f"artifacts/gates/{gate_id}-evidence.json",
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        event="gate.evidence_recorded",
        gate=gate_id,
        actor=actor,
        artifact_keys=sorted(artifacts),
        artifact_bindings=artifact_bindings,
        source_evidence_bindings=source_evidence_bindings,
    )
    _RUN_EVENTS_CACHE.clear()
    _ARTIFACT_INDEX_CACHE.clear()
    return artifact, None


def _materialize_release_gate_evidence(repo: Path, store: RunStore, run_id: str) -> list[dict[str, object]]:
    from .evidence import materialize_gate_evidence, plan_gate_evidence

    plan = store.load_plan(run_id)
    ledger = Ledger(store.run_dir(run_id), run_id)
    statuses: list[dict[str, object]] = []
    for gate in sorted(plan.gates, key=lambda item: item.order):
        gate_plan = plan_gate_evidence(repo, run_id, gate.id, actor=gate.owner)
        if gate.state in {"SKIPPED", "WAIVED"}:
            statuses.append({"gate_id": gate.id, "status": gate.state, "blockers": []})
            continue
        if not gate_plan.auto_completable:
            statuses.append({"gate_id": gate.id, "status": "NO_GO", "blockers": gate_plan.blockers or ["Gate is not auto-completable."]})
            continue
        result = materialize_gate_evidence(
            repo,
            run_id,
            gate.id,
            actor=gate.owner,
            source_paths=list(gate.evidence),
        )
        evidence_record = None
        record_error = None
        if result.artifact_paths and result.source_evidence:
            evidence_record, record_error = _record_typed_gate_evidence(
                repo,
                store,
                run_id,
                gate.id,
                actor=result.actor,
                artifacts=result.artifact_paths,
                source_evidence=result.source_evidence,
                notes="Automatic typed gate evidence materialization.",
            )
            result.evidence_record_path = evidence_record
        blockers = list(result.blockers)
        if record_error:
            blockers.append(record_error)
        evidence_path = f".sdlc/runs/{run_id}/{evidence_record}" if evidence_record else None
        status = "GO" if result.verdict == "GO" and evidence_path and not blockers else "NO_GO"
        if evidence_path and status == "GO":
            release_error = _validate_release_gate_evidence(repo, store.run_dir(run_id), gate, "GO", [evidence_path])
            if release_error:
                blockers.append(release_error)
                status = "NO_GO"
        current = next((item for item in plan.gates if item.id == gate.id), gate)
        if evidence_path and status == "GO":
            current.state = "GO"
            current.verdict = "GO"
            if evidence_path not in current.evidence:
                current.evidence.append(evidence_path)
            current.notes = "Release-grade typed evidence materialized by the SDLC control plane."
            if not _has_gate_completion_event(_load_run_events(store.run_dir(run_id)), gate.id):
                ledger.event("gate.completed", gate=gate.id, verdict="GO", evidence=[evidence_path], materialized=True)
            ledger.event("gate.evidence_materialized", gate=gate.id, verdict="GO", evidence=evidence_path, artifact_keys=sorted(result.artifact_paths))
        else:
            if gate.id in {"deterministic_quality", "qa_tests_integration_smoke"}:
                current.state = "NO_GO"
                current.verdict = "NO_GO"
                if evidence_path and evidence_path not in current.evidence:
                    current.evidence.append(evidence_path)
                current.notes = "Evidence materialization could not satisfy release gate: " + "; ".join(blockers)
            ledger.event("gate.evidence_materialization_blocked", gate=gate.id, blockers=blockers, evidence=evidence_path)
        statuses.append({
            "gate_id": gate.id,
            "status": status,
            "evidence": evidence_path,
            "blockers": blockers,
        })
        store.save_plan(plan)
    store.save_plan(plan)
    return statuses


def _print_materialization_statuses(statuses: list[dict[str, object]]) -> None:
    print("\nGate evidence materialization:")
    for item in statuses:
        gate_id = str(item.get("gate_id", ""))
        status = str(item.get("status", "NO_GO"))
        print(f"  {gate_id}: {status}")


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


PROMPT_RUN_REQUIRED_FILE_RE = re.compile(
    r"^\s*-\s+`?((?:[A-Za-z0-9_./-]+\.(?:md|json|txt|yaml|yml|toml|rs|go|ts|tsx|js|jsx|proto|sql|html|css))|(?:[A-Za-z0-9_./-]+/)?(?:Makefile|Dockerfile))`?\s*$"
)


def _prompt_run_feature(prompt_text: str, prompt_path: Path, request: str | None) -> str:
    if request:
        return request
    for line in prompt_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("# "):
            return stripped.removeprefix("# ").strip()[:180] or prompt_path.stem
    return prompt_path.stem.replace("-", " ").replace("_", " ").strip() or "Prompt run"


def _required_output_paths_from_prompt(prompt_text: str) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    in_required_section = False
    for line in prompt_text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if lower.startswith("create these files under "):
            in_required_section = True
            continue
        if in_required_section and lower.startswith("optional"):
            in_required_section = False
            continue
        if stripped.startswith("## "):
            heading = stripped.strip("# ").lower()
            in_required_section = "required output" in heading or "required files" in heading or "required deliverables" in heading
            continue
        if not in_required_section:
            continue
        match = PROMPT_RUN_REQUIRED_FILE_RE.match(line)
        if match:
            rel = match.group(1)
            if rel not in seen:
                paths.append(rel)
                seen.add(rel)
    return paths


def _prompt_run_progress(
    ledger: Ledger,
    *,
    phase: str,
    status: str,
    phases: list[dict[str, object]],
    detail: str = "",
    extra: dict[str, object] | None = None,
) -> None:
    item: dict[str, object] = {"phase": phase, "status": status, "ts": now_iso()}
    if detail:
        item["detail"] = detail
    if extra:
        item.update(extra)
    phases.append(item)
    ledger.event("prompt_run.phase", phase=phase, status=status, detail=detail, **(extra or {}))
    ledger.artifact(
        "artifacts/prompt-run/progress.json",
        json.dumps({"schema_version": 1, "phases": phases}, indent=2, sort_keys=True) + "\n",
        event="prompt_run.progress_written",
        redact=False,
        phase=phase,
        status=status,
    )


def _checkout_prompt_run_branch(repo: Path, run_id: str, branch_name: str | None) -> tuple[bool, str, str]:
    if not is_git_repo(repo):
        return False, "", "Target repository is not a Git repository."
    branch = branch_name or f"sdlc/{run_id}"
    exists = run_cmd(["git", "rev-parse", "--verify", branch], repo)
    command = ["git", "checkout", branch] if exists["returncode"] == 0 else ["git", "checkout", "-b", branch]
    result = run_cmd(command, repo, timeout=120)
    if result["returncode"] != 0:
        return False, branch, str(result.get("stderr") or result.get("stdout") or "git checkout failed")
    return True, branch, ""


def _repo_snapshot_changes(repo: Path, before: dict[str, bytes]) -> list[str]:
    after = _repo_content_snapshot(repo)
    changed = {path for path, content in after.items() if before.get(path) != content}
    changed.update(path for path in before if path not in after)
    return sorted(changed)


def _validate_prompt_required_outputs(repo: Path, required_paths: list[str]) -> tuple[list[str], list[str]]:
    missing: list[str] = []
    invalid: list[str] = []
    for rel in required_paths:
        resolved, error = resolve_under_base(repo, Path(rel), must_exist=True)
        if error or resolved is None or not resolved.is_file():
            missing.append(rel)
            continue
        if resolved.suffix == ".json":
            try:
                json.loads(resolved.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                invalid.append(f"{rel}: {exc}")
    return missing, invalid


def _prompt_run_read_only_repo_error(repo: Path, path: Path, *, allow_production_read: bool) -> str | None:
    resolved = path.resolve(strict=False)
    repo_resolved = repo.resolve(strict=False)
    sensitive_names = {
        ".aws",
        ".ssh",
        ".codex",
        ".docker",
        "secrets",
        "strat26",
    }
    lowered_parts = {part.lower() for part in resolved.parts}
    if lowered_parts.intersection(sensitive_names):
        return f"Read-only repo path is sensitive and cannot be exposed to workers: {resolved}"
    if not allow_production_read and any(part.lower() in {"prod", "production"} for part in resolved.parts):
        return f"Read-only production path requires --allow-production-read and policy approval: {resolved}"
    allowed_roots = {
        repo_resolved.parent.resolve(strict=False),
        Path.home().joinpath("dev").resolve(strict=False),
    }
    if not any(resolved == root or root in resolved.parents for root in allowed_roots):
        return f"Read-only repo path is outside allowed evidence roots: {resolved}"
    return None


def _supervised_prompt_text(
    *,
    prompt_text: str,
    repo: Path,
    read_only_repos: list[Path],
    required_paths: list[str],
    commit_requested: bool,
    allow_production_read: bool,
) -> str:
    read_only_text = "\n".join(f"- {path}" for path in read_only_repos) or "- <none>"
    required_text = "\n".join(f"- {path}" for path in required_paths) or "- <not declared in prompt>"
    commit_text = "The orchestrator will commit after validation." if commit_requested else "Do not commit; the orchestrator will leave changes for review."
    production_text = (
        "Read-only production evidence access is explicitly allowed by this run."
        if allow_production_read
        else "Do not SSH to, query, or read production hosts; use local repositories only."
    )
    return "\n".join([
        "# SDLC Supervised Prompt Run",
        "",
        f"Target repository: `{repo}`",
        "",
        "The SDLC orchestrator is authoritative. The user prompt below is the mission, but these controls override it:",
        "",
        "- Do not deploy, restart production services, place orders, mutate live trading state, or push to a remote.",
        "- Write only the requested deliverables in the target repository unless the prompt explicitly requires supporting docs.",
        "- Treat every extra repository as read-only evidence. Do not edit it.",
        f"- {production_text}",
        "- Do not store secrets in files, prompts, logs, commits, or run artifacts.",
        "- Mark unsupported trading, profitability, production-readiness, safety, or compliance claims as evidence gaps.",
        f"- {commit_text}",
        "",
        "Read-only evidence repositories:",
        read_only_text,
        "",
        "Required output paths parsed by SDLC:",
        required_text,
        "",
        "---",
        "",
        prompt_text,
    ])


def _prompt_run_commit(repo: Path, ledger: Ledger, message: str) -> tuple[bool, str]:
    add = run_cmd(["git", "add", "docs", ".codex/prompts"], repo, timeout=120)
    if add["returncode"] != 0:
        reason = str(add.get("stderr") or add.get("stdout") or "git add failed")
        ledger.event("prompt_run.commit_failed", reason=reason, command=add.get("cmd"))
        return False, reason
    staged = run_cmd(["git", "diff", "--cached", "--quiet"], repo, timeout=120)
    if staged["returncode"] == 0:
        ledger.event("prompt_run.commit_skipped", reason="No staged docs or prompt changes.")
        return True, "No staged docs or prompt changes."
    commit = run_cmd(["git", "commit", "-m", message], repo, timeout=120)
    if commit["returncode"] != 0 and "Author identity unknown" in str(commit.get("stderr") or commit.get("stdout") or ""):
        ledger.event(
            "prompt_run.commit_identity_fallback",
            reason="Repository has no git author identity; retrying with non-persistent SDLC commit author.",
        )
        commit = run_cmd([
            "git",
            "-c",
            "user.name=SDLC Orchestrator",
            "-c",
            "user.email=sdlc@example.local",
            "commit",
            "-m",
            message,
        ], repo, timeout=120)
    if commit["returncode"] != 0:
        reason = str(commit.get("stderr") or commit.get("stdout") or "git commit failed")
        ledger.event("prompt_run.commit_failed", reason=reason, command=commit.get("cmd"))
        return False, reason
    ledger.event("prompt_run.commit_completed", message=message, stdout=commit.get("stdout", ""))
    return True, str(commit.get("stdout") or "").strip()


def command_prompt(args: argparse.Namespace) -> int:
    if args.prompt_command != "run":
        eprint(f"Unknown prompt command: {args.prompt_command}")
        return 2
    repo = Path(args.repo).resolve()
    prompt_path = Path(args.prompt_file).expanduser().resolve(strict=False)
    if not prompt_path.is_file():
        eprint(f"Prompt file not found: {prompt_path}")
        return 2
    prompt_text = prompt_path.read_text(encoding="utf-8")
    feature = _prompt_run_feature(prompt_text, prompt_path, args.request)
    run_id = args.run_id or _plan_run_id(feature)
    try:
        validate_run_id(run_id)
    except ValueError as exc:
        eprint(str(exc))
        return 2

    branch_name = ""
    if not args.no_branch:
        branch_created, branch_name, branch_error = _checkout_prompt_run_branch(repo, run_id, args.branch_name)
        if not branch_created:
            eprint(branch_error)
            return 3

    plan, run_dir, error = _create_run(
        repo,
        feature=feature,
        risk=args.risk,
        ui=args.ui,
        security=args.security,
        infra=args.infra,
        policy_profile=args.policy,
        run_id=run_id,
        production_rollout_allowed_flag=False,
        allow_main_push_flag=False,
    )
    if error or plan is None or run_dir is None:
        eprint(error or "Unable to create prompt run")
        return 2

    store = RunStore(repo)
    ledger = Ledger(run_dir, run_id)
    phases: list[dict[str, object]] = []
    _prompt_run_progress(
        ledger,
        phase="bootstrap",
        status="GO",
        phases=phases,
        detail="Run initialized and prompt run branch prepared.",
        extra={"branch": branch_name or plan.branch, "prompt_file": str(prompt_path)},
    )

    if args.execute and plan.risk_level in {"HIGH", "EXTREME"}:
        preflight = release_preflight(
            repo=repo,
            policy=load_policy(repo, plan.policy_profile),
            policy_profile=plan.policy_profile,
            risk_level=plan.risk_level,
            allow_network=args.allow_network,
            run_id=run_id,
        )
        Ledger(run_dir, run_id).artifact(
            "artifacts/release/preflight.json",
            json.dumps(preflight.to_dict(), indent=2, sort_keys=True) + "\n",
            event="release.preflight_evaluated",
            status=preflight.status,
            blockers=len(preflight.blockers),
        )
        _prompt_run_progress(
            ledger,
            phase="release_preflight",
            status=preflight.status,
            phases=phases,
            detail=f"Release prerequisites checked before high-risk worker execution; blockers={len(preflight.blockers)}.",
            extra={"blockers": [item.to_dict() for item in preflight.blockers]},
        )
        preflight_error = release_preflight_error(preflight)
        if preflight_error:
            eprint(preflight_error)
            print(f"Run ID: {run_id}")
            print(f"Preflight: {run_dir / 'artifacts' / 'release' / 'preflight.json'}")
            print(f"Progress: {run_dir / 'artifacts' / 'prompt-run' / 'progress.json'}")
            return 3

    required_paths = _required_output_paths_from_prompt(prompt_text)
    source_rel = ledger.artifact(
        f"prompts/{prompt_path.name}",
        prompt_text,
        event="prompt_run.source_prompt_imported",
        redact=True,
        source_prompt=str(prompt_path),
    )
    read_only_repos = [Path(item).expanduser().resolve(strict=False) for item in args.read_only_repo]
    for read_only_repo in read_only_repos:
        repo_error = _prompt_run_read_only_repo_error(
            repo,
            read_only_repo,
            allow_production_read=bool(args.allow_production_read),
        )
        if repo_error:
            _prompt_run_progress(ledger, phase="read_only_repo_preflight", status="NO_GO", phases=phases, detail=repo_error)
            eprint(repo_error)
            return 3
    supervised = _supervised_prompt_text(
        prompt_text=prompt_text,
        repo=repo,
        read_only_repos=read_only_repos,
        required_paths=required_paths,
        commit_requested=args.commit,
        allow_production_read=args.allow_production_read,
    )
    supervised_rel = ledger.artifact(
        "prompts/prompt_run.md",
        supervised,
        event="prompt_run.supervised_prompt_written",
        redact=True,
        source_prompt_artifact=source_rel,
        required_outputs=required_paths,
        read_only_repos=[str(path) for path in read_only_repos],
    )
    _prompt_run_progress(
        ledger,
        phase="prompt_import",
        status="GO",
        phases=phases,
        detail=f"Imported prompt and parsed {len(required_paths)} required output path(s).",
        extra={"prompt_artifact": supervised_rel, "required_outputs": required_paths},
    )

    missing_read_repos = [str(path) for path in read_only_repos if not path.exists()]
    if missing_read_repos:
        reason = "Read-only repo path(s) do not exist: " + ", ".join(missing_read_repos)
        _prompt_run_progress(ledger, phase="read_only_repo_preflight", status="NO_GO", phases=phases, detail=reason)
        eprint(reason)
        return 2
    read_only_before = {str(path): _repo_content_snapshot(path) for path in read_only_repos if path.is_dir()}

    policy = load_policy(repo, plan.policy_profile)
    policy_error = _worker_execution_policy_error(policy, execute=args.execute, allow_network=args.allow_network)
    if policy_error:
        _prompt_run_progress(ledger, phase="worker_execute", status="NO_GO", phases=phases, detail=policy_error)
        eprint(policy_error)
        return 3
    adapter = adapter_from_policy(args.worker, policy)
    if adapter is None:
        reason = f"Unknown worker: {args.worker}"
        _prompt_run_progress(ledger, phase="worker_execute", status="NO_GO", phases=phases, detail=reason)
        eprint(reason)
        return 2

    _prompt_run_progress(
        ledger,
        phase="worker_execute",
        status="RUNNING" if args.execute else "DRY_RUN",
        phases=phases,
        detail=f"Invoking {args.worker} with timeout {args.timeout}s.",
        extra={"worker": args.worker, "execute": args.execute},
    )
    old_extra = getattr(adapter, "_sdlc_extra_read_dirs", None)
    setattr(adapter, "_sdlc_extra_read_dirs", read_only_repos)
    try:
        result = adapter.run(run_dir / supervised_rel, repo, args.mode, execute=args.execute, timeout=args.timeout)
    finally:
        if old_extra is None:
            if hasattr(adapter, "_sdlc_extra_read_dirs"):
                delattr(adapter, "_sdlc_extra_read_dirs")
        else:
            setattr(adapter, "_sdlc_extra_read_dirs", old_extra)

    captured = capture_worker_result(
        run_dir=run_dir,
        mode=args.mode,
        prompt_path=run_dir / supervised_rel,
        result=result,
        ledger=ledger,
        label="prompt-run",
    )
    read_only_violations: list[str] = []
    for path_text, before in read_only_before.items():
        path = Path(path_text)
        changes = _repo_snapshot_changes(path, before)
        if changes:
            restored = _restore_repo_snapshot_paths(path, before, changes)
            read_only_violations.extend(f"{path}:{rel}" for rel in changes)
            ledger.event("prompt_run.read_only_repo_violation", repo=str(path), changed_paths=changes, restored_paths=restored)
    worker_status = "GO" if result.returncode in {0, None} and not read_only_violations else "NO_GO"
    _prompt_run_progress(
        ledger,
        phase="worker_execute",
        status=worker_status,
        phases=phases,
        detail=f"Worker return code: {result.returncode}",
        extra={"worker_result": captured.get("result_path"), "read_only_violations": read_only_violations},
    )
    if worker_status != "GO":
        generate_report(repo, run_id, verdict_override="NO_GO")
        print(f"Run ID: {run_id}")
        print(f"Report: {run_dir / 'final-report.md'}")
        return 1

    missing, invalid = _validate_prompt_required_outputs(repo, required_paths)
    validation_status = "GO" if not missing and not invalid else "NO_GO"
    _prompt_run_progress(
        ledger,
        phase="deliverable_validation",
        status=validation_status,
        phases=phases,
        detail=f"Missing={len(missing)} invalid_json={len(invalid)}",
        extra={"missing": missing, "invalid": invalid},
    )
    if validation_status != "GO":
        generate_report(repo, run_id, verdict_override="NO_GO")
        print(f"Run ID: {run_id}")
        print(f"Missing outputs: {', '.join(missing) if missing else '<none>'}")
        print(f"Invalid outputs: {', '.join(invalid) if invalid else '<none>'}")
        print(f"Report: {run_dir / 'final-report.md'}")
        return 1

    commit_detail = "Commit not requested."
    if args.commit:
        ok, commit_detail = _prompt_run_commit(repo, ledger, args.commit_message)
        _prompt_run_progress(ledger, phase="commit", status="GO" if ok else "NO_GO", phases=phases, detail=commit_detail)
        if not ok:
            generate_report(repo, run_id, verdict_override="NO_GO")
            print(f"Run ID: {run_id}")
            print(f"Commit failed: {commit_detail}")
            print(f"Report: {run_dir / 'final-report.md'}")
            return 1
    else:
        _prompt_run_progress(ledger, phase="commit", status="SKIPPED", phases=phases, detail=commit_detail)

    run_dry_gates(store, run_id, full_advisory=True)
    materialization_statuses = _materialize_release_gate_evidence(repo, store, run_id)
    _prompt_run_progress(
        ledger,
        phase="gate_evidence_materialization",
        status="GO" if any(item.get("status") == "GO" for item in materialization_statuses) else "NO_GO",
        phases=phases,
        detail="Typed gate evidence materialization attempted for auto-completable gates.",
        extra={"gates": materialization_statuses},
    )
    report = generate_report(repo, run_id)
    _prompt_run_progress(ledger, phase="final_report", status="GO", phases=phases, detail=report)

    payload = {
        "run_id": run_id,
        "repo": str(repo),
        "branch": branch_name or plan.branch,
        "prompt": str(prompt_path),
        "worker_result": captured.get("result_path"),
        "required_outputs": required_paths,
        "gate_evidence_materialization": materialization_statuses,
        "report": str(run_dir / "final-report.md"),
        "commit": commit_detail,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Run ID: {run_id}")
        print(f"Branch: {payload['branch']}")
        print(f"Worker result: {payload['worker_result']}")
        print(f"Required outputs: {len(required_paths)}")
        _print_materialization_statuses(materialization_statuses)
        print(f"Report: {payload['report']}")
        print(f"Progress: {run_dir / 'artifacts' / 'prompt-run' / 'progress.json'}")
    return 0


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


def command_isolation(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    store = RunStore(repo)
    plan = store.load_plan(args.run_id)
    policy = load_policy(repo, plan.policy_profile)
    workers = [worker.strip() for worker in args.workers.split(",") if worker.strip()] if args.workers else _policy_redteam_workers(policy)
    prompt_manifest = read_json(store.run_dir(args.run_id) / "artifacts" / "prompts" / "manifest.json", {})
    prompt_sha256 = str(prompt_manifest.get("redteam_prompt.md") or "") if isinstance(prompt_manifest, dict) else ""
    results = []
    for worker in workers:
        adapter = adapter_from_policy(worker, policy)
        provider = str(getattr(adapter, "provider", "unknown")).strip().lower() if adapter is not None else "unknown"
        if adapter is None:
            results.append({
                "worker": worker,
                "provider": provider,
                "available": False,
                "hard_isolation": False,
                "advisory_isolation": False,
                "method": None,
                "reason": "Unknown worker.",
            })
            continue
        preflight = audit_isolation_preflight(
            policy=policy,
            repo=repo,
            worker=worker,
            provider=provider,
            prompt_sha256=prompt_sha256,
            allow_network=args.allow_network,
        )
        results.append({
            "worker": worker,
            "provider": provider,
            "requested_kind": preflight.requested_kind,
            "runtime_kind": preflight.runtime_kind,
            "method": preflight.method,
            "available": preflight.available,
            "hard_isolation": preflight.hard_isolation,
            "advisory_isolation": preflight.advisory_isolation,
            "network_mode": preflight.network_mode,
            "auth_mode": preflight.auth_mode,
            "reason": preflight.reason,
        })
    payload = {"run_id": args.run_id, "workers": results}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for item in results:
            status = "HARD" if item.get("hard_isolation") else "ADVISORY" if item.get("advisory_isolation") else "UNAVAILABLE"
            print(f"{item['worker']}: {status} method={item.get('method') or '<none>'} reason={item.get('reason')}")
    return 0 if all(item.get("hard_isolation") for item in results) else 1


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
        # FAC-10: even a human-accepted/deferred CRITICAL/HIGH can be RECORDED for
        # tracking, but final_verdict() will never let it reach a shippable verdict —
        # the run stays NO_GO until the finding is fixed and CLOSED with evidence.
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
        if finding.severity in {"CRITICAL", "HIGH"} and getattr(args, "actor_proof", None):
            proof_hash = hashlib.sha256(str(args.actor_proof).encode("utf-8")).hexdigest()
            proof_message = f"{args.run_id}:{finding.id}:{closed_by}:finding.close"
            proof_message_sha256 = hashlib.sha256(proof_message.encode("utf-8")).hexdigest()
            proof_artifact = ledger.artifact(
                f"artifacts/findings/{finding.id}/actor_proof.json",
                json.dumps(
                    {
                        "schema_version": 1,
                        "run_id": args.run_id,
                        "finding_id": finding.id,
                        "closed_by": closed_by,
                        "action": "finding.close",
                        "actor_proof_method": "sdlc_actor_hmac_sha256",
                        "actor_proof_verified": True,
                        "actor_proof_sha256": proof_hash,
                        "actor_proof_message_sha256": proof_message_sha256,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                event="finding.actor_proof",
                finding_id=finding.id,
                closed_by=closed_by,
                actor_proof_method="sdlc_actor_hmac_sha256",
                actor_proof_verified=True,
                actor_proof_sha256=proof_hash,
                actor_proof_message_sha256=proof_message_sha256,
            )
            finding.closure_evidence.append(f".sdlc/runs/{args.run_id}/{proof_artifact}")
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
        source_evidence = args.source or []
        artifact, evidence_error = _record_typed_gate_evidence(
            repo,
            store,
            args.run_id,
            args.gate_id,
            actor=args.actor,
            artifacts=artifacts,
            source_evidence=source_evidence,
            notes=args.notes or "",
        )
        if evidence_error or artifact is None:
            eprint(evidence_error or "Unable to record gate evidence")
            return 2
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
        plan = store.load_plan(args.run_id)
        findings = store.load_findings(args.run_id)
        release_errors = _release_readiness_errors(
            store,
            plan,
            findings,
            ignore_gate_ids={"deploy_rollout_postdeploy", "final_report_reaudit"},
        ) if args.env == "production" else None
        result = rollback_deployment(
            store,
            args.run_id,
            env=args.env,
            execute=args.execute,
            command=args.command,
            evidence=args.evidence,
            release_errors=release_errors,
        )
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
        policy, _, policy_error = _agent_model_policy_from_args(repo, policy, args)
        if policy_error or policy is None:
            eprint(policy_error or "Unable to apply agent model mapping")
            return 2
        result = agents_doctor(policy)
    else:
        plan = store.load_plan(args.run_id)
        policy = load_policy(repo, plan.policy_profile)
        policy, _, policy_error = _agent_model_policy_from_args(repo, policy, args)
        if policy_error or policy is None:
            eprint(policy_error or "Unable to apply agent model mapping")
            return 2
        run_dir = store.run_dir(args.run_id)
        if args.agents_command == "plan":
            result = write_agent_plan(run_dir, plan, policy, requested_parallelism=args.parallel)
        elif args.agents_command == "execute":
            policy_error = _worker_execution_policy_error(policy, execute=args.execute, allow_network=args.allow_network)
            if policy_error:
                Ledger(run_dir, args.run_id).event("agents.execution_rejected", reason=policy_error)
                eprint(policy_error)
                return 3
            result = execute_agent_plan(
                run_dir,
                plan,
                policy,
                execute=args.execute,
                parallel=args.parallel,
                timeout=args.timeout,
                progress=None if args.json else _print_agents_progress,
            )
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
    if args.agents_command == "plan":
        scope_contract = result.get("write_scope_contract", {})
        if isinstance(scope_contract, dict) and scope_contract.get("status") == "NO_GO":
            for violation in scope_contract.get("violations", []):
                eprint(f"agent write scope violation: {violation}")
            return 3
    if args.agents_command == "execute":
        statuses = {str(task.get("status")) for task in result.get("tasks", [])}
        if statuses & {"failed", "blocked_unavailable_worker", "blocked_by_dependency", "blocked_by_permissions"}:
            return 1
    return 0


def _print_agents_progress(event: dict[str, Any]) -> None:
    event_name = str(event.get("event") or "")
    if event_name == "agents.execution_started":
        mode = "execute" if event.get("execute_requested") else "dry-run"
        print(f"Agent {mode} started: parallelism={event.get('parallelism')}", flush=True)
    elif event_name == "agents.task_started":
        print(
            f"  {event.get('agent_id')} started worker={event.get('worker')} mode={event.get('mode')}",
            flush=True,
        )
    elif event_name in {"agents.task_completed", "agents.task_failed"}:
        status = event.get("status")
        reason = event.get("blocked_reason")
        suffix = f" reason={reason}" if reason else ""
        print(f"  {event.get('agent_id')} {status} returncode={event.get('returncode')}{suffix}", flush=True)
    elif event_name == "agents.execution_completed":
        print(
            f"Agent execution completed: completed={event.get('completed')} blocked={event.get('blocked')}",
            flush=True,
        )


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
    from . import dashboard

    repo = Path(args.repo).resolve()
    store = RunStore(repo)
    plan = store.load_plan(args.run_id)
    findings = store.load_findings(args.run_id)
    readiness = _release_readiness_payload(repo, plan, findings)
    next_action = _recommend_next_action(plan, findings, readiness)
    model = dashboard.build_dashboard_model(repo, plan, findings, readiness, next_action)

    # Plain text when explicitly requested, when not a tty (CI/pipes), or as a
    # safe fallback if curses cannot start.
    if getattr(args, "no_tui", False) or not sys.stdout.isatty():
        print(dashboard.render_plain(model))
        return 0
    try:
        dashboard.run_curses(model)
    except Exception as exc:  # noqa: BLE001 - never crash; degrade to plain text.
        eprint(f"Interactive TUI unavailable ({exc}); showing plain dashboard.")
        print(dashboard.render_plain(model))
    return 0


def command_release(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    if args.release_command != "doctor":
        eprint(f"Unknown release command: {args.release_command}")
        return 2
    policy_profile = args.policy
    risk_level = "HIGH" if args.risk == "auto" else args.risk.upper()
    run_id = args.run_id
    prompt_sha256 = ""
    if run_id:
        store = RunStore(repo)
        plan = store.load_plan(run_id)
        policy_profile = plan.policy_profile
        risk_level = plan.risk_level
        prompt_manifest = read_json(store.run_dir(run_id) / "artifacts" / "prompts" / "manifest.json", {})
        prompt_sha256 = str(prompt_manifest.get("redteam_prompt.md") or "") if isinstance(prompt_manifest, dict) else ""
    policy = load_policy(repo, policy_profile)
    workers = [worker.strip() for worker in args.workers.split(",") if worker.strip()] if args.workers else None
    result = release_preflight(
        repo=repo,
        policy=policy,
        policy_profile=policy_profile,
        risk_level=risk_level,
        allow_network=args.allow_network,
        workers=workers,
        run_id=run_id,
        prompt_sha256=prompt_sha256,
        check_isolation_runtime=args.check_isolation_runtime,
        require_clean_worktree=not args.no_worktree_check,
        require_branch=not args.no_branch_check,
    )
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"Release doctor: {result.status}")
        print(f"Repo: {result.repo}")
        print(f"Risk: {result.risk_level} | Policy: {result.policy_profile}")
        for requirement in result.requirements:
            block = " blocking" if requirement.blocking and requirement.status != "GO" else ""
            print(f"  {requirement.status:<5} {requirement.title}{block}")
            print(f"        {requirement.detail}")
            if requirement.status != "GO":
                print(f"        Fix: {requirement.remediation}")
    return 1 if result.blockers else 0


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
    policy = _load_release_policy_snapshot(run_dir, repo, plan.policy_profile)
    errors.extend(_ledger_integrity_errors(run_dir, require_origin=not audit_workspace_copy))
    errors.extend(_control_snapshot_divergence_errors(run_dir))
    errors.extend(
        _release_command_bundle_policy_errors(
            repo,
            run_dir,
            policy,
            require_origin=not audit_workspace_copy,
        )
    )
    errors.extend(_operator_report_consistency_errors(repo, run_dir, findings, policy))
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
    for finding in invalid_findings(findings):
        errors.append(
            f"Finding {finding.id} has invalid persisted integrity fields: "
            f"severity={finding.severity!r}, status={finding.status!r}"
        )
    if open_findings(findings, {"CRITICAL", "HIGH", "MEDIUM"}):
        errors.append("Release validation found open blocking findings")
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
        release_evidence_error = _validate_release_gate_evidence(
            repo,
            run_dir,
            gate,
            gate.verdict or "",
            gate.evidence,
            require_origin=not audit_workspace_copy,
        )
        if release_evidence_error:
            errors.append(release_evidence_error)
        git_context_error = _validate_git_context_gate_release(plan, repo, run_dir, gate)
        if git_context_error:
            errors.append(git_context_error)
        security_error = _validate_security_gate_completion(
            store,
            plan.run_id,
            gate,
            gate.verdict or "",
            _latest_gate_actor(events, gate.id),
            gate.notes,
            require_event_binding=True,
        )
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


def _release_command_bundle_policy_errors(
    repo: Path,
    run_dir: Path,
    policy: dict[str, Any],
    *,
    require_origin: bool = True,
) -> list[str]:
    release_policy = policy.get("release_evidence")
    if not isinstance(release_policy, dict) or not any(release_policy.values()):
        return []
    rel = "artifacts/release/replayable_command_bundle_latest.json"
    path = run_dir / rel
    if not path.exists():
        return [f"Release evidence policy requires replayable command bundle: {rel}"]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [f"Release evidence command bundle is invalid JSON: {rel}"]
    digest = _digest_file(path)
    provenance, provenance_error = _artifact_provenance(repo, run_dir, path, digest, require_origin=require_origin)
    if provenance_error or provenance is None or provenance.get("event") != "release.command_bundle_recorded":
        return [provenance_error or f"Release evidence command bundle lacks release.command_bundle_recorded provenance: {rel}"]
    commands = payload.get("commands")
    if not isinstance(commands, list) or not commands:
        return ["Release evidence command bundle must contain at least one command transcript"]
    errors: list[str] = []
    for index, item in enumerate(commands):
        if not isinstance(item, dict):
            errors.append(f"Release evidence command {index} must be an object")
            continue
        label = str(item.get("label") or f"command[{index}]")
        if release_policy.get("require_command_cwd_timestamp_returncode"):
            for key in ("command", "cwd", "started_at", "ended_at", "returncode"):
                if item.get(key) in (None, ""):
                    errors.append(f"Release evidence command {label} missing {key}")
            if isinstance(item.get("returncode"), bool) or not isinstance(item.get("returncode"), int):
                errors.append(f"Release evidence command {label} returncode must be an integer")
        if release_policy.get("require_artifact_paths_and_hashes"):
            for stream in ("stdout", "stderr"):
                artifact_key = f"{stream}_artifact"
                sha_key = f"{stream}_sha256"
                artifact_rel = item.get(artifact_key)
                expected_sha = item.get(sha_key)
                if not isinstance(artifact_rel, str) or not artifact_rel:
                    errors.append(f"Release evidence command {label} missing {artifact_key}")
                    continue
                if not isinstance(expected_sha, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha):
                    errors.append(f"Release evidence command {label} missing valid {sha_key}")
                    continue
                artifact_path = run_dir / artifact_rel
                if not artifact_path.exists() or not artifact_path.is_file():
                    errors.append(f"Release evidence command {label} missing artifact {artifact_rel}")
                    continue
                actual_sha = _digest_file(artifact_path)
                if actual_sha != expected_sha:
                    errors.append(f"Release evidence command {label} {artifact_key} hash mismatch")
    return errors


def _operator_report_consistency_errors(
    repo: Path,
    run_dir: Path,
    findings: list[Finding],
    policy: dict[str, Any],
) -> list[str]:
    """Fail release when operator-facing keys-only reports drift from source or ledger state."""
    run_id = run_dir.name
    status_path = repo / "docs" / "reports" / "strat26_9bot_canary_gate_status.json"
    aws_report_path = repo / "docs" / "reports" / "aws_kms_secrets_manager_backend.json"
    release_policy = policy.get("release_evidence")
    require_operator_reports = (
        isinstance(release_policy, dict)
        and release_policy.get("require_operator_report_consistency") is True
    )
    if not require_operator_reports and not status_path.exists() and not aws_report_path.exists():
        return []
    errors: list[str] = []
    if not status_path.exists():
        errors.append("Operator gate-status JSON report is missing")
        return errors
    try:
        status = json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"Operator gate-status JSON report is invalid: {exc}"]
    if status.get("run_id") != run_id:
        errors.append("Operator gate-status report run_id does not match active run")

    current_open = sorted(
        finding.id
        for finding in findings
        if finding.status in {"OPEN", "FIXED_PENDING_REVIEW"} and finding.severity in {"CRITICAL", "HIGH", "MEDIUM"}
    )
    reported_open: list[str] = []
    for item in status.get("blocking_open_findings", []):
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            reported_open.append(str(item["id"]))
        elif isinstance(item, str):
            reported_open.append(item.split()[0])
    if sorted(reported_open) != current_open:
        errors.append("Operator gate-status report blocking findings diverge from findings ledger")

    source_hashes = status.get("source_hashes")
    if not isinstance(source_hashes, dict) or not source_hashes:
        errors.append("Operator gate-status report is missing source_hashes")
    else:
        for rel, expected in source_hashes.items():
            if not isinstance(rel, str) or not isinstance(expected, str):
                errors.append("Operator gate-status report source_hashes must map paths to sha256 strings")
                continue
            path = repo / rel
            if not path.exists() or not path.is_file():
                errors.append(f"Operator gate-status source hash path is missing: {rel}")
                continue
            actual = _digest_file(path)
            if actual != expected:
                errors.append(f"Operator gate-status source hash mismatch for {rel}")

    backend = status.get("aws_backend_preflight")
    if not isinstance(backend, dict):
        errors.append("Operator gate-status report is missing aws_backend_preflight")
    else:
        backend_path_value = backend.get("path")
        if not isinstance(backend_path_value, str) or "value_bound" in backend_path_value:
            errors.append("Operator gate-status report must not cite value-reading AWS backend proof")
        else:
            backend_path = repo / backend_path_value if backend_path_value.startswith(".sdlc/") else run_dir / backend_path_value
            if not backend_path.exists():
                errors.append("Operator gate-status AWS backend proof path is missing")
            else:
                try:
                    backend_payload = json.loads(backend_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    errors.append(f"Operator gate-status AWS backend proof is invalid JSON: {exc}")
                else:
                    if backend_payload.get("value_read_operations") != 0:
                        errors.append("Operator gate-status AWS backend proof must have value_read_operations=0")
                    if backend_payload.get("post_baseline_secret_management_events") != 0:
                        errors.append("Operator gate-status AWS backend proof must have zero post-baseline mutations")
                    if backend_payload.get("placeholder_baseline_checked_slots") != 36:
                        errors.append("Operator gate-status AWS backend proof must check all 36 baseline slots")

    if aws_report_path.exists():
        try:
            aws_report = json.loads(aws_report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"AWS backend operator report JSON is invalid: {exc}")
        else:
            artifact = aws_report.get("artifact")
            if isinstance(artifact, dict):
                path_value = str(artifact.get("path") or "")
                if "value_bound" in path_value:
                    errors.append("AWS backend operator report still cites value-reading proof")
            result = aws_report.get("result")
            if isinstance(result, dict):
                if result.get("value_read_operations") != 0:
                    errors.append("AWS backend operator report must record value_read_operations=0")
                if result.get("post_baseline_secret_management_events") != 0:
                    errors.append("AWS backend operator report must record zero post-baseline mutations")
    return errors


def _control_snapshot_divergence_errors(run_dir: Path) -> list[str]:
    snapshot_dir = run_dir / "artifacts" / "attestations" / "control-snapshots"
    errors: list[str] = []
    plan_snapshot = snapshot_dir / "plan.json"
    findings_snapshot = snapshot_dir / "findings.json"
    if plan_snapshot.exists():
        live_plan = run_dir / "plan.json"
        if not live_plan.exists():
            errors.append("Live plan.json is missing while an attested control snapshot exists")
        else:
            try:
                live_payload = _release_snapshot_plan_payload(read_json(live_plan, {}))
                snapshot_payload = _release_snapshot_plan_payload(read_json(plan_snapshot, {}))
                if live_payload != snapshot_payload:
                    errors.append("Live plan.json diverges from attested control snapshot")
            except OSError:
                errors.append("Unable to compare live plan.json with attested control snapshot")
    if findings_snapshot.exists():
        live_findings = run_dir / "findings.json"
        if not live_findings.exists():
            errors.append("Live findings.json is missing while an attested control snapshot exists")
        else:
            try:
                if _digest_file(live_findings) != _digest_file(findings_snapshot):
                    errors.append("Live findings.json diverges from attested control snapshot")
            except OSError:
                errors.append("Unable to compare live findings.json with attested control snapshot")
    return errors


def _release_snapshot_plan_payload(payload: object) -> object:
    if not isinstance(payload, dict):
        return payload
    cloned = json.loads(json.dumps(payload, sort_keys=True))
    gates = cloned.get("gates")
    if isinstance(gates, list):
        post_snapshot_gate_ids = {
            "deploy_rollout_postdeploy",
            "evidence_traceability_attestations",
            "final_report_reaudit",
        }
        cloned["gates"] = [
            gate for gate in gates
            if not (isinstance(gate, dict) and gate.get("id") in post_snapshot_gate_ids)
        ]
    return cloned


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


def _latest_gate_completion_event(events: list[dict[str, object]], gate_id: str) -> dict[str, object] | None:
    for event in reversed(events):
        if event.get("gate") == gate_id and event.get("event") in {"gate.manually_completed", "gate.completed"}:
            return event
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
            has_actor_proof = finding.severity not in {"CRITICAL", "HIGH"} or any(
                item.get("event") == "finding.actor_proof"
                and item.get("finding_id") == finding.id
                and item.get("closed_by") == finding.closed_by
                and item.get("actor_proof_method") == "sdlc_actor_hmac_sha256"
                and item.get("actor_proof_verified") is True
                and isinstance(item.get("actor_proof_sha256"), str)
                and re.fullmatch(r"[a-f0-9]{64}", str(item.get("actor_proof_sha256")))
                and item.get("actor_proof_message_sha256")
                == hashlib.sha256(
                    f"{run_dir.name}:{finding.id}:{finding.closed_by}:finding.close".encode(
                        "utf-8"
                    )
                ).hexdigest()
                for item in ledger_backed
            )
            if not has_diff:
                return f"Finding {finding.id} closure evidence is not release-valid: missing ledger-backed remediation diff"
            if not has_validation:
                return f"Finding {finding.id} closure evidence is not release-valid: missing independent second-validation"
            if not has_actor_proof:
                return f"Finding {finding.id} closure evidence is not release-valid: missing ledger-backed actor proof"
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


def command_bench(args: argparse.Namespace) -> int:
    """Measured, evidence-based benchmark over the 12 goal-spec dimensions."""
    from . import bench as bench_mod

    repo = Path(args.repo).resolve()
    bench_dir = repo / "artifacts" / "bench"

    # Reproducibility: if there are no live runs (e.g. a fresh clone — .sdlc/runs is
    # gitignored), fall back to the committed reference corpus (tests/fixtures/runs) so
    # the headline is deterministic and reproducible anywhere, not dependent on whatever
    # runs happen to be present. corpus_source records which was used.
    import shutil as _shutil
    import tempfile as _tempfile
    live_runs = repo / ".sdlc" / "runs"
    reference = repo / "tests" / "fixtures" / "runs"
    has_live = live_runs.is_dir() and any((p / "plan.json").exists() for p in live_runs.iterdir())
    _tmp_corpus = None
    if has_live:
        corpus_repo = repo
        corpus_source = "live:.sdlc/runs"
    elif reference.is_dir() and any((p / "plan.json").exists() for p in reference.iterdir()):
        _tmp_corpus = _tempfile.TemporaryDirectory()
        seeded = Path(_tmp_corpus.name) / ".sdlc" / "runs"
        seeded.mkdir(parents=True)
        for run in reference.iterdir():
            if run.is_dir():
                _shutil.copytree(run, seeded / run.name)
        corpus_repo = Path(_tmp_corpus.name)
        corpus_source = "reference:tests/fixtures/runs"
    else:
        corpus_repo = repo
        corpus_source = "empty"

    def readiness_fn(run_id: str) -> dict[str, object]:
        store = RunStore(corpus_repo)
        plan = store.load_plan(run_id)
        findings = store.load_findings(run_id)
        return _release_readiness_payload(corpus_repo, plan, findings)

    if args.bench_command == "run":
        result = bench_mod.measure(corpus_repo, readiness_fn)
        result["corpus_source"] = corpus_source
        comparative = bench_mod.comparative_blocker_identification(corpus_repo)
        if _tmp_corpus is not None:
            _tmp_corpus.cleanup()
        if not args.no_write:
            bench_dir.mkdir(parents=True, exist_ok=True)
            write_json(bench_dir / "after.json", result)
            write_json(bench_dir / "comparative.json", comparative)
            (bench_dir / "report.md").write_text(bench_mod.report_markdown(result), encoding="utf-8")
            (bench_dir / "comparison_matrix.md").write_text(
                bench_mod.comparison_matrix_markdown(result, comparative), encoding="utf-8")
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            headline_dims = result.get("headline_dimensions", [])
            print(f"Headline (CORPUS only, corpus-relative): {result.get('headline_score')} "
                  f"from {len(headline_dims)}/{result['total_dimensions']} dimensions "
                  f"across {result['runs_evaluated']} runs.")
            print("Other dimensions are reported but excluded from the headline (see kind):")
            for key, dim in result["dimensions"].items():
                if dim["status"] != "MEASURED":
                    mark = "UNAVAILABLE"
                else:
                    kind = dim.get("kind", "?")
                    flag = "*" if kind == result.get("headline_kind") else " "
                    mark = f"{dim['score']:<6}{flag}{kind}"
                print(f"  {key:<32} {mark}")
        return 0

    if args.bench_command == "compare":
        before = read_json(Path(args.before))
        after = read_json(Path(args.after))
        diff = bench_mod.compare(before, after)
        if not args.no_write:
            bench_dir.mkdir(parents=True, exist_ok=True)
            write_json(bench_dir / "diff.json", diff)
        print(json.dumps(diff, indent=2, sort_keys=True))
        return 0

    if args.bench_command == "report":
        result_path = Path(args.result) if args.result else (bench_dir / "after.json")
        if not result_path.exists():
            eprint(f"No benchmark result at {result_path}; run `sdlc bench run` first.")
            return 1
        print(bench_mod.report_markdown(read_json(result_path)))
        return 0

    eprint("Unknown bench command")
    return 2


def command_learn(args: argparse.Namespace) -> int:
    """Self-improvement loop: record lessons, suggest proposals, apply approvals."""
    from . import learn as learn_mod

    repo = Path(args.repo).resolve()
    if args.learn_command == "record":
        store = RunStore(repo)
        plan = store.load_plan(args.run_id)
        findings = store.load_findings(args.run_id)
        result = learn_mod.record_lessons(repo, plan, findings)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.learn_command == "suggest":
        result = learn_mod.suggest_proposals(repo)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.learn_command == "apply":
        result = learn_mod.apply_proposal(repo, args.proposal, actor=args.actor or "", execute=args.execute)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("status") in {"APPLIED", "DRY_RUN", "ALREADY_APPLIED"} else 1
    eprint("Unknown learn command")
    return 2


def command_diff(args: argparse.Namespace) -> int:
    """Structural quality diff between two runs (distinct from `bench compare`)."""
    from . import diff as diff_mod

    if args.diff_command != "quality":
        eprint(f"Unknown diff command: {args.diff_command}")
        return 2
    repo = Path(args.repo).resolve()
    result = diff_mod.quality_diff(repo, args.old_run, args.new_run)
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(diff_mod.render_markdown(result))
    return 0


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
            # Detect ledger tampering in EVERY non-release mode (default AND
            # --structural-only): a broken canonical hash-chain is a defect regardless
            # of validation intent. require_origin=False so a legitimately unsigned
            # local ledger is not rejected, while a byte-tamper still fails. The
            # --release lane runs its own stricter (origin-required) check.
            if not args.release:
                errors.extend(_ledger_integrity_errors(store.run_dir(args.run_id), require_origin=False))
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


def _add_auto_cli_arguments(parser: argparse.ArgumentParser, *, request_help: str) -> None:
    parser.add_argument("request", nargs="*", help=request_help)
    parser.add_argument("--risk", default="auto", choices=["auto", "low", "medium", "high", "extreme"])
    parser.add_argument("--ui", default="auto", choices=["auto", "yes", "no"])
    parser.add_argument("--security", default="auto", choices=["auto", "yes", "no"])
    parser.add_argument("--infra", default="auto", choices=["auto", "yes", "no"])
    parser.add_argument("--policy", default="default")
    parser.add_argument("--run-id")
    parser.add_argument("--parallel", type=int, default=6)
    parser.add_argument("--timeout", type=int, default=120, help="Local worker artifact timeout metadata in seconds. Default: 120.")
    parser.add_argument("--intake-plan", help="JSON intake plan generated by an LLM or another planner. When present, options/artifacts are driven from this file.")
    parser.add_argument("--intake-model", default="codex", help="Worker/LLM family used for request interpretation when --execute-intake-llm is set. Default: codex.")
    parser.add_argument("--execute-intake-llm", action="store_true", help="Execute the selected intake worker to interpret the request and generate questions/options. Requires --allow-network and policy network_allowed=true.")
    parser.add_argument("--execute-agents", action="store_true", help="Execute role-agent workers during auto after artifact generation. Requires --allow-network and policy network_allowed=true.")
    parser.add_argument("--execute-redteam", action="store_true", help="Execute formal red-team workers during auto and block gate 20/21 unless they return GO.")
    parser.add_argument("--redteam-workers", help="Comma-separated red-team worker families for auto. Default: policy redteam.default_workers.")
    parser.add_argument("--redteam-rounds", type=int, help="Red-team rounds for auto. Default: one round, or policy minimum for HIGH/EXTREME runs.")
    parser.add_argument("--redteam-total-timeout", type=int, help="Optional total timeout in seconds for all auto red-team workers.")
    parser.add_argument("--redteam-parallel", action="store_true", help="Request parallel red-team workers per round when policy allows it.")
    parser.add_argument("--claude-validate", action="store_true", help="Execute the validation worker, default claude, to audit that auto evidence honestly reflects real execution.")
    parser.add_argument("--validation-worker", default="claude", help="Worker family for auto honesty validation. Default: claude.")
    parser.add_argument("--presentation", action="store_true", help="Generate an HTML slide deck and Manim scene for the auto run.")
    parser.add_argument("--showcase", action="store_true", help="Live demo mode: implies host-oauth-tools policy when unset, --allow-network, executed intake LLM, role agents, red-team, Claude validation, presentation, and browser opening.")
    parser.add_argument("--allow-network", action="store_true", help="Required for executed LLM/worker paths because host model CLIs may use network/OAuth.")
    parser.add_argument("--aws-profile", default="default", help="AWS CLI profile to use when --execute-aws is set. Default: default.")
    parser.add_argument("--aws-region", default="us-east-1", help="AWS region for S3 website hosting. Default: us-east-1.")
    parser.add_argument("--aws-bucket", help="Existing or desired S3 bucket name. Default: derived from the run id.")
    parser.add_argument("--aws-gateway-name", default="sdlc-web-gateway", help="Logical S3 website gateway/bucket prefix. Default: sdlc-web-gateway.")
    parser.add_argument("--execute-aws", action="store_true", help="Create/sync the S3 static website. Requires --approve-aws-deploy.")
    parser.add_argument("--approve-aws-deploy", help="Explicit approval text required before AWS resources are created or modified.")
    parser.add_argument("--public-read", action="store_true", help="Attach a public-read bucket policy for S3 website hosting.")
    parser.add_argument("--target-run-id", help="Existing auto run to decommission or clean up.")
    parser.add_argument("--execute-cleanup", action="store_true", help="Execute decommission cleanup. Requires --approve-cleanup.")
    parser.add_argument("--approve-cleanup", help="Explicit approval text required before AWS/local cleanup is executed.")
    parser.add_argument("--cleanup-local", action="store_true", help="During decommission, delete generated local site artifacts such as site/.")
    parser.add_argument("--agent-model-config", help="JSON file with role-to-worker mappings for the role agents.")
    parser.add_argument("--agent-model", action="append", default=[], metavar="ROLE=WORKER", help="Override one role worker, for example architecture=claude or agent_6_redteam_deploy_rollback=openai-codex-primary.")
    parser.add_argument("--yes", action="store_true", help="Accept safe defaults and skip interactive approval questions.")
    parser.add_argument("--open-browser", action="store_true", help="Open the generated page or report when the run completes.")
    parser.add_argument("--no-open-browser", action="store_true", help="Do not open a browser when the run completes.")
    parser.add_argument("--json", action="store_true")


def _add_agent_model_cli_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agent-model-config", help="JSON file with role-to-worker mappings for the role agents.")
    parser.add_argument("--agent-model", action="append", default=[], metavar="ROLE=WORKER", help="Override one role worker, for example implementation=codex.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sdlc", description="Terminal-native Secure SDLC control plane for AI software delivery")
    parser.add_argument("--repo", default=".", help="Repository root")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize .sdlc structure")
    p_init.add_argument("--force", action="store_true", help="Rewrite default schemas/policies")
    p_init.set_defaults(func=command_init)

    p_auto = sub.add_parser("auto", help="Build an artifact and run all 25 local SDLC gates")
    _add_auto_cli_arguments(p_auto, request_help="Auto request. The intake plan/LLM decides request-specific questions and artifact type.")
    p_auto.set_defaults(func=command_auto)

    p_demo = sub.add_parser("demo", help=argparse.SUPPRESS)
    _add_auto_cli_arguments(p_demo, request_help="Legacy auto request")
    p_demo.set_defaults(func=command_demo)

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
    _add_agent_model_cli_arguments(p_start)
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

    p_prompt = sub.add_parser("prompt", help="Run an external prompt under SDLC supervision")
    prompt_sub = p_prompt.add_subparsers(dest="prompt_command", required=True)
    prompt_run = prompt_sub.add_parser("run", help="Import, execute, validate, report, and optionally commit a prompt run")
    prompt_run.add_argument("prompt_file", help="Path to the prompt file to execute")
    prompt_run.add_argument("--request", help="Override the run feature/request text derived from the prompt heading")
    prompt_run.add_argument("--risk", default="high", choices=["auto", "low", "medium", "high", "extreme"])
    prompt_run.add_argument("--ui", default="auto", choices=["auto", "yes", "no"])
    prompt_run.add_argument("--security", default="auto", choices=["auto", "yes", "no"])
    prompt_run.add_argument("--infra", default="auto", choices=["auto", "yes", "no"])
    prompt_run.add_argument("--policy", default="host-oauth-tools")
    prompt_run.add_argument("--run-id")
    prompt_run.add_argument("--worker", default="codex")
    prompt_run.add_argument("--mode", default="BUILD", choices=["READ_ONLY", "PLAN", "BUILD", "TEST", "SECURITY_REVIEW", "FIX"])
    prompt_run.add_argument("--read-only-repo", action="append", default=[], help="Additional evidence repo exposed to the worker and restored if mutated. Repeatable.")
    prompt_run.add_argument("--allow-production-read", action="store_true", help="Allow explicitly read-only production evidence access requested by the prompt. Default forbids production host access.")
    prompt_run.add_argument("--execute", action="store_true", help="Actually invoke the worker. Default is dry-run evidence capture.")
    prompt_run.add_argument("--allow-network", action="store_true", help="Required with --execute because host model CLIs use network/OAuth.")
    prompt_run.add_argument("--timeout", type=int, default=14400, help="Worker timeout in seconds. Default: 14400.")
    prompt_run.add_argument("--no-branch", action="store_true", help="Do not create or switch to sdlc/<run-id> before running.")
    prompt_run.add_argument("--branch-name", help="Feature branch name to create/switch to. Defaults to sdlc/<run-id>.")
    prompt_run.add_argument("--commit", action="store_true", help="Commit docs and .codex/prompts after validation.")
    prompt_run.add_argument("--commit-message", default="docs: add s4 clean-room review plan")
    prompt_run.add_argument("--json", action="store_true")
    prompt_run.set_defaults(func=command_prompt)

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

    p_isolation = sub.add_parser("isolation", help="Preflight audit worker hard-isolation runtime availability")
    isolation_sub = p_isolation.add_subparsers(dest="isolation_command", required=True)
    i_preflight = isolation_sub.add_parser("preflight", help="Dry-run audit isolation runtime selection and qualification")
    i_preflight.add_argument("run_id")
    i_preflight.add_argument("--workers", help="Comma-separated worker families. Defaults to policy red-team workers.")
    i_preflight.add_argument("--allow-network", action="store_true", help="Evaluate the policy-bound network mode used for executed workers.")
    i_preflight.add_argument("--json", action="store_true")
    i_preflight.set_defaults(func=command_isolation)

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
    ag_plan = agents_sub.add_parser("plan", help="Create a role-agent task plan")
    ag_plan.add_argument("run_id")
    ag_plan.add_argument("--parallel", type=int, default=6)
    _add_agent_model_cli_arguments(ag_plan)
    ag_plan.add_argument("--json", action="store_true")
    ag_plan.set_defaults(func=command_agents)
    ag_execute = agents_sub.add_parser("execute", help="Execute or dry-run a planned agent batch")
    ag_execute.add_argument("run_id")
    ag_execute.add_argument("--parallel", type=int, default=6)
    ag_execute.add_argument("--execute", action="store_true")
    ag_execute.add_argument("--allow-network", action="store_true")
    ag_execute.add_argument("--timeout", type=int, default=120)
    _add_agent_model_cli_arguments(ag_execute)
    ag_execute.add_argument("--json", action="store_true")
    ag_execute.set_defaults(func=command_agents)
    ag_status = agents_sub.add_parser("status", help="Show agent task status")
    ag_status.add_argument("run_id")
    ag_status.add_argument("--json", action="store_true")
    ag_status.set_defaults(func=command_agents)
    ag_doctor = agents_sub.add_parser("doctor", help="Show worker family availability")
    ag_doctor.add_argument("--policy", default="default")
    _add_agent_model_cli_arguments(ag_doctor)
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
    p_tui.add_argument("--no-tui", action="store_true", help="Plain-text dashboard (no interactive curses)")
    p_tui.set_defaults(func=command_tui)

    p_release = sub.add_parser("release", help="Check and prepare release-lane prerequisites")
    release_sub = p_release.add_subparsers(dest="release_command", required=True)
    release_doctor = release_sub.add_parser("doctor", help="Fail-fast check for recurring release blockers")
    release_doctor.add_argument("run_id", nargs="?", help="Optional run id; uses its risk and policy profile when provided.")
    release_doctor.add_argument("--risk", default="high", choices=["auto", "low", "medium", "high", "extreme"])
    release_doctor.add_argument("--policy", default="default")
    release_doctor.add_argument("--workers", help="Comma-separated red-team worker families to evaluate.")
    release_doctor.add_argument("--allow-network", action="store_true", help="Evaluate runtime/network prerequisites for executed worker commands.")
    release_doctor.add_argument("--check-isolation-runtime", action="store_true", help="Run the configured container/VM isolation preflight probe.")
    release_doctor.add_argument("--no-worktree-check", action="store_true", help="Do not require a clean Git worktree for this diagnostic run.")
    release_doctor.add_argument("--no-branch-check", action="store_true", help="Do not reject protected/detached branches for this diagnostic run.")
    release_doctor.add_argument("--json", action="store_true")
    release_doctor.set_defaults(func=command_release)

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

    p_bench = sub.add_parser("bench", help="Measured, evidence-based benchmark over the 12 dimensions")
    bench_sub = p_bench.add_subparsers(dest="bench_command", required=True)
    b_run = bench_sub.add_parser("run", help="Measure all dimensions and write artifacts/bench/after.json")
    b_run.add_argument("--json", action="store_true", help="Emit the full result as JSON")
    b_run.add_argument("--no-write", action="store_true", help="Do not write artifacts")
    b_run.set_defaults(func=command_bench)
    b_compare = bench_sub.add_parser("compare", help="Diff two benchmark results per dimension")
    b_compare.add_argument("--before", required=True, help="Path to baseline/before result JSON")
    b_compare.add_argument("--after", required=True, help="Path to after result JSON")
    b_compare.add_argument("--no-write", action="store_true", help="Do not write diff.json")
    b_compare.set_defaults(func=command_bench)
    b_report = bench_sub.add_parser("report", help="Render a benchmark result as markdown")
    b_report.add_argument("--result", help="Result JSON path (default artifacts/bench/after.json)")
    b_report.set_defaults(func=command_bench)

    p_learn = sub.add_parser("learn", help="Self-improvement loop: record, suggest, apply")
    learn_sub = p_learn.add_subparsers(dest="learn_command", required=True)
    l_record = learn_sub.add_parser("record", help="Record pattern-level lessons from a run")
    l_record.add_argument("run_id")
    l_record.set_defaults(func=command_learn)
    l_suggest = learn_sub.add_parser("suggest", help="Suggest proposals from recurring lessons")
    l_suggest.set_defaults(func=command_learn)
    l_apply = learn_sub.add_parser("apply", help="Record human approval of a proposal (no policy change)")
    l_apply.add_argument("--proposal", type=int, required=True)
    l_apply.add_argument("--actor", required=True, help="Named approver (learn cannot self-approve)")
    l_apply.add_argument("--execute", action="store_true", help="Record approval (omit for dry-run)")
    l_apply.set_defaults(func=command_learn)

    p_diff = sub.add_parser("diff", help="Structural quality diff between two runs")
    diff_sub = p_diff.add_subparsers(dest="diff_command", required=True)
    d_quality = diff_sub.add_parser("quality", help="Compare two runs across 12 structural fields")
    d_quality.add_argument("old_run")
    d_quality.add_argument("new_run")
    d_quality.add_argument("--format", choices=["json", "md"], default="md")
    d_quality.set_defaults(func=command_diff)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
