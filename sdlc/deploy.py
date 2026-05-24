"""Locked deployment and rollout evidence workflows."""

from __future__ import annotations

import json
import hashlib
import hmac
import os
import shlex
from pathlib import Path
from typing import Any

from .ledger import Ledger, canonical_artifact_event, is_origin_authenticated_ledger_event
from .models import Finding, RunPlan, open_findings, plan_condition_value
from .util import now_iso, read_json, redact_secrets, resolve_repo_paths, run_cmd


DEPLOY_ENVS = {"staging", "production"}
HUMAN_RELEASE_ACTORS = {"human_release_manager", "human_approval_authority", "human_product_owner"}
HUMAN_RESIDUAL_RISK_ACTORS = HUMAN_RELEASE_ACTORS | {"human_security_owner"}
PRIOR_RELEASE_GATE_IDS = {
    "intake_scope",
    "stakeholders_raci",
    "mission_non_goals",
    "repo_context_env_branch",
    "risk_blast_radius",
    "data_privacy_secrets",
    "baseline_freeze",
    "supply_chain_sbom",
    "agent_plan_permissions",
    "architecture_contracts",
    "ui_architecture_accessibility",
    "threat_model_abuse_cases",
    "implementation_plan_changeset",
    "implementation",
    "deterministic_quality",
    "qa_tests_integration_smoke",
    "security_scans",
    "observability_runbooks",
    "implementer_self_review",
    "independent_redteam_cross_model",
    "critical_high_fix_loop",
    "evidence_traceability_attestations",
    "commit_branch_pr_ci",
}


def plan_deployment(store: Any, run_id: str, *, env: str, rollback_command: str | None = None) -> dict[str, Any]:
    plan = store.load_plan(run_id)
    run_dir = store.run_dir(run_id)
    ledger = Ledger(run_dir, run_id)
    record = _load_deploy_record(run_dir, env)
    record.update({
        "environment": env,
        "requested": True,
        "planned_at": now_iso(),
        "execute_default": "DRY_RUN",
        "production_rollout_allowed": plan.production_rollout_allowed,
        "rollback_plan": "Rollback command evidence must be captured before production execution. Executed rollback evidence is required for plain GO; rollback dry-run/readiness evidence requires explicit accepted residual risk.",
    })
    if rollback_command:
        record["rollback_command"] = _command_record(rollback_command)
    artifact = _write_deploy_record(ledger, env, record, event="deploy.plan_artifact")
    _update_deploy_gate(store, plan, run_id, env, artifact)
    ledger.event(
        "deploy.planned",
        env=env,
        execute_default="DRY_RUN",
        rollback_command_sha256=_json_sha256(record.get("rollback_command")),
        record_sha256=_artifact_sha256(run_dir, artifact),
        evidence=[artifact],
    )
    return {"status": "PLANNED", "artifact": artifact, "record": record}


def approve_deployment(store: Any, run_id: str, *, env: str, actor: str, evidence: list[str], actor_proof: str | None = None) -> dict[str, Any]:
    plan = store.load_plan(run_id)
    run_dir = store.run_dir(run_id)
    repo = Path(plan.repo)
    ledger = Ledger(run_dir, run_id)
    if actor not in HUMAN_RELEASE_ACTORS:
        reason = f"Deployment approval requires human release authority; got {actor}"
        ledger.event("deploy.approval_rejected", env=env, actor=actor, reason=reason)
        return {"status": "REJECTED", "reason": reason}
    evidence_paths, error = _resolve_evidence(repo, evidence)
    if error:
        ledger.event("deploy.approval_rejected", env=env, actor=actor, reason=error)
        return {"status": "REJECTED", "reason": error}
    approval_binding = _approval_binding_payload(repo, run_id, env, actor, evidence_paths)
    if env == "production":
        proof_error = _actor_proof_error(
            repo,
            run_dir,
            run_id,
            env,
            actor,
            actor_proof,
            action="deploy.approve",
            binding_sha256=str(approval_binding["binding_sha256"]),
        )
        if proof_error:
            ledger.event("deploy.approval_rejected", env=env, actor=actor, reason=proof_error)
            return {"status": "REJECTED", "reason": proof_error}
    binding_artifact = ledger.artifact(
        f"artifacts/deploy/{env}-approval-binding.json",
        json.dumps(approval_binding, indent=2, sort_keys=True) + "\n",
        event="deploy.approval_binding_artifact",
        env=env,
        actor=actor,
        binding_sha256=approval_binding["binding_sha256"],
    )
    record = _load_deploy_record(run_dir, env)
    record.update({
        "environment": env,
        "requested": True,
        "approved_at": now_iso(),
        "approver": actor,
        "approval_evidence": evidence_paths,
        "approval_actor_proof_verified": env == "production",
        "approval_binding_artifact": binding_artifact,
        "approval_binding_sha256": approval_binding["binding_sha256"],
    })
    artifact = _write_deploy_record(ledger, env, record, event="deploy.approval_artifact")
    _update_deploy_gate(store, plan, run_id, env, artifact)
    ledger.event(
        "deploy.approved",
        env=env,
        actor=actor,
        approval_evidence=evidence_paths,
        approval_binding_artifact=binding_artifact,
        approval_binding_sha256=approval_binding["binding_sha256"],
        actor_proof_verified=env == "production",
        record_sha256=_artifact_sha256(run_dir, artifact),
        evidence=evidence_paths + [binding_artifact, artifact],
    )
    return {"status": "APPROVED", "artifact": artifact, "record": record}


def execute_deployment(
    store: Any,
    run_id: str,
    *,
    env: str,
    execute: bool,
    command: str | None = None,
    release_errors: list[str] | None = None,
) -> dict[str, Any]:
    plan = store.load_plan(run_id)
    findings = store.load_findings(run_id)
    run_dir = store.run_dir(run_id)
    ledger = Ledger(run_dir, run_id)
    record = _load_deploy_record(run_dir, env)
    record.update({"environment": env, "requested": True, "execute_requested": execute})
    if command:
        record["execution_command"] = _command_record(command)
    artifact = _write_deploy_record(ledger, env, record, event="deploy.execute_plan_artifact")

    if not execute:
        _update_deploy_gate(store, plan, run_id, env, artifact)
        ledger.event("deploy.execute_dry_run", env=env, evidence=[artifact])
        return {"status": "DRY_RUN", "artifact": artifact, "record": record}

    rejection = _production_execute_rejection(plan, findings, env, record, release_errors=release_errors)
    if rejection:
        record["execution_rejected_at"] = now_iso()
        record["execution_rejection"] = rejection
        artifact = _write_deploy_record(ledger, env, record, event="deploy.execution_rejected_artifact")
        _update_deploy_gate(store, plan, run_id, env, artifact)
        ledger.event("deploy.execution_rejected", env=env, reason=rejection, record_sha256=_artifact_sha256(run_dir, artifact), evidence=[artifact])
        return {"status": "REJECTED", "reason": rejection, "artifact": artifact, "record": record}

    command_error = _validate_command(command, "Deployment execution")
    if command_error:
        record["execution_rejected_at"] = now_iso()
        record["execution_rejection"] = command_error
        artifact = _write_deploy_record(ledger, env, record, event="deploy.execution_rejected_artifact")
        _update_deploy_gate(store, plan, run_id, env, artifact)
        ledger.event("deploy.execution_rejected", env=env, reason=command_error, record_sha256=_artifact_sha256(run_dir, artifact), evidence=[artifact])
        return {"status": "REJECTED", "reason": command_error, "artifact": artifact, "record": record}

    command_args = shlex.split(command or "")
    result = run_cmd(command_args, Path(plan.repo), timeout=600)
    record["execution_returncode"] = result["returncode"]
    record["execution_stdout"] = redact_secrets(str(result["stdout"] or ""))
    record["execution_stderr"] = redact_secrets(str(result["stderr"] or ""))
    record["execution_stdout_truncated"] = bool(result.get("stdout_truncated"))
    record["execution_stderr_truncated"] = bool(result.get("stderr_truncated"))
    if result["returncode"] == 0:
        record["executed_at"] = now_iso()
        event = "deploy.execution_artifact"
        ledger_event = "deploy.executed"
        status = "EXECUTED"
    else:
        record["execution_failed_at"] = now_iso()
        event = "deploy.execution_failed_artifact"
        ledger_event = "deploy.execution_failed"
        status = "FAILED"
    artifact = _write_deploy_record(ledger, env, record, event=event)
    _update_deploy_gate(store, plan, run_id, env, artifact)
    ledger.event(
        ledger_event,
        env=env,
        returncode=result["returncode"],
        command_sha256=_json_sha256(record.get("execution_command")),
        record_sha256=_artifact_sha256(run_dir, artifact),
        stdout_truncated=record["execution_stdout_truncated"],
        stderr_truncated=record["execution_stderr_truncated"],
        evidence=[artifact],
    )
    return {"status": status, "artifact": artifact, "record": record}


def verify_deployment(
    store: Any,
    run_id: str,
    *,
    env: str,
    evidence: list[str],
    accepted_residual_risk: str | None = None,
    actor: str | None = None,
    actor_proof: str | None = None,
) -> dict[str, Any]:
    plan = store.load_plan(run_id)
    run_dir = store.run_dir(run_id)
    repo = Path(plan.repo)
    ledger = Ledger(run_dir, run_id)
    evidence_paths, error = _resolve_evidence(repo, evidence)
    if error:
        ledger.event("deploy.verification_rejected", env=env, reason=error)
        return {"status": "REJECTED", "reason": error}
    residual_acceptance: dict[str, Any] | None = None
    if accepted_residual_risk:
        acceptance_error = _residual_risk_acceptance_error(
            repo,
            run_dir,
            run_id,
            env,
            accepted_residual_risk,
            actor=actor,
            actor_proof=actor_proof,
        )
        if acceptance_error:
            ledger.event("deploy.verification_rejected", env=env, reason=acceptance_error, actor=actor)
            return {"status": "REJECTED", "reason": acceptance_error}
        residual_acceptance = {
            "risk": accepted_residual_risk,
            "accepted_by": actor,
            "accepted_at": now_iso(),
            "actor_proof_verified": True,
            "scope": "deploy.verify.rollback_readiness_residual_risk",
        }
    record = _load_deploy_record(run_dir, env)
    record.update({
        "environment": env,
        "requested": True,
        "verified_at": now_iso(),
        "verification_evidence": evidence_paths,
    })
    if residual_acceptance:
        risks = list(record.get("accepted_residual_risks", []))
        risks.append(residual_acceptance)
        record["accepted_residual_risks"] = risks
        record["residual_risk_acceptance_actor"] = actor
        record["residual_risk_actor_proof_verified"] = True
    artifact = _write_deploy_record(ledger, env, record, event="deploy.verification_artifact")
    ledger.event(
        "deploy.verified",
        env=env,
        verification_evidence=evidence_paths,
        record_sha256=_artifact_sha256(run_dir, artifact),
        evidence=evidence_paths + [artifact],
        accepted_residual_risk=residual_acceptance,
        actor=actor if residual_acceptance else None,
        actor_proof_verified=bool(residual_acceptance),
    )
    _update_deploy_gate(store, plan, run_id, env, artifact)
    return {"status": "VERIFIED", "artifact": artifact, "record": record}


def rollback_deployment(
    store: Any,
    run_id: str,
    *,
    env: str,
    execute: bool,
    command: str | None = None,
    evidence: list[str] | None = None,
    release_errors: list[str] | None = None,
) -> dict[str, Any]:
    plan = store.load_plan(run_id)
    findings = store.load_findings(run_id)
    run_dir = store.run_dir(run_id)
    repo = Path(plan.repo)
    ledger = Ledger(run_dir, run_id)
    record = _load_deploy_record(run_dir, env)
    record.update({"environment": env, "requested": True, "rollback_execute_requested": execute})
    if command:
        record["rollback_command"] = _command_record(command)
    if evidence:
        evidence_paths, error = _resolve_evidence(repo, evidence)
        if error:
            record["rollback_rejection"] = error
            artifact = _write_deploy_record(ledger, env, record, event="deploy.rollback_rejected_artifact")
            _update_deploy_gate(store, plan, run_id, env, artifact)
            ledger.event("deploy.rollback_rejected", env=env, reason=error, record_sha256=_artifact_sha256(run_dir, artifact), evidence=[artifact])
            return {"status": "REJECTED", "reason": error, "artifact": artifact, "record": record}
        record["rollback_validation_evidence"] = evidence_paths
    if execute and env == "production" and not plan.production_rollout_allowed:
        reason = "Production rollback execution requires production_rollout_allowed=true"
        record["rollback_rejection"] = reason
        artifact = _write_deploy_record(ledger, env, record, event="deploy.rollback_rejected_artifact")
        _update_deploy_gate(store, plan, run_id, env, artifact)
        ledger.event("deploy.rollback_rejected", env=env, reason=reason, record_sha256=_artifact_sha256(run_dir, artifact), evidence=[artifact])
        return {"status": "REJECTED", "reason": reason, "artifact": artifact, "record": record}
    if execute:
        rejection = _production_execute_rejection(plan, findings, env, record, release_errors=release_errors)
        if rejection:
            record["rollback_rejection"] = rejection
            artifact = _write_deploy_record(ledger, env, record, event="deploy.rollback_rejected_artifact")
            _update_deploy_gate(store, plan, run_id, env, artifact)
            ledger.event("deploy.rollback_rejected", env=env, reason=rejection, record_sha256=_artifact_sha256(run_dir, artifact), evidence=[artifact])
            return {"status": "REJECTED", "reason": rejection, "artifact": artifact, "record": record}
    if not execute:
        record["rollback_status"] = "DRY_RUN"
        record["rollback_readiness_status"] = "RECORDED"
        record["rollback_recorded_at"] = now_iso()
        artifact = _write_deploy_record(ledger, env, record, event="deploy.rollback_artifact")
        ledger.event(
            "deploy.rollback_recorded",
            env=env,
            execute_requested=execute,
            rollback_validation_evidence=record.get("rollback_validation_evidence", []),
            record_sha256=_artifact_sha256(run_dir, artifact),
            evidence=[artifact],
        )
        _update_deploy_gate(store, plan, run_id, env, artifact)
        return {"status": record["rollback_status"], "artifact": artifact, "record": record}

    command_error = _validate_command(command, "Rollback execution")
    if command_error:
        record["rollback_rejection"] = command_error
        artifact = _write_deploy_record(ledger, env, record, event="deploy.rollback_rejected_artifact")
        _update_deploy_gate(store, plan, run_id, env, artifact)
        ledger.event("deploy.rollback_rejected", env=env, reason=command_error, record_sha256=_artifact_sha256(run_dir, artifact), evidence=[artifact])
        return {"status": "REJECTED", "reason": command_error, "artifact": artifact, "record": record}

    result = run_cmd(shlex.split(command or ""), Path(plan.repo), timeout=600)
    record["rollback_returncode"] = result["returncode"]
    record["rollback_stdout"] = redact_secrets(str(result["stdout"] or ""))
    record["rollback_stderr"] = redact_secrets(str(result["stderr"] or ""))
    record["rollback_stdout_truncated"] = bool(result.get("stdout_truncated"))
    record["rollback_stderr_truncated"] = bool(result.get("stderr_truncated"))
    if result["returncode"] == 0:
        record["rollback_status"] = "EXECUTED"
        record["rollback_recorded_at"] = now_iso()
        event = "deploy.rollback_artifact"
        ledger_event = "deploy.rollback_executed"
    else:
        record["rollback_status"] = "FAILED"
        record["rollback_failed_at"] = now_iso()
        event = "deploy.rollback_failed_artifact"
        ledger_event = "deploy.rollback_failed"
    artifact = _write_deploy_record(ledger, env, record, event=event)
    ledger.event(
        ledger_event,
        env=env,
        returncode=result["returncode"],
        command_sha256=_json_sha256(record.get("rollback_command")),
        rollback_validation_evidence=record.get("rollback_validation_evidence", []),
        record_sha256=_artifact_sha256(run_dir, artifact),
        stdout_truncated=record["rollback_stdout_truncated"],
        stderr_truncated=record["rollback_stderr_truncated"],
        evidence=[artifact],
    )
    _update_deploy_gate(store, plan, run_id, env, artifact)
    return {"status": record["rollback_status"], "artifact": artifact, "record": record}


def _production_execute_rejection(
    plan: RunPlan,
    findings: list[Finding],
    env: str,
    record: dict[str, Any],
    *,
    release_errors: list[str] | None = None,
) -> str | None:
    if env != "production":
        return None
    if not plan.production_rollout_allowed:
        return "production_rollout_allowed=true is required for production execution"
    if not record.get("approved_at") or not record.get("approver"):
        return "Human release-manager approval evidence is required"
    if not record.get("rollback_command"):
        return "Rollback command evidence from deploy plan is required before production execution"
    blocking = [finding.id for finding in open_findings(findings, {"CRITICAL", "HIGH", "MEDIUM"})]
    if blocking:
        return "Open CRITICAL/HIGH/MEDIUM findings block production execution: " + ", ".join(blocking)
    if release_errors is None:
        return "Canonical release-readiness validation is required before production execution"
    if release_errors:
        return "Canonical release-readiness validation blocks production execution: " + "; ".join(release_errors[:8])
    gate_error = _prior_release_gate_rejection(plan)
    if gate_error:
        return gate_error
    if not record.get("planned_at"):
        return "Deployment plan evidence is required"
    return None


def _prior_release_gate_rejection(plan: RunPlan) -> str | None:
    blocking: list[str] = []
    for gate in sorted(plan.gates, key=lambda item: item.order):
        if gate.id not in PRIOR_RELEASE_GATE_IDS:
            continue
        if gate.state == "SKIPPED" and gate.verdict == "SKIPPED" and gate.conditional_on and plan_condition_value(plan, gate.conditional_on) is False:
            continue
        if gate.state != "GO" or gate.verdict not in {"GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"}:
            blocking.append(f"{gate.id}={gate.state}/{gate.verdict or 'PENDING'}")
            continue
        if not gate.evidence:
            blocking.append(f"{gate.id}=missing evidence")
    if blocking:
        return "All prior release gates through commit/CI must be satisfied before production execution: " + ", ".join(blocking)
    return None


def _update_deploy_gate(store: Any, plan: RunPlan, run_id: str, env: str, artifact: str) -> None:
    gate = next((item for item in plan.gates if item.id == "deploy_rollout_postdeploy"), None)
    if gate is None or env != "production":
        store.save_plan(plan)
        return
    if not plan.production_rollout_allowed:
        gate.state = "SKIPPED"
        gate.verdict = "SKIPPED"
        gate.notes = "Production rollout is not allowed by plan/policy."
    else:
        record = _load_deploy_record(store.run_dir(run_id), env)
        missing = _missing_production_evidence(record)
        if missing:
            gate.state = "NO_GO"
            gate.verdict = "NO_GO"
            gate.notes = "Production rollout requested but evidence is missing: " + ", ".join(missing)
        elif provenance := _deployment_provenance_errors(store.run_dir(run_id), record):
            gate.state = "NO_GO"
            gate.verdict = "NO_GO"
            gate.notes = "Production rollout provenance is missing or invalid: " + ", ".join(provenance)
        else:
            residuals = record.get("accepted_residual_risks", [])
            gate.state = "GO"
            gate.verdict = "GO_WITH_ACCEPTED_RESIDUAL_RISKS" if residuals else "GO"
            gate.notes = "Production rollout evidence verified." if not residuals else "Production rollout evidence verified with accepted residual risks."
    if artifact not in gate.evidence:
        gate.evidence.append(artifact)
    store.save_plan(plan)


def _missing_production_evidence(record: dict[str, Any]) -> list[str]:
    required = {
        "planned_at": "deploy plan",
        "rollback_command": "rollback command plan",
        "approved_at": "human approval",
        "approval_evidence": "approval evidence",
        "approval_actor_proof_verified": "authenticated human approval proof",
        "approval_binding_artifact": "approval evidence binding",
        "approval_binding_sha256": "approval evidence binding digest",
        "executed_at": "execution record",
        "verification_evidence": "smoke/monitoring verification",
    }
    missing = [label for key, label in required.items() if not record.get(key)]
    rollback_status = record.get("rollback_status")
    if record.get("accepted_residual_risks") and not _authenticated_residual_risk_acceptance(record):
        missing.append("authenticated residual-risk acceptance provenance")
    if rollback_status == "FAILED":
        missing.append("successful rollback execution after failed rollback attempt")
    elif rollback_status == "EXECUTED" and record.get("rollback_returncode") != 0:
        missing.append("successful rollback execution after failed rollback attempt")
    elif rollback_status == "DRY_RUN":
        if not record.get("rollback_readiness_status"):
            missing.append("rollback readiness evidence")
        if not record.get("rollback_validation_evidence"):
            missing.append("rollback validation evidence for rollback dry-run/readiness")
        if not _authenticated_residual_risk_acceptance(record):
            missing.append("authenticated accepted residual risk for rollback dry-run/readiness")
    elif rollback_status != "EXECUTED":
        missing.append("rollback execution or rollback dry-run/readiness evidence")
    return missing


def _rollback_readiness_is_residual(record: dict[str, Any]) -> bool:
    return record.get("rollback_status") == "DRY_RUN"


def production_deploy_gate_rejection(store: Any, run_id: str, verdict: str = "GO") -> str | None:
    run_dir = store.run_dir(run_id)
    record = _load_deploy_record(run_dir, "production")
    missing = _missing_production_evidence(record)
    if missing:
        return "Deployment gate positive verdict requires production deploy record evidence: " + ", ".join(missing)
    provenance_errors = _deployment_provenance_errors(run_dir, record)
    if provenance_errors:
        return "Deployment gate positive verdict requires ledger-backed provenance: " + ", ".join(provenance_errors)
    if verdict == "GO" and _rollback_readiness_is_residual(record):
        return "Deployment gate plain GO requires executed rollback evidence; rollback dry-run/readiness must use GO_WITH_ACCEPTED_RESIDUAL_RISKS"
    if verdict == "GO_WITH_ACCEPTED_RESIDUAL_RISKS" and _rollback_readiness_is_residual(record) and not _authenticated_residual_risk_acceptance(record):
        return "Rollback dry-run/readiness residual risk must be explicitly accepted by an authenticated human actor"
    return None


def _deployment_provenance_errors(run_dir: Path, record: dict[str, Any]) -> list[str]:
    events = _load_deploy_events(run_dir)
    errors: list[str] = []
    planned = _matching_deploy_event(run_dir, events, "deploy.planned")
    approved = _matching_deploy_event(run_dir, events, "deploy.approved")
    executed = _matching_deploy_event(run_dir, events, "deploy.executed")
    verified = _matching_deploy_event(run_dir, events, "deploy.verified")
    sequence = [planned, approved, executed, verified]
    labels = ["deployment plan ledger event", "human approval ledger event", "successful execution ledger event", "smoke/monitoring verification ledger event"]
    for event, label in zip(sequence, labels):
        if event is None:
            errors.append(label)
    if all(sequence) and not _events_in_order(events, [item for item in sequence if item is not None]):
        errors.append("deployment ledger event order")
    if approved is not None and approved.get("actor") != record.get("approver"):
        errors.append("approval actor does not match deploy record")
    if approved is not None:
        if approved.get("actor_proof_verified") is not True or record.get("approval_actor_proof_verified") is not True:
            errors.append("approval actor proof binding")
        if approved.get("approval_binding_sha256") != record.get("approval_binding_sha256"):
            errors.append("approval evidence digest binding")
        binding_error = _approval_binding_provenance_error(run_dir, events, record)
        if binding_error:
            errors.append(binding_error)
    if executed is not None:
        if executed.get("returncode") != 0 or record.get("execution_returncode") != 0:
            errors.append("successful execution return code")
        if executed.get("command_sha256") != _json_sha256(record.get("execution_command")):
            errors.append("execution command digest")
    if verified is not None:
        expected_evidence = {str(item) for item in record.get("verification_evidence", [])}
        event_evidence = {str(item) for item in verified.get("verification_evidence", [])}
        if expected_evidence and expected_evidence != event_evidence:
            errors.append("verification evidence binding")
        if record.get("accepted_residual_risks") or _rollback_readiness_is_residual(record):
            acceptance = _latest_residual_risk_acceptance(record)
            event_acceptance = verified.get("accepted_residual_risk")
            if not acceptance:
                errors.append("authenticated residual-risk acceptance")
            elif not isinstance(event_acceptance, dict):
                errors.append("deploy.verified residual-risk acceptance provenance")
            elif event_acceptance.get("accepted_by") != acceptance.get("accepted_by") or event_acceptance.get("risk") != acceptance.get("risk"):
                errors.append("deploy.verified residual-risk acceptance binding")
            elif verified.get("actor") != acceptance.get("accepted_by") or verified.get("actor_proof_verified") is not True:
                errors.append("deploy.verified residual-risk actor proof binding")
    for event in [item for item in sequence if item is not None]:
        if not _event_has_artifact_sha(run_dir, events, event):
            errors.append(f"{event.get('event')} artifact digest binding")
    rollback_status = record.get("rollback_status")
    if rollback_status == "EXECUTED":
        rollback = _matching_deploy_event(run_dir, events, "deploy.rollback_executed")
        if rollback is None:
            errors.append("rollback execution ledger event")
        elif rollback.get("returncode") != 0 or rollback.get("command_sha256") != _json_sha256(record.get("rollback_command")):
            errors.append("rollback execution digest/returncode binding")
        elif not _event_has_artifact_sha(run_dir, events, rollback):
            errors.append("deploy.rollback_executed artifact digest binding")
    elif rollback_status == "DRY_RUN":
        rollback = _matching_deploy_event(run_dir, events, "deploy.rollback_recorded")
        if rollback is None:
            errors.append("rollback readiness ledger event")
        elif not _event_has_artifact_sha(run_dir, events, rollback):
            errors.append("deploy.rollback_recorded artifact digest binding")
        elif set(str(item) for item in record.get("rollback_validation_evidence", [])) != set(str(item) for item in rollback.get("rollback_validation_evidence", [])):
            errors.append("rollback readiness evidence binding")
    return errors


def _approval_binding_provenance_error(run_dir: Path, events: list[dict[str, Any]], record: dict[str, Any]) -> str | None:
    artifact = record.get("approval_binding_artifact")
    digest = record.get("approval_binding_sha256")
    if not isinstance(artifact, str) or not artifact:
        return "approval evidence binding artifact"
    if not isinstance(digest, str) or not digest:
        return "approval evidence binding digest"
    event = canonical_artifact_event(
        events,
        run_id=run_dir.name,
        path=artifact,
        sha256=_artifact_sha256(run_dir, artifact),
        allowed_events={"deploy.approval_binding_artifact"},
        require_origin=True,
        run_dir=run_dir,
    )
    if event is None:
        return "approval evidence binding ledger event"
    if event.get("binding_sha256") != digest:
        return "approval evidence binding ledger digest"
    return None


def _residual_risk_acceptance_error(
    repo: Path,
    run_dir: Path,
    run_id: str,
    env: str,
    accepted_residual_risk: str,
    *,
    actor: str | None,
    actor_proof: str | None,
) -> str | None:
    if env != "production":
        return "Accepted deployment residual risk is only supported for production rollout evidence"
    if not accepted_residual_risk.strip():
        return "Accepted residual risk requires a non-empty rationale"
    if actor not in HUMAN_RESIDUAL_RISK_ACTORS:
        return "Accepted deployment residual risk requires an authorized human release or security actor"
    proof_error = _actor_proof_error(repo, run_dir, run_id, env, actor, actor_proof, action="deploy.verify_residual_risk")
    if proof_error:
        return proof_error
    return None


def _actor_proof_error(
    repo: Path,
    run_dir: Path,
    run_id: str,
    env: str,
    actor: str | None,
    proof: str | None,
    *,
    action: str,
    binding_sha256: str | None = None,
) -> str | None:
    key_text = os.environ.get("SDLC_ACTOR_PROOF_KEY", "")
    key_file = os.environ.get("SDLC_ACTOR_PROOF_KEY_FILE", "")
    if not key_text and key_file:
        try:
            key_path = Path(key_file).resolve(strict=True)
            if _path_inside(key_path, repo.resolve(strict=False)) or _path_inside(key_path, run_dir.resolve(strict=False)):
                return "Actor proof key file must be outside the repository and run artifacts"
            key_text = key_path.read_text(encoding="utf-8").strip()
        except OSError:
            return "Actor proof key file is unavailable"
    if not key_text:
        return "Actor proof is required; set SDLC_ACTOR_PROOF_KEY or SDLC_ACTOR_PROOF_KEY_FILE outside the repo"
    if not proof:
        if action == "deploy.approve":
            return "Actor proof is required for production deployment approval"
        return "Actor proof is required for deployment residual-risk acceptance"
    if action == "deploy.approve":
        if not binding_sha256:
            return "Deployment approval proof requires approval evidence binding"
        message = f"{run_id}:deploy:{env}:{actor}:deploy.approve:{binding_sha256}".encode("utf-8")
    else:
        message = f"{run_id}:deploy:{env}:{actor}:deploy.verify_residual_risk".encode("utf-8")
    expected = hmac.new(key_text.encode("utf-8"), message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, proof):
        return "Actor proof verification failed"
    return None


def _authenticated_residual_risk_acceptance(record: dict[str, Any]) -> bool:
    return _latest_residual_risk_acceptance(record) is not None


def _latest_residual_risk_acceptance(record: dict[str, Any]) -> dict[str, Any] | None:
    for item in reversed(record.get("accepted_residual_risks", []) or []):
        if not isinstance(item, dict):
            continue
        if (
            item.get("risk")
            and item.get("accepted_by") in HUMAN_RESIDUAL_RISK_ACTORS
            and item.get("actor_proof_verified") is True
            and item.get("accepted_at")
        ):
            return item
    return None


def _path_inside(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def _load_deploy_events(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "events.jsonl"
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def _matching_deploy_event(run_dir: Path, events: list[dict[str, Any]], event_name: str) -> dict[str, Any] | None:
    for event in reversed(events):
        if event.get("event") != event_name:
            continue
        if event.get("env") != "production":
            continue
        if event_name in {"deploy.executed", "deploy.rollback_executed"} and event.get("returncode") != 0:
            continue
        evidence = [str(item) for item in event.get("evidence", [])]
        if "artifacts/deploy/production.json" not in evidence:
            continue
        if not event.get("record_sha256"):
            continue
        if not is_origin_authenticated_ledger_event(event, run_dir=run_dir):
            continue
        return event
    return None


def _has_deploy_event(events: list[dict[str, Any]], event_name: str) -> bool:
    run_dir = _infer_run_dir_from_events(events)
    return run_dir is not None and _matching_deploy_event(run_dir, events, event_name) is not None


def _events_in_order(all_events: list[dict[str, Any]], sequence: list[dict[str, Any]]) -> bool:
    positions = [_event_index(all_events, event) for event in sequence]
    ordered_positions = sorted(positions)
    return positions == ordered_positions


def _event_index(events: list[dict[str, Any]], target: dict[str, Any]) -> int:
    for index, event in enumerate(events):
        if event is target:
            return index
    return -1


def _event_has_artifact_sha(run_dir: Path, events: list[dict[str, Any]], event: dict[str, Any]) -> bool:
    digest = event.get("record_sha256")
    if not isinstance(digest, str) or not digest:
        return False
    return canonical_artifact_event(
        events,
        run_id=str(event.get("run_id") or run_dir.name),
        path="artifacts/deploy/production.json",
        sha256=digest,
        allowed_events={
            "deploy.approval_artifact",
            "deploy.execute_plan_artifact",
            "deploy.execution_artifact",
            "deploy.execution_failed_artifact",
            "deploy.execution_rejected_artifact",
            "deploy.plan_artifact",
            "deploy.rollback_artifact",
            "deploy.rollback_failed_artifact",
            "deploy.rollback_rejected_artifact",
            "deploy.verification_artifact",
        },
        require_origin=True,
        run_dir=run_dir,
    ) is not None


def _infer_run_dir_from_events(events: list[dict[str, Any]]) -> Path | None:
    for event in events:
        marker = event.get("_run_dir")
        if isinstance(marker, str):
            return Path(marker)
    return None


def _load_deploy_record(run_dir: Path, env: str) -> dict[str, Any]:
    _validate_env(env)
    return read_json(run_dir / "artifacts" / "deploy" / f"{env}.json", {})


def _write_deploy_record(ledger: Ledger, env: str, record: dict[str, Any], *, event: str) -> str:
    _validate_env(env)
    return ledger.artifact(
        f"artifacts/deploy/{env}.json",
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        event=event,
        env=env,
    )


def _approval_binding_payload(repo: Path, run_id: str, env: str, actor: str, evidence_paths: list[str]) -> dict[str, Any]:
    evidence_bindings: list[dict[str, Any]] = []
    for rel in evidence_paths:
        path = repo / rel
        content = path.read_bytes()
        evidence_bindings.append({
            "path": rel,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        })
    payload: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "environment": env,
        "actor": actor,
        "evidence": evidence_bindings,
    }
    payload["binding_sha256"] = _json_sha256(payload)
    return payload


def _artifact_sha256(run_dir: Path, relative_path: str) -> str:
    path = run_dir / relative_path
    if not path.exists():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json_sha256(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _resolve_evidence(repo: Path, evidence: list[str]) -> tuple[list[str], str | None]:
    return resolve_repo_paths(repo, evidence, required=True)


def _validate_command(command: str | None, label: str) -> str | None:
    if not command or not command.strip():
        return f"{label} requires --command; no real command is configured"
    try:
        parsed = shlex.split(command)
    except ValueError as exc:
        return f"{label} command could not be parsed: {exc}"
    if not parsed:
        return f"{label} requires --command; no real command is configured"
    return None


def _command_record(command: str) -> list[str]:
    try:
        return shlex.split(redact_secrets(command))
    except ValueError:
        return [redact_secrets(command)]


def _validate_env(env: str) -> None:
    if env not in DEPLOY_ENVS:
        raise ValueError(f"Unsupported deploy environment: {env}")
