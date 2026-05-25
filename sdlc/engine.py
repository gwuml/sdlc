"""Gate engine and run operations."""

from __future__ import annotations

import hashlib
import sys
import json
import math
import re
import shutil
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

from .adapters import WorkerResult, _ensure_writable_worker_temp_dir, _worker_temp_dir, adapter_from_policy, capture_worker_result, worker_identity_group
from .audit_runtime import audit_isolation_preflight
from .ledger import Ledger
from .models import RunPlan, Finding, invalid_findings, open_findings, plan_condition_value
from .policies import load_policy
from .prompts import PROMPT_BINDING_RE, redteam_prompt_binding_sha256
from .scanners import run_security_scans, scan_notes, scan_verdict
from .util import find_files, git_current_branch, is_git_repo, now_iso, read_json, run_cmd, write_json
from .validation import validate_json_schema


DRY_GO_GATE_IDS = {
    "repo_context_env_branch",
    "baseline_freeze",
    "supply_chain_sbom",
    "deterministic_quality",
    "security_scans",
}
RUN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
EXTERNAL_WORKER_PROVIDERS = {"openai", "anthropic", "google", "moonshot"}


def validate_run_id(run_id: str) -> str:
    if not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("run_id must match ^[a-z0-9][a-z0-9-]{0,127}$")
    return run_id


class RunStore:
    def __init__(self, repo: Path):
        self.repo = repo.resolve()
        self.sdlc_dir = self.repo / ".sdlc"
        self.runs_dir = self.sdlc_dir / "runs"

    def run_dir(self, run_id: str) -> Path:
        run_id = validate_run_id(run_id)
        path = (self.runs_dir / run_id).resolve(strict=False)
        try:
            path.relative_to(self.runs_dir.resolve(strict=False))
        except ValueError as exc:
            raise ValueError(f"run_id escapes .sdlc/runs: {run_id}") from exc
        return path

    def plan_path(self, run_id: str) -> Path:
        return self.run_dir(run_id) / "plan.json"

    def findings_path(self, run_id: str) -> Path:
        return self.run_dir(run_id) / "findings.json"

    def load_plan(self, run_id: str) -> RunPlan:
        data = read_json(self.plan_path(run_id))
        if data is None:
            raise FileNotFoundError(f"Run not found: {run_id}")
        return RunPlan.from_dict(data)

    def save_plan(self, plan: RunPlan) -> None:
        write_json(self.plan_path(plan.run_id), plan.to_dict())

    def load_findings(self, run_id: str) -> list[Finding]:
        data = read_json(self.findings_path(run_id), [])
        return [Finding.from_dict(item) for item in data]

    def save_findings(self, run_id: str, findings: list[Finding]) -> None:
        write_json(self.findings_path(run_id), [finding.to_dict() for finding in findings])


def deterministic_artifacts_for_gate(plan: RunPlan, gate_id: str, run_dir: Path) -> tuple[str, list[str], str | None]:
    repo = Path(plan.repo)
    artifacts: list[str] = []
    content_lines: list[str] = []
    verdict_override: str | None = None

    def append_command(cmd: list[str]) -> dict[str, Any]:
        result = run_cmd(cmd, repo)
        content_lines.append(f"$ {' '.join(cmd)}")
        content_lines.append(f"returncode: {result['returncode']}")
        content_lines.append("stdout:")
        content_lines.append(result["stdout"] or "<empty>")
        content_lines.append("stderr:")
        content_lines.append(result["stderr"] or "<empty>")
        return result

    if gate_id == "repo_context_env_branch":
        failures: list[str] = []
        inside = append_command(["git", "rev-parse", "--is-inside-work-tree"])
        branch = append_command(["git", "branch", "--show-current"])
        status = append_command(["git", "status", "--short", "--branch"])
        content_lines.append(f"is_git_repo: {is_git_repo(repo)}")
        content_lines.append(f"current_branch: {git_current_branch(repo)}")
        if inside["returncode"] != 0 or inside["stdout"].strip() != "true":
            failures.append("git rev-parse --is-inside-work-tree")
        if branch["returncode"] != 0 or not branch["stdout"].strip():
            failures.append("git branch --show-current")
        if status["returncode"] != 0:
            failures.append("git status --short --branch")
        if failures:
            verdict_override = "NO_GO"
            content_lines.append("git_context_failures:")
            content_lines.extend(f"- {item}" for item in failures)
    elif gate_id == "baseline_freeze":
        commands = [["git", "status", "--short", "--branch"], ["git", "diff", "--stat"], ["git", "rev-parse", "HEAD"]]
        failures: list[str] = []
        for cmd in commands:
            result = append_command(cmd)
            if result["returncode"] != 0:
                failures.append(" ".join(cmd))
        if failures:
            verdict_override = "NO_GO"
            content_lines.append("baseline_git_failures:")
            content_lines.extend(f"- {item}" for item in failures)
    elif gate_id == "supply_chain_sbom":
        lockfiles = find_files(repo, ["**/package-lock.json", "**/pnpm-lock.yaml", "**/yarn.lock", "**/poetry.lock", "**/requirements*.txt", "**/Cargo.lock", "**/go.sum"])
        content_lines.append("lockfiles:")
        content_lines.extend(f"- {path}" for path in lockfiles or ["<none found>"])
    elif gate_id == "deterministic_quality":
        candidates = []
        failures: list[str] = []
        if (repo / "pyproject.toml").exists() or (repo / "tests").exists():
            candidates.append([sys.executable, "-m", "unittest", "discover", "-s", "tests"])
        if (repo / "package.json").exists():
            candidates.append(["npm", "test", "--", "--runInBand"])
        if not candidates:
            content_lines.append("No deterministic test command detected. Gate requires manual evidence before GO in non-dry-run mode.")
            verdict_override = "NO_GO"
        for cmd in candidates[:2]:
            result = run_cmd(cmd, repo, timeout=120)
            content_lines.append(f"$ {' '.join(cmd)}")
            content_lines.append(f"returncode: {result['returncode']}")
            content_lines.append(result["stdout"] or result["stderr"] or "<empty>")
            if result["returncode"] != 0:
                failures.append(" ".join(cmd))
        if failures:
            verdict_override = "NO_GO"
            content_lines.append("failing_commands:")
            content_lines.extend(f"- {item}" for item in failures)
    elif gate_id == "security_scans":
        results, scan_artifacts = run_security_scans(
            repo=repo,
            run_dir=run_dir,
            run_id=plan.run_id,
            policy=load_policy(repo, plan.policy_profile),
            risk_level=plan.risk_level,
            allow_network=False,
        )
        artifacts.extend(scan_artifacts)
        verdict_override = scan_verdict(results)
        content_lines.append(scan_notes(results))
        for result in results:
            content_lines.append(f"{result.scanner}: {result.status} ({result.artifact})")
    else:
        content_lines.append(f"Gate {gate_id} requires agent/human evidence. This placeholder is not sufficient for production GO.")

    artifact_rel = f"artifacts/{gate_id}.md"
    (run_dir / artifact_rel).parent.mkdir(parents=True, exist_ok=True)
    (run_dir / artifact_rel).write_text("\n".join(content_lines) + "\n", encoding="utf-8")
    artifacts.append(artifact_rel)
    return "\n".join(content_lines), artifacts, verdict_override


def mark_gate(plan: RunPlan, gate_id: str, state: str, verdict: str | None, evidence: list[str], notes: str = "") -> None:
    for gate in plan.gates:
        if gate.id == gate_id:
            gate.state = state
            gate.verdict = verdict
            gate.evidence.extend(evidence)
            gate.notes = notes
            return
    raise KeyError(gate_id)


def invalidate_downstream_gates(plan: RunPlan, gate_order: int, reason: str) -> list[str]:
    invalidated: list[str] = []
    for gate in sorted(plan.gates, key=lambda item: item.order):
        if gate.order <= gate_order or gate.state in {"SKIPPED", "WAIVED"}:
            continue
        if gate.state == "GO" or gate.verdict in {"GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"}:
            gate.state = "BLOCKED"
            gate.verdict = "NO_GO"
            gate.notes = reason
            invalidated.append(gate.id)
    return invalidated


def _dry_gate_satisfied(gate: Any) -> bool:
    if gate.state == "WAIVED":
        return True
    if gate.state == "SKIPPED":
        return gate.verdict == "SKIPPED"
    return gate.state == "GO" and gate.verdict in {"GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"}


def _prior_dry_gate_blockers(plan: RunPlan, gate_order: int) -> list[str]:
    return [
        gate.id
        for gate in sorted(plan.gates, key=lambda item: item.order)
        if gate.order < gate_order and not _dry_gate_satisfied(gate)
    ]


def run_dry_gates(store: RunStore, run_id: str) -> RunPlan:
    plan = store.load_plan(run_id)
    run_dir = store.run_dir(run_id)
    ledger = Ledger(run_dir, run_id)
    context = {
        "has_ui": bool(plan.classification.get("has_ui")),
        "production_rollout_allowed": plan.production_rollout_allowed,
    }

    for gate in sorted(plan.gates, key=lambda item: item.order):
        if gate.state in {"GO", "SKIPPED", "WAIVED"}:
            continue
        if gate.conditional_on and not context.get(gate.conditional_on, False):
            gate.state = "SKIPPED"
            gate.verdict = "SKIPPED"
            gate.notes = f"Conditional gate skipped because {gate.conditional_on}=false"
            ledger.event("gate.skipped", gate=gate.id, reason=gate.notes)
            continue
        blockers = _prior_dry_gate_blockers(plan, gate.order)
        if blockers:
            gate.state = "BLOCKED"
            gate.verdict = "NO_GO"
            gate.notes = "Blocked because prerequisite gates are unresolved: " + ", ".join(blockers)
            ledger.event("gate.blocked", gate=gate.id, blockers=blockers, notes=gate.notes)
            continue
        gate.state = "RUNNING"
        ledger.event("gate.started", gate=gate.id, owner=gate.owner)
        _content, artifacts, verdict_override = deterministic_artifacts_for_gate(plan, gate.id, run_dir)
        # Agent/human gates need substantive evidence, so the dry engine never
        # converts placeholder artifacts into positive gate results.
        if gate.id not in DRY_GO_GATE_IDS:
            gate.state = "FIX_REQUIRED" if gate.id != "independent_redteam_cross_model" else "NO_GO"
            gate.verdict = "NO_GO"
            gate.notes = "Agent or human evidence required; dry-run placeholder cannot mark this gate GO."
            invalidated = invalidate_downstream_gates(plan, gate.order, f"Blocked because prerequisite gate {gate.id} is NO_GO.")
            ledger.event("gate.no_go", gate=gate.id, evidence=artifacts, notes=gate.notes)
            if invalidated:
                ledger.event("gate.downstream_invalidated", gate=gate.id, invalidated=invalidated)
        elif verdict_override == "NO_GO":
            gate.state = "NO_GO"
            gate.verdict = "NO_GO"
            gate.notes = _content or "Deterministic gate evidence returned NO_GO."
            invalidated = invalidate_downstream_gates(plan, gate.order, f"Blocked because prerequisite gate {gate.id} is NO_GO.")
            ledger.event("gate.no_go", gate=gate.id, evidence=artifacts, notes=gate.notes)
            if invalidated:
                ledger.event("gate.downstream_invalidated", gate=gate.id, invalidated=invalidated)
        else:
            gate.state = "GO"
            gate.verdict = "GO"
            gate.notes = "Dry deterministic artifact captured. Production use requires reviewing evidence quality."
            ledger.event("gate.completed", gate=gate.id, verdict="GO", evidence=artifacts)
        gate.evidence.extend(artifacts)
    store.save_plan(plan)
    return plan


def create_redteam_findings(store: RunStore, run_id: str) -> list[Finding]:
    plan = store.load_plan(run_id)
    findings = store.load_findings(run_id)
    existing_ids = {finding.id for finding in findings}
    next_findings: list[Finding] = []

    if any(gate.id == "implementation" and gate.verdict != "GO" for gate in plan.gates):
        if "HIGH-001" not in existing_ids:
            next_findings.append(Finding(
                id="HIGH-001",
                severity="HIGH",
                title="Implementation gate has no accepted code-diff evidence",
                evidence=["plan.gates.implementation.verdict != GO"],
                impact="Cannot prove the requested feature was implemented or bounded to approved write paths.",
                required_fix="Run the implementation worker under constrained permissions, capture code diff, and re-run focused validation.",
                owner="agent_3_implementation_owner",
            ))

    if plan.risk_level in {"HIGH", "EXTREME"} and not any(gate.id == "security_scans" and gate.verdict == "GO" for gate in plan.gates):
        if "HIGH-002" not in existing_ids:
            next_findings.append(Finding(
                id="HIGH-002",
                severity="HIGH",
                title="High-stakes run lacks completed security scan evidence",
                evidence=["risk_level in HIGH/EXTREME", "security_scans.verdict != GO"],
                impact="Security or operational flaws may be missed before a user relies on the output.",
                required_fix="Run SAST/dependency/secret/IaC scans or document unavailable tools with compensating manual review evidence.",
                owner="agent_8_cybersecurity_engineer",
            ))

    findings.extend(next_findings)
    store.save_findings(run_id, findings)
    Ledger(store.run_dir(run_id), run_id).event("redteam.findings_created", count=len(next_findings), findings=[f.id for f in next_findings])
    return findings


def execute_redteam_workers(
    store: RunStore,
    run_id: str,
    *,
    workers: list[str],
    rounds: int,
    execute: bool,
    timeout: int = 120,
    total_timeout: int | None = None,
    allow_network: bool = False,
    parallel_per_round: bool = False,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    plan = store.load_plan(run_id)
    run_dir = store.run_dir(run_id)
    repo = Path(plan.repo)
    ledger = Ledger(run_dir, run_id)
    prompt_path = run_dir / "prompts" / "redteam_prompt.md"
    prompt_text = prompt_path.read_text(encoding="utf-8") if prompt_path.exists() else ""
    prompt_binding = _prompt_binding_from_text(prompt_text)
    expected_prompt_binding = _recorded_redteam_prompt_binding(run_dir)
    if expected_prompt_binding and prompt_binding != expected_prompt_binding:
        ledger.event(
            "redteam.prompt_binding_mismatch",
            expected_sha256=expected_prompt_binding,
            actual_sha256=prompt_binding,
            prompt_path="prompts/redteam_prompt.md",
        )
        prompt_binding = ""
    findings = store.load_findings(run_id)
    policy = load_policy(repo, plan.policy_profile)
    redteam_policy = policy.get("redteam", {})
    rounds = max(1, rounds)
    worker_timeout = max(1, int(timeout or 1))
    total_timeout_seconds = int(total_timeout) if total_timeout else None
    min_rounds = int(redteam_policy.get("min_rounds_high_stakes", 1) or 1)
    high_stakes = plan.risk_level in {"HIGH", "EXTREME"}
    parallel_allowed = bool(redteam_policy.get("parallel_per_round_allowed", False))
    parallel_enabled = bool(execute and parallel_per_round and parallel_allowed)
    deadline = time.monotonic() + total_timeout_seconds if total_timeout_seconds else None

    def emit_progress(event: str, **payload: Any) -> None:
        if progress is not None:
            progress({
                "event": event,
                "run_id": run_id,
                "execute_requested": execute,
                "worker_timeout_seconds": worker_timeout,
                "total_timeout_seconds": total_timeout_seconds,
                "parallel_per_round_requested": parallel_per_round,
                "parallel_per_round_enabled": parallel_enabled,
                **payload,
            })

    ledger.event(
        "redteam.execution_started",
        workers=workers,
        rounds=rounds,
        execute_requested=execute,
        worker_timeout_seconds=worker_timeout,
        total_timeout_seconds=total_timeout_seconds,
        parallel_per_round_requested=parallel_per_round,
        parallel_per_round_enabled=parallel_enabled,
    )
    emit_progress("redteam.execution_started", workers=workers, rounds=rounds)
    provider_error = _redteam_allowed_provider_error(workers, policy, redteam_policy)
    if provider_error:
        notes = provider_error
        summary = _write_redteam_execution_summary(
            ledger,
            workers=workers,
            rounds=rounds,
            execute=execute,
            unavailable=workers,
            available_families=[],
            executed_families=[],
            executed_identity_groups=[],
            parsed_findings=[],
            verdict="NO_GO",
            notes=notes,
            worker_timeout_seconds=worker_timeout,
            total_timeout_seconds=total_timeout_seconds,
            parallel_per_round_requested=parallel_per_round,
            parallel_per_round_enabled=parallel_enabled,
        )
        _set_redteam_gate(store, plan, summary, [], "NO_GO", notes)
        ledger.event("redteam.execution_rejected", reason=notes, evidence=[summary])
        ledger.event(
            "redteam.execution_completed",
            verdict="NO_GO",
            workers=workers,
            rounds=rounds,
            execute_requested=execute,
            available_families=[],
            executed_families=[],
            executed_identity_groups=[],
            unavailable=workers,
            parsed_findings=[],
            worker_verdicts=[],
            mutation_violations=[],
            evidence=[summary],
            rejected=True,
            worker_timeout_seconds=worker_timeout,
            total_timeout_seconds=total_timeout_seconds,
            parallel_per_round_requested=parallel_per_round,
            parallel_per_round_enabled=parallel_enabled,
        )
        emit_progress("redteam.execution_rejected", verdict="NO_GO", reason=notes)
        return {
            "verdict": "NO_GO",
            "notes": notes,
            "summary": summary,
            "worker_results": [],
            "parsed_findings": [],
            "unavailable": workers,
            "available_families": [],
            "executed_families": [],
            "executed_identity_groups": [],
            "timed_out_workers": [],
            "skipped_due_total_timeout": [],
            "parallel_per_round_enabled": parallel_enabled,
        }
    if execute and high_stakes and rounds < min_rounds:
        notes = f"High-stakes red-team requires at least {min_rounds} rounds by policy; requested {rounds}."
        summary = _write_redteam_execution_summary(
            ledger,
            workers=workers,
            rounds=rounds,
            execute=execute,
            unavailable=[],
            available_families=[],
            executed_families=[],
            executed_identity_groups=[],
            parsed_findings=[],
            verdict="NO_GO",
            notes=notes,
            worker_timeout_seconds=worker_timeout,
            total_timeout_seconds=total_timeout_seconds,
            parallel_per_round_requested=parallel_per_round,
            parallel_per_round_enabled=parallel_enabled,
        )
        _set_redteam_gate(store, plan, summary, [], "NO_GO", notes)
        ledger.event("redteam.execution_rejected", reason=notes, evidence=[summary])
        ledger.event(
            "redteam.execution_completed",
            verdict="NO_GO",
            workers=workers,
            rounds=rounds,
            execute_requested=execute,
            available_families=[],
            executed_families=[],
            executed_identity_groups=[],
            unavailable=[],
            parsed_findings=[],
            worker_verdicts=[],
            mutation_violations=[],
            evidence=[summary],
            rejected=True,
            worker_timeout_seconds=worker_timeout,
            total_timeout_seconds=total_timeout_seconds,
            parallel_per_round_requested=parallel_per_round,
            parallel_per_round_enabled=parallel_enabled,
        )
        emit_progress("redteam.execution_rejected", verdict="NO_GO", reason=notes)
        return {
            "verdict": "NO_GO",
            "notes": notes,
            "summary": summary,
            "worker_results": [],
            "parsed_findings": [],
            "unavailable": [],
            "available_families": [],
            "executed_families": [],
            "executed_identity_groups": [],
            "timed_out_workers": [],
            "skipped_due_total_timeout": [],
            "parallel_per_round_enabled": parallel_enabled,
        }
    if execute and not (allow_network and bool(policy.get("network_allowed", False))):
        notes = "Executed worker red-team requires --allow-network and policy network_allowed=true."
        summary = _write_redteam_execution_summary(
            ledger,
            workers=workers,
            rounds=rounds,
            execute=execute,
            unavailable=[],
            available_families=[],
            executed_families=[],
            executed_identity_groups=[],
            parsed_findings=[],
            verdict="NO_GO",
            notes=notes,
            worker_timeout_seconds=worker_timeout,
            total_timeout_seconds=total_timeout_seconds,
            parallel_per_round_requested=parallel_per_round,
            parallel_per_round_enabled=parallel_enabled,
        )
        _set_redteam_gate(store, plan, summary, [], "NO_GO", notes)
        ledger.event("redteam.execution_rejected", reason=notes, evidence=[summary])
        ledger.event(
            "redteam.execution_completed",
            verdict="NO_GO",
            workers=workers,
            rounds=rounds,
            execute_requested=execute,
            available_families=[],
            executed_families=[],
            executed_identity_groups=[],
            unavailable=[],
            parsed_findings=[],
            worker_verdicts=[],
            mutation_violations=[],
            evidence=[summary],
            rejected=True,
            worker_timeout_seconds=worker_timeout,
            total_timeout_seconds=total_timeout_seconds,
            parallel_per_round_requested=parallel_per_round,
            parallel_per_round_enabled=parallel_enabled,
        )
        emit_progress("redteam.execution_rejected", verdict="NO_GO", reason=notes)
        return {
            "verdict": "NO_GO",
            "notes": notes,
            "summary": summary,
            "worker_results": [],
            "parsed_findings": [],
            "unavailable": [],
            "available_families": [],
            "executed_families": [],
            "executed_identity_groups": [],
            "timed_out_workers": [],
            "skipped_due_total_timeout": [],
            "parallel_per_round_enabled": parallel_enabled,
        }
    if execute and parallel_per_round and not parallel_allowed:
        notes = "Parallel red-team per-round execution requires redteam.parallel_per_round_allowed=true in policy."
        summary = _write_redteam_execution_summary(
            ledger,
            workers=workers,
            rounds=rounds,
            execute=execute,
            unavailable=[],
            available_families=[],
            executed_families=[],
            executed_identity_groups=[],
            parsed_findings=[],
            verdict="NO_GO",
            notes=notes,
            worker_timeout_seconds=worker_timeout,
            total_timeout_seconds=total_timeout_seconds,
            parallel_per_round_requested=parallel_per_round,
            parallel_per_round_enabled=parallel_enabled,
        )
        _set_redteam_gate(store, plan, summary, [], "NO_GO", notes)
        ledger.event("redteam.execution_rejected", reason=notes, evidence=[summary])
        ledger.event(
            "redteam.execution_completed",
            verdict="NO_GO",
            workers=workers,
            rounds=rounds,
            execute_requested=execute,
            available_families=[],
            executed_families=[],
            executed_identity_groups=[],
            unavailable=[],
            parsed_findings=[],
            worker_verdicts=[],
            mutation_violations=[],
            evidence=[summary],
            rejected=True,
            worker_timeout_seconds=worker_timeout,
            total_timeout_seconds=total_timeout_seconds,
            parallel_per_round_requested=parallel_per_round,
            parallel_per_round_enabled=parallel_enabled,
        )
        emit_progress("redteam.execution_rejected", verdict="NO_GO", reason=notes)
        return {
            "verdict": "NO_GO",
            "notes": notes,
            "summary": summary,
            "worker_results": [],
            "parsed_findings": [],
            "unavailable": [],
            "available_families": [],
            "executed_families": [],
            "executed_identity_groups": [],
            "timed_out_workers": [],
            "skipped_due_total_timeout": [],
            "parallel_per_round_enabled": parallel_enabled,
        }
    worker_results: list[dict[str, Any]] = []
    parsed_findings: list[Finding] = []
    worker_verdicts: list[dict[str, str]] = []
    unavailable: list[str] = []
    available_families: set[str] = set()
    executed_families: set[str] = set()
    timed_out_workers: list[str] = []
    truncated_workers: list[str] = []
    skipped_due_total_timeout: list[str] = []
    hard_isolated_workers: list[str] = []
    audit_isolation_attestations: list[str] = []
    worker_providers: dict[str, str] = {}
    active_worker: str | None = None
    active_round: int | None = None

    redteam_before = _repo_snapshot(repo, include_run_artifacts=True) if execute else {}
    redteam_journal = _MutationJournal(repo, redteam_before, include_run_artifacts=True) if execute else None
    mutation_violations: list[str] = []

    def worker_timeout_remaining() -> tuple[int | None, str]:
        if deadline is None:
            return worker_timeout, "per_worker"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, "total_command"
        effective = max(1, min(worker_timeout, math.ceil(remaining)))
        scope = "total_command" if effective < worker_timeout else "per_worker"
        return effective, scope

    def record_unavailable(worker: str, round_number: int) -> None:
        unavailable.append(worker)
        artifact = ledger.artifact(
            f"artifacts/redteam/round-{round_number}-{worker}-unavailable.json",
            json.dumps({"worker": worker, "round": round_number, "available": False, "reason": "unknown worker"}, indent=2, sort_keys=True) + "\n",
            event="redteam.worker_unavailable",
            worker=worker,
            round=round_number,
        )
        worker_results.append({"worker": worker, "round": round_number, "available": False, "artifact": artifact})
        emit_progress("redteam.worker_unavailable", worker=worker, round=round_number, reason="unknown worker")

    def record_rejected(worker: str, round_number: int) -> None:
        unavailable.append(worker)
        artifact = ledger.artifact(
            f"artifacts/redteam/round-{round_number}-{worker}-write-isolation-missing.json",
            json.dumps({
                "worker": worker,
                "round": round_number,
                "available": True,
                "executed": False,
                "reason": "SECURITY_REVIEW adapter does not declare read-only source isolation",
            }, indent=2, sort_keys=True) + "\n",
            event="redteam.worker_rejected",
            worker=worker,
            round=round_number,
            reason="security_review_write_isolation_missing",
        )
        worker_results.append({"worker": worker, "round": round_number, "available": True, "executed": False, "artifact": artifact})
        emit_progress("redteam.worker_rejected", worker=worker, round=round_number, reason="security_review_write_isolation_missing")

    def record_hard_isolation_rejected(worker: str, round_number: int, adapter: Any, preflight: Any | None = None) -> None:
        unavailable.append(worker)
        provider = str(getattr(adapter, "provider", "unknown"))
        reason = (
            str(getattr(preflight, "reason", "") or "").strip()
            or "No qualifying container/VM hard audit isolation runtime was available for this worker."
        )
        attestation = getattr(preflight, "attestation", None)
        attestation_artifact = None
        if isinstance(attestation, dict):
            attestation_artifact = ledger.artifact(
                f"artifacts/redteam/round-{round_number}-{worker}-isolation-attestation.json",
                json.dumps(attestation, indent=2, sort_keys=True) + "\n",
                event="redteam.isolation_attestation_written",
                worker=worker,
                provider=provider,
                round=round_number,
                hard_isolation=False,
                method=attestation.get("method"),
            )
            audit_isolation_attestations.append(attestation_artifact)
        artifact = ledger.artifact(
            f"artifacts/redteam/round-{round_number}-{worker}-hard-source-isolation-unavailable.json",
            json.dumps({
                "worker": worker,
                "provider": provider,
                "round": round_number,
                "available": True,
                "executed": False,
                "reason": reason,
                "isolation_attestation": attestation_artifact,
            }, indent=2, sort_keys=True) + "\n",
            event="redteam.worker_rejected",
            worker=worker,
            provider=provider,
            round=round_number,
            reason="audit_source_hard_readonly_isolation_unavailable",
            detail=reason,
            isolation_attestation=attestation_artifact,
        )
        worker_results.append({"worker": worker, "round": round_number, "available": True, "executed": False, "artifact": artifact})
        emit_progress(
            "redteam.worker_rejected",
            worker=worker,
            round=round_number,
            reason="audit_source_hard_readonly_isolation_unavailable",
        )

    def redteam_worker_preflight(worker: str, round_number: int) -> Any | None:
        adapter = adapter_from_policy(worker, policy)
        if adapter is None:
            record_unavailable(worker, round_number)
            return None
        worker_providers[worker] = str(getattr(adapter, "provider", "unknown")).strip().lower() or "unknown"
        if hasattr(adapter, "_sdlc_hard_audit_isolation_method"):
            delattr(adapter, "_sdlc_hard_audit_isolation_method")
        if execute and not adapter.security_review_write_protected(policy):
            record_rejected(worker, round_number)
            return None
        if execute and _external_hard_audit_isolation_required(plan, redteam_policy, adapter):
            preflight = audit_isolation_preflight(
                policy=policy,
                repo=repo,
                worker=worker,
                provider=worker_providers[worker],
                prompt_sha256=prompt_binding,
                allow_network=allow_network,
            )
            ledger.event(
                "redteam.isolation_runtime_selected",
                worker=worker,
                provider=worker_providers[worker],
                round=round_number,
                requested_kind=preflight.requested_kind,
                runtime_kind=preflight.runtime_kind,
                method=preflight.method,
                hard_isolation=preflight.hard_isolation,
                advisory_isolation=preflight.advisory_isolation,
            )
            ledger.event(
                "redteam.isolation_preflight_result",
                worker=worker,
                provider=worker_providers[worker],
                round=round_number,
                available=preflight.available,
                hard_isolation=preflight.hard_isolation,
                advisory_isolation=preflight.advisory_isolation,
                method=preflight.method,
                reason=preflight.reason,
            )
            probe = preflight.attestation.get("source_write_probe") if isinstance(preflight.attestation, dict) else {}
            ledger.event(
                "redteam.isolation_readonly_source_probe",
                worker=worker,
                round=round_number,
                method=preflight.method,
                attempted=bool(isinstance(probe, dict) and probe.get("attempted")),
                passed=bool(isinstance(probe, dict) and probe.get("passed")),
            )
            ledger.event(
                "redteam.isolation_credential_result",
                worker=worker,
                round=round_number,
                method=preflight.method,
                auth_mode=preflight.auth_mode,
                host_credential_dirs_mounted=bool(preflight.attestation.get("host_credential_dirs_mounted")) if isinstance(preflight.attestation, dict) else True,
            )
            ledger.event(
                "redteam.isolation_network_policy",
                worker=worker,
                round=round_number,
                method=preflight.method,
                network_mode=preflight.network_mode,
                policy_allow_network=allow_network,
            )
            if not preflight.hard_isolation or not preflight.adapter_config:
                ledger.event(
                    "redteam.isolation_failure",
                    worker=worker,
                    provider=worker_providers[worker],
                    round=round_number,
                    method=preflight.method,
                    reason=preflight.reason,
                )
                record_hard_isolation_rejected(worker, round_number, adapter, preflight)
                return None
            setattr(adapter, "_sdlc_audit_isolation_config", preflight.adapter_config)
        return adapter

    def record_total_timeout_skip(worker: str, round_number: int) -> None:
        label = f"{worker}@round{round_number}"
        skipped_due_total_timeout.append(label)
        artifact = ledger.artifact(
            f"artifacts/redteam/round-{round_number}-{worker}-total-timeout.json",
            json.dumps({
                "worker": worker,
                "round": round_number,
                "available": None,
                "executed": False,
                "timed_out": True,
                "timeout_scope": "total_command",
                "total_timeout_seconds": total_timeout_seconds,
                "worker_timeout_seconds": worker_timeout,
                "reason": "total command timeout expired before this worker could start",
            }, indent=2, sort_keys=True) + "\n",
            event="redteam.worker_timeout_skipped",
            worker=worker,
            round=round_number,
            total_timeout_seconds=total_timeout_seconds,
            worker_timeout_seconds=worker_timeout,
        )
        worker_results.append({
            "worker": worker,
            "round": round_number,
            "available": None,
            "executed": False,
            "timed_out": True,
            "timeout_scope": "total_command",
            "artifact": artifact,
        })
        emit_progress("redteam.worker_skipped", worker=worker, round=round_number, reason="total command timeout expired")

    def run_redteam_worker(adapter: Any, worker: str, round_number: int, effective_timeout: int, timeout_scope: str) -> tuple[str, int, WorkerResult, list[str]]:
        audit_temp: tempfile.TemporaryDirectory | None = None
        worker_repo = repo
        audit_before: dict[str, str] = {}
        audit_mutations: list[str] = []
        audit_journal: _MutationJournal | None = None
        if execute:
            audit_temp, worker_repo = _create_audit_workspace(repo)
            audit_before = _repo_snapshot(worker_repo)
            audit_journal = _MutationJournal(worker_repo, audit_before)
        try:
            review_mode = "SECURITY_REVIEW_AUDIT_WORKSPACE" if execute and audit_temp is not None else "SECURITY_REVIEW"
            if execute and audit_temp is not None:
                temp_dir = _worker_temp_dir(prompt_path, worker_repo, review_mode, run_id=plan.run_id)
                try:
                    _ensure_writable_worker_temp_dir(temp_dir)
                except OSError as exc:
                    ledger.event(
                        "redteam.worker_rejected",
                        worker=worker,
                        round=round_number,
                        reason="audit_worker_tempdir_unavailable",
                        temp_dir=str(temp_dir),
                        error=str(exc),
                    )
                    now = now_iso()
                    return worker, round_number, WorkerResult(
                        worker,
                        True,
                        False,
                        [],
                        126,
                        "",
                        f"Audit worker temp directory is not writable: {exc}",
                        now,
                        now,
                        mode=review_mode,
                        timeout_seconds=effective_timeout,
                    ), []
            if audit_journal is not None:
                audit_journal.start()
            result = adapter.run(prompt_path, worker_repo, review_mode, execute=execute, timeout=effective_timeout)
            if result.timed_out:
                result.timeout_scope = timeout_scope
            if execute and audit_temp is not None:
                audit_mutations = _repo_mutations(worker_repo, audit_before)
        finally:
            if audit_journal is not None:
                audit_mutations = sorted(set(audit_mutations + audit_journal.stop()))
            if audit_temp is not None:
                _make_tree_writable(worker_repo)
                audit_temp.cleanup()
        return worker, round_number, result, audit_mutations

    def record_worker_result(worker: str, round_number: int, result: WorkerResult, audit_mutations: list[str]) -> None:
        if execute and audit_mutations:
            tagged = [f"audit_workspace:{path}" for path in audit_mutations]
            mutation_violations.extend(tagged)
            ledger.event("redteam.worker_policy_violation", worker=worker, round=round_number, audit_workspace_mutations=audit_mutations)
        captured = capture_worker_result(
            run_dir=run_dir,
            mode=f"REDTEAM_ROUND_{round_number}",
            prompt_path=prompt_path,
            result=result,
            ledger=ledger,
        )
        captured["round"] = round_number
        worker_results.append(captured)
        if result.timed_out:
            timeout_label = f"{worker}@round{round_number}:{result.timeout_scope or 'per_worker'}:{result.timeout_seconds or worker_timeout}s"
            timed_out_workers.append(timeout_label)
        if result.stdout_truncated or result.stderr_truncated:
            streams = []
            if result.stdout_truncated:
                streams.append("stdout")
            if result.stderr_truncated:
                streams.append("stderr")
            truncated_label = f"{worker}@round{round_number}:{'+'.join(streams)}:{result.max_output_chars or 'unknown'}chars"
            truncated_workers.append(truncated_label)
            ledger.event(
                "redteam.worker_output_truncated",
                worker=worker,
                round=round_number,
                stdout_truncated=result.stdout_truncated,
                stderr_truncated=result.stderr_truncated,
                max_output_chars=result.max_output_chars,
            )
        if result.available:
            available_families.add(worker)
        else:
            unavailable.append(worker)
        if result.hard_audit_isolation:
            method = result.hard_audit_isolation_method or "unknown"
            label = f"{worker}@round{round_number}:{method}"
            hard_isolated_workers.append(label)
            ledger.event(
                "redteam.worker_hard_audit_isolated",
                worker=worker,
                round=round_number,
                method=method,
            )
        if result.advisory_audit_isolation:
            ledger.event(
                "redteam.worker_advisory_audit_isolated",
                worker=worker,
                round=round_number,
                method=result.advisory_audit_isolation_method or "unknown",
            )
        if isinstance(result.audit_isolation_attestation, dict):
            artifact = ledger.artifact(
                f"artifacts/redteam/round-{round_number}-{worker}-runtime-attestation.json",
                json.dumps(result.audit_isolation_attestation, indent=2, sort_keys=True) + "\n",
                event="redteam.isolation_attestation_written",
                worker=worker,
                provider=worker_providers.get(worker, "unknown"),
                round=round_number,
                hard_isolation=result.hard_audit_isolation,
                method=result.hard_audit_isolation_method,
            )
            audit_isolation_attestations.append(artifact)
            ledger.event(
                "redteam.isolation_process_cleanup_result",
                worker=worker,
                round=round_number,
                method=result.hard_audit_isolation_method,
                passed=bool(result.audit_isolation_attestation.get("process_cleanup_ok")),
            )
        declared_verdict = _worker_declared_verdict(result.stdout)
        if declared_verdict:
            context_attested = _worker_attested_review(result.stdout, plan.run_id, prompt_binding)
            worker_verdicts.append({
                "worker": worker,
                "round": str(round_number),
                "verdict": declared_verdict,
                "context_attested": context_attested,
            })
            ledger.event("redteam.worker_verdict", worker=worker, round=round_number, verdict=declared_verdict, context_attested=context_attested)
            if declared_verdict in {"GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"} and not context_attested:
                ledger.event("redteam.worker_context_unverified", worker=worker, round=round_number, run_id=plan.run_id, prompt_sha256=prompt_binding)
        if result.executed and result.returncode == 0 and result.stdout.strip():
            executed_families.add(worker)
        new_findings = _parse_worker_findings(repo, run_dir, worker, result.stdout, findings, ledger)
        if new_findings:
            parsed_findings.extend(new_findings)
            findings.extend(new_findings)
            store.save_findings(run_id, findings)
            _refresh_report_after_redteam_findings(repo, run_id, ledger)
            ledger.event(
                "redteam.findings_persisted",
                worker=worker,
                round=round_number,
                findings=[finding.id for finding in new_findings],
            )
        emit_progress(
            "redteam.worker_completed",
            worker=worker,
            round=round_number,
            available=result.available,
            executed=result.executed,
            returncode=result.returncode,
            timed_out=result.timed_out,
            timeout_seconds=result.timeout_seconds,
            timeout_scope=result.timeout_scope,
        )

    try:
        for round_number in range(1, rounds + 1):
            active_round = round_number
            emit_progress("redteam.round_started", round=round_number, workers=workers)
            ledger.event("redteam.round_started", round=round_number, workers=workers, parallel_per_round_enabled=parallel_enabled)
            if execute:
                redteam_before = _repo_snapshot(repo, include_run_artifacts=True)
                if redteam_journal is not None:
                    redteam_journal.reset(redteam_before)
            if parallel_enabled:
                runnable: list[tuple[str, Any, int, str]] = []
                for worker in workers:
                    adapter = redteam_worker_preflight(worker, round_number)
                    if adapter is None:
                        continue
                    effective_timeout, timeout_scope = worker_timeout_remaining()
                    if effective_timeout is None:
                        record_total_timeout_skip(worker, round_number)
                        continue
                    runnable.append((worker, adapter, effective_timeout, timeout_scope))
                    emit_progress("redteam.worker_started", worker=worker, round=round_number, timeout_seconds=effective_timeout, timeout_scope=timeout_scope)
                if runnable:
                    active_worker = f"parallel-round-{round_number}"
                    batch_before = _repo_snapshot(repo, include_run_artifacts=True)
                    batch_journal = _MutationJournal(repo, batch_before, include_run_artifacts=True)
                    batch_journal.start()
                    outcomes: list[tuple[str, int, WorkerResult, list[str]]] = []
                    try:
                        with ThreadPoolExecutor(max_workers=len(runnable)) as executor:
                            futures = [
                                executor.submit(run_redteam_worker, adapter, worker, round_number, effective_timeout, timeout_scope)
                                for worker, adapter, effective_timeout, timeout_scope in runnable
                            ]
                            for future in as_completed(futures):
                                outcomes.append(future.result())
                    finally:
                        journal_changes = batch_journal.stop()
                    changed = sorted(set(_repo_mutations(repo, batch_before, include_run_artifacts=True) + journal_changes))
                    if changed:
                        mutation_violations.extend(changed)
                        ledger.event("redteam.worker_policy_violation", workers=[item[0] for item in runnable], round=round_number, mutated_paths=changed)
                    for worker, worker_round, result, audit_mutations in outcomes:
                        record_worker_result(worker, worker_round, result, audit_mutations)
                    redteam_before = _repo_snapshot(repo, include_run_artifacts=True)
                    if redteam_journal is not None:
                        redteam_journal.reset(redteam_before)
            else:
                for worker in workers:
                    active_worker = worker
                    active_round = round_number
                    adapter = redteam_worker_preflight(worker, round_number)
                    if adapter is None:
                        if execute:
                            redteam_before = _repo_snapshot(repo, include_run_artifacts=True)
                            if redteam_journal is not None:
                                redteam_journal.reset(redteam_before)
                        continue
                    if execute:
                        redteam_before = _repo_snapshot(repo, include_run_artifacts=True)
                        if redteam_journal is not None:
                            redteam_journal.reset(redteam_before)
                    effective_timeout, timeout_scope = worker_timeout_remaining()
                    if effective_timeout is None:
                        record_total_timeout_skip(worker, round_number)
                        continue
                    emit_progress("redteam.worker_started", worker=worker, round=round_number, timeout_seconds=effective_timeout, timeout_scope=timeout_scope)
                    if redteam_journal is not None:
                        redteam_journal.start()
                    try:
                        worker_name, worker_round, result, audit_mutations = run_redteam_worker(adapter, worker, round_number, effective_timeout, timeout_scope)
                    finally:
                        if redteam_journal is not None:
                            redteam_journal.stop()
                    if execute:
                        journal_changes = redteam_journal.changes() if redteam_journal is not None else []
                        changed = sorted(set(_repo_mutations(repo, redteam_before, include_run_artifacts=True) + journal_changes))
                        if changed:
                            mutation_violations.extend(changed)
                            ledger.event("redteam.worker_policy_violation", worker=worker, round=round_number, mutated_paths=changed)
                    record_worker_result(worker_name, worker_round, result, audit_mutations)
                    if execute:
                        redteam_before = _repo_snapshot(repo, include_run_artifacts=True)
                        if redteam_journal is not None:
                            redteam_journal.reset(redteam_before)
            ledger.event("redteam.round_completed", round=round_number)
            emit_progress("redteam.round_completed", round=round_number)
    except KeyboardInterrupt:
        return _record_redteam_execution_interrupted(
            store=store,
            plan=plan,
            ledger=ledger,
            workers=workers,
            rounds=rounds,
            execute=execute,
            unavailable=sorted(set(unavailable)),
            available_families=sorted(available_families),
            executed_families=sorted(executed_families),
            parsed_findings=parsed_findings,
            worker_results=worker_results,
            worker_verdicts=worker_verdicts,
            mutation_violations=sorted(set(mutation_violations)),
            timed_out_workers=timed_out_workers,
            truncated_workers=truncated_workers,
            skipped_due_total_timeout=skipped_due_total_timeout,
            active_worker=active_worker,
            active_round=active_round,
            worker_timeout_seconds=worker_timeout,
            total_timeout_seconds=total_timeout_seconds,
            parallel_per_round_requested=parallel_per_round,
            parallel_per_round_enabled=parallel_enabled,
        )

    executed_identity_groups = {worker_identity_group(worker, policy) for worker in executed_families}
    verdict, notes = _redteam_execution_verdict(
        plan=plan,
        findings=findings,
        execute=execute,
        available_families=available_families,
        executed_families=executed_families,
        executed_identity_groups=executed_identity_groups,
        worker_verdicts=worker_verdicts,
        mutation_violations=sorted(set(mutation_violations)),
        timed_out_workers=timed_out_workers,
        truncated_workers=truncated_workers,
        skipped_due_total_timeout=skipped_due_total_timeout,
        cross_model_required=bool(redteam_policy.get("cross_model_required_for_high_or_extreme", True)),
    )
    summary = _write_redteam_execution_summary(
        ledger,
        workers=workers,
        rounds=rounds,
        execute=execute,
        unavailable=sorted(set(unavailable)),
        available_families=sorted(available_families),
        executed_families=sorted(executed_families),
        executed_identity_groups=sorted(executed_identity_groups),
        parsed_findings=parsed_findings,
        worker_verdicts=worker_verdicts,
        mutation_violations=sorted(set(mutation_violations)),
        timed_out_workers=timed_out_workers,
        truncated_workers=truncated_workers,
        skipped_due_total_timeout=skipped_due_total_timeout,
        hard_isolated_workers=hard_isolated_workers,
        worker_providers=worker_providers,
        audit_isolation_attestations=audit_isolation_attestations,
        verdict=verdict,
        notes=notes,
        worker_timeout_seconds=worker_timeout,
        total_timeout_seconds=total_timeout_seconds,
        parallel_per_round_requested=parallel_per_round,
        parallel_per_round_enabled=parallel_enabled,
    )
    _set_redteam_gate(store, plan, summary, worker_results, verdict, notes)
    ledger.event(
        "redteam.execution_completed",
        verdict=verdict,
        workers=workers,
        rounds=rounds,
        execute_requested=execute,
        available_families=sorted(available_families),
        executed_families=sorted(executed_families),
        executed_identity_groups=sorted(executed_identity_groups),
        unavailable=sorted(set(unavailable)),
        parsed_findings=[finding.id for finding in parsed_findings],
        worker_verdicts=worker_verdicts,
        mutation_violations=sorted(set(mutation_violations)),
        timed_out_workers=timed_out_workers,
        truncated_workers=truncated_workers,
        skipped_due_total_timeout=skipped_due_total_timeout,
        hard_isolated_workers=hard_isolated_workers,
        worker_providers=worker_providers,
        audit_isolation_attestations=audit_isolation_attestations,
        evidence=[summary],
        worker_timeout_seconds=worker_timeout,
        total_timeout_seconds=total_timeout_seconds,
        parallel_per_round_requested=parallel_per_round,
        parallel_per_round_enabled=parallel_enabled,
    )
    emit_progress("redteam.execution_completed", verdict=verdict, summary=summary)
    return {
        "verdict": verdict,
        "notes": notes,
        "summary": summary,
        "worker_results": worker_results,
        "parsed_findings": [finding.to_dict() for finding in parsed_findings],
        "worker_verdicts": worker_verdicts,
        "mutation_violations": sorted(set(mutation_violations)),
        "unavailable": sorted(set(unavailable)),
        "available_families": sorted(available_families),
        "executed_families": sorted(executed_families),
        "executed_identity_groups": sorted(executed_identity_groups),
        "timed_out_workers": timed_out_workers,
        "truncated_workers": truncated_workers,
        "skipped_due_total_timeout": skipped_due_total_timeout,
        "hard_isolated_workers": hard_isolated_workers,
        "worker_providers": worker_providers,
        "audit_isolation_attestations": audit_isolation_attestations,
        "worker_timeout_seconds": worker_timeout,
        "total_timeout_seconds": total_timeout_seconds,
        "parallel_per_round_requested": parallel_per_round,
        "parallel_per_round_enabled": parallel_enabled,
    }


def _record_redteam_execution_interrupted(
    *,
    store: RunStore,
    plan: RunPlan,
    ledger: Ledger,
    workers: list[str],
    rounds: int,
    execute: bool,
    unavailable: list[str],
    available_families: list[str],
    executed_families: list[str],
    parsed_findings: list[Finding],
    worker_results: list[dict[str, Any]],
    worker_verdicts: list[dict[str, str]],
    mutation_violations: list[str],
    timed_out_workers: list[str],
    truncated_workers: list[str],
    skipped_due_total_timeout: list[str],
    active_worker: str | None,
    active_round: int | None,
    worker_timeout_seconds: int | None,
    total_timeout_seconds: int | None,
    parallel_per_round_requested: bool,
    parallel_per_round_enabled: bool,
) -> dict[str, Any]:
    notes = "Red-team execution was interrupted before completion; partial evidence is not release-sufficient. Rerun `sdlc redteam execute` to produce completion evidence."
    summary = _write_redteam_execution_summary(
        ledger,
        workers=workers,
        rounds=rounds,
        execute=execute,
        unavailable=unavailable,
        available_families=available_families,
        executed_families=executed_families,
        executed_identity_groups=[],
        parsed_findings=parsed_findings,
        worker_verdicts=worker_verdicts,
        mutation_violations=mutation_violations,
        timed_out_workers=timed_out_workers,
        truncated_workers=truncated_workers,
        skipped_due_total_timeout=skipped_due_total_timeout,
        verdict="NO_GO",
        notes=notes,
        worker_timeout_seconds=worker_timeout_seconds,
        total_timeout_seconds=total_timeout_seconds,
        parallel_per_round_requested=parallel_per_round_requested,
        parallel_per_round_enabled=parallel_per_round_enabled,
    )
    _set_redteam_gate(store, plan, summary, worker_results, "NO_GO", notes)
    ledger.event(
        "redteam.execution_interrupted",
        verdict="NO_GO",
        status="INTERRUPTED",
        workers=workers,
        rounds=rounds,
        execute_requested=execute,
        available_families=available_families,
        executed_families=executed_families,
        unavailable=unavailable,
        parsed_findings=[finding.id for finding in parsed_findings],
        worker_verdicts=worker_verdicts,
        mutation_violations=mutation_violations,
        timed_out_workers=timed_out_workers,
        truncated_workers=truncated_workers,
        skipped_due_total_timeout=skipped_due_total_timeout,
        active_worker=active_worker,
        active_round=active_round,
        evidence=[summary],
        reason="KeyboardInterrupt",
        worker_timeout_seconds=worker_timeout_seconds,
        total_timeout_seconds=total_timeout_seconds,
        parallel_per_round_requested=parallel_per_round_requested,
        parallel_per_round_enabled=parallel_per_round_enabled,
    )
    return {
        "verdict": "NO_GO",
        "notes": notes,
        "summary": summary,
        "worker_results": worker_results,
        "parsed_findings": [finding.to_dict() for finding in parsed_findings],
        "worker_verdicts": worker_verdicts,
        "mutation_violations": mutation_violations,
        "timed_out_workers": timed_out_workers,
        "truncated_workers": truncated_workers,
        "skipped_due_total_timeout": skipped_due_total_timeout,
        "unavailable": unavailable,
        "available_families": available_families,
        "executed_families": executed_families,
        "executed_identity_groups": [],
        "worker_timeout_seconds": worker_timeout_seconds,
        "total_timeout_seconds": total_timeout_seconds,
        "parallel_per_round_requested": parallel_per_round_requested,
        "parallel_per_round_enabled": parallel_per_round_enabled,
        "interrupted": True,
    }


def _refresh_report_after_redteam_findings(repo: Path, run_id: str, ledger: Ledger) -> None:
    try:
        from .reporting import generate_report
        from . import cli as cli_module

        store = RunStore(repo)
        plan = store.load_plan(run_id)
        findings = store.load_findings(run_id)
        readiness = cli_module._release_readiness_payload(repo, plan, findings)
        cli_module._persist_release_readiness(store.run_dir(run_id), run_id, readiness)
        blockers = [str(item) for item in readiness.get("blockers", [])] if isinstance(readiness.get("blockers"), list) else []
        verdict = final_verdict(findings, plan)
        generate_report(
            repo,
            run_id,
            verdict_override="NO_GO" if verdict in {"GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"} and blockers else None,
            readiness_errors=blockers,
        )
        ledger.event("report.auto_refreshed", reason="redteam.findings_persisted")
    except Exception as exc:  # pragma: no cover - report freshness must never hide parsed findings
        ledger.event("report.auto_refresh_failed", reason="redteam.findings_persisted", error=str(exc))


def _redteam_allowed_provider_error(workers: list[str], policy: dict[str, Any], redteam_policy: dict[str, Any]) -> str | None:
    allowed_raw = redteam_policy.get("allowed_providers", [])
    if not isinstance(allowed_raw, list) or not allowed_raw:
        return None
    allowed = {str(item).strip().lower() for item in allowed_raw if str(item).strip()}
    rejected: list[str] = []
    for worker in workers:
        adapter = adapter_from_policy(worker, policy)
        provider = getattr(adapter, "provider", "unknown") if adapter is not None else "unknown"
        if str(provider).lower() not in allowed:
            rejected.append(f"{worker}:{provider}")
    if not rejected:
        return None
    return "Red-team policy restricts worker providers to " + ", ".join(sorted(allowed)) + "; rejected " + ", ".join(rejected)


def _external_hard_audit_isolation_required(plan: RunPlan, redteam_policy: dict[str, Any], adapter: Any) -> bool:
    provider = str(getattr(adapter, "provider", "local")).strip().lower()
    if provider == "local":
        return False
    if plan.risk_level in {"HIGH", "EXTREME"}:
        return True
    configured = redteam_policy.get("external_hard_source_isolation_required")
    if configured is not None:
        return bool(configured)
    return False


def _set_redteam_gate(store: RunStore, plan: RunPlan, summary: str, worker_results: list[dict[str, Any]], verdict: str, notes: str) -> None:
    gate = next((item for item in plan.gates if item.id == "independent_redteam_cross_model"), None)
    if gate is None:
        store.save_plan(plan)
        return
    gate.verdict = verdict
    gate.state = "GO" if verdict in {"GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"} else "NO_GO"
    if summary not in gate.evidence:
        gate.evidence.append(summary)
    for captured in worker_results:
        for key in ("result_path", "stdout_path", "stderr_path", "artifact"):
            value = captured.get(key)
            if isinstance(value, str) and value not in gate.evidence:
                gate.evidence.append(value)
    gate.notes = notes
    if verdict == "NO_GO":
        invalidate_downstream_gates(plan, gate.order, "Blocked because independent red-team is NO_GO.")
    store.save_plan(plan)


def _parse_worker_findings(
    repo: Path,
    run_dir: Path,
    worker: str,
    output: str,
    existing: list[Finding],
    ledger: Ledger,
) -> list[Finding]:
    if not output.strip():
        return []
    candidates = _worker_structured_payloads(output)
    schema = read_json(repo / ".sdlc" / "schemas" / "finding.schema.json", _finding_schema())
    parsed: list[Finding] = []
    for candidate in _expand_worker_payloads(candidates):
        if isinstance(candidate, dict):
            if "findings" in candidate:
                items = candidate["findings"]
            elif _looks_like_finding(candidate):
                items = [candidate]
            else:
                continue
        else:
            items = candidate
        if isinstance(items, dict):
            items = [items]
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            severity = str(item.get("severity") or "LOW").upper()
            finding = Finding(
                id=_unique_finding_id(str(item.get("id") or ""), severity, existing + parsed),
                severity=severity,
                title=str(item.get("title") or "Worker red-team finding"),
                evidence=[str(value) for value in item.get("evidence", [f"worker:{worker}"])],
                impact=str(item.get("impact") or "Impact not supplied by worker; requires human review."),
                required_fix=str(item.get("required_fix") or "Triage and provide independent closure evidence."),
                owner=str(item.get("owner") or "agent_3_implementation_owner"),
            )
            errors = validate_json_schema(finding.to_dict(), schema)
            if errors:
                ledger.event("redteam.finding_rejected", worker=worker, errors=errors, payload=item)
                continue
            parsed.append(finding)
    if not parsed:
        markdown_texts = _worker_agent_message_texts(output)
        if not markdown_texts and not _worker_output_is_transport_jsonl(output):
            markdown_texts = [output]
        for text in markdown_texts:
            parsed.extend(_parse_markdown_worker_findings(worker, text, existing + parsed, schema, ledger))
    if parsed:
        artifact = ledger.artifact(
            f"artifacts/redteam/{worker}-parsed-findings.json",
            json.dumps([finding.to_dict() for finding in parsed], indent=2, sort_keys=True) + "\n",
            event="redteam.findings_parsed",
            worker=worker,
            findings=[finding.id for finding in parsed],
        )
        for finding in parsed:
            if artifact not in finding.evidence:
                finding.evidence.append(artifact)
    return parsed


def _worker_declared_verdict(output: str) -> str | None:
    if not output.strip():
        return None
    verdicts: list[str] = []
    agent_texts = _worker_agent_message_texts(output)
    transport_jsonl = _worker_output_is_transport_jsonl(output)
    if transport_jsonl and not agent_texts:
        payload_sources = _worker_top_level_result_texts(output)
    else:
        payload_sources = agent_texts if agent_texts else [output]
    for source in payload_sources:
        for payload in _json_payloads_from_text(source):
            for candidate in _expand_worker_payloads([payload]):
                if not isinstance(candidate, dict):
                    continue
                value = candidate.get("verdict") or candidate.get("final_verdict")
                if isinstance(value, str):
                    verdicts.append(value.upper())
        for match in re.finditer(r"\bverdict\s*[:=]\s*([A-Z_]+)", source, flags=re.IGNORECASE):
            verdicts.append(match.group(1).upper())
    if not verdicts and not agent_texts and not transport_jsonl:
        for payload in _json_payloads_from_text(output):
            if not isinstance(payload, dict) or payload.get("type") in {"item.started", "item.completed", "turn.started", "turn.completed", "thread.started"}:
                continue
            value = payload.get("verdict") or payload.get("final_verdict")
            if isinstance(value, str):
                verdicts.append(value.upper())
    normalized = [item for item in verdicts if item in {"GO", "NO_GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"}]
    if not normalized:
        return None
    return normalized[-1]


def _worker_top_level_result_texts(output: str) -> list[str]:
    texts: list[str] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        if payload.get("type") in {"item.started", "item.completed", "turn.started", "turn.completed", "thread.started"}:
            continue
        if any(key in payload for key in ("verdict", "final_verdict", "findings", "reviewed_run_id")):
            texts.append(json.dumps(payload))
    return texts


def _worker_agent_message_texts(output: str) -> list[str]:
    candidates: list[Any] = []
    for line in output.splitlines():
        try:
            candidates.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if not candidates:
        try:
            payload = json.loads(output)
            if isinstance(payload, dict):
                response = payload.get("response")
                if isinstance(response, str):
                    return [response]
            candidates.append(payload)
        except json.JSONDecodeError:
            return []
    texts = _agent_message_texts(candidates)
    if texts:
        return texts
    responses = [str(item.get("response")) for item in candidates if isinstance(item, dict) and isinstance(item.get("response"), str)]
    return responses


def _worker_output_is_transport_jsonl(output: str) -> bool:
    transport_events = 0
    nonempty_lines = 0
    for line in output.splitlines():
        if not line.strip():
            continue
        nonempty_lines += 1
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload.get("type") in {
            "thread.started",
            "turn.started",
            "turn.completed",
            "item.started",
            "item.completed",
        }:
            transport_events += 1
    return transport_events > 0 and transport_events >= max(1, nonempty_lines // 2)


def _worker_structured_payloads(output: str) -> list[Any]:
    agent_texts = _worker_agent_message_texts(output)
    if agent_texts:
        payloads: list[Any] = []
        for text in agent_texts:
            payloads.extend(_json_payloads_from_text(text))
        return _dedupe_payloads(payloads)
    return _dedupe_payloads(_json_payloads_from_text(output))


def _dedupe_payloads(payloads: list[Any]) -> list[Any]:
    seen: set[str] = set()
    unique: list[Any] = []
    for payload in payloads:
        try:
            key = json.dumps(payload, sort_keys=True)
        except TypeError:
            key = repr(payload)
        if key in seen:
            continue
        seen.add(key)
        unique.append(payload)
    return unique


def _prompt_binding_from_text(text: str) -> str:
    match = PROMPT_BINDING_RE.search(text)
    embedded = match.group(1) if match and re.fullmatch(r"[a-f0-9]{64}", match.group(1)) else ""
    if not embedded:
        return ""
    computed = redteam_prompt_binding_sha256(text)
    return embedded if embedded == computed else computed


def _recorded_redteam_prompt_binding(run_dir: Path) -> str:
    manifest = run_dir / "artifacts" / "prompts" / "manifest.json"
    if not manifest.exists():
        return ""
    try:
        payload = read_json(manifest, {})
    except Exception:
        return ""
    prompts = payload.get("prompts") if isinstance(payload, dict) else None
    if not isinstance(prompts, dict):
        return ""
    value = prompts.get("redteam_prompt.md")
    return str(value) if isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) else ""


def _load_run_policy(run_dir: Path, repo: Path, profile: str) -> dict[str, Any]:
    snapshot = run_dir / "artifacts" / "policy" / "snapshot.json"
    if snapshot.exists():
        return read_json(snapshot, load_policy(repo, profile))
    return load_policy(repo, profile)


def _worker_attested_review(output: str, run_id: str, prompt_sha256: str) -> bool:
    if not output.strip() or not prompt_sha256:
        return False
    for payload in _json_payloads_from_text(output):
        for candidate in _expand_worker_payloads([payload]):
            if not isinstance(candidate, dict):
                continue
            if candidate.get("reviewed_run_id") == run_id and candidate.get("prompt_sha256") == prompt_sha256:
                return True
    return False


def _create_audit_workspace(repo: Path) -> tuple[tempfile.TemporaryDirectory, Path]:
    temp_dir = tempfile.TemporaryDirectory(prefix="sdlc-redteam-")
    destination = Path(temp_dir.name) / repo.name
    shutil.copytree(
        repo,
        destination,
        ignore=shutil.ignore_patterns(
            ".venv",
            "venv",
            "__pycache__",
            "*.pyc",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
        ),
    )
    (destination / ".sdlc-redteam-tmp").mkdir(parents=True, exist_ok=True)
    (destination.parent / ".sdlc-worker-tmp" / destination.name).mkdir(parents=True, exist_ok=True)
    _make_tree_readonly(destination)
    return temp_dir, destination


def _make_tree_readonly(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        try:
            if path.is_file():
                path.chmod(0o444)
            elif path.is_dir():
                path.chmod(0o555)
        except OSError:
            continue
    try:
        root.chmod(0o555)
    except OSError:
        pass


def _make_tree_writable(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts)):
        try:
            if path.is_dir():
                path.chmod(0o755)
            elif path.is_file():
                path.chmod(0o644)
        except OSError:
            continue
    try:
        root.chmod(0o755)
    except OSError:
        pass


def _repo_snapshot(repo: Path, *, include_run_artifacts: bool = True) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    excluded_roots = {".git", ".venv", "venv", "__pycache__", ".sdlc-redteam-tmp", ".sdlc-worker-tmp"}
    for path in repo.rglob("*"):
        if not path.is_file():
            continue
        relative_path = path.relative_to(repo)
        rel = str(relative_path)
        parts = set(relative_path.parts)
        if parts & excluded_roots:
            continue
        if not include_run_artifacts and len(relative_path.parts) >= 3 and relative_path.parts[:2] == (".sdlc", "runs"):
            continue
        snapshot[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return snapshot


def _repo_mutations(repo: Path, before: dict[str, str], *, include_run_artifacts: bool = True) -> list[str]:
    after = _repo_snapshot(repo, include_run_artifacts=include_run_artifacts)
    changed = {path for path, digest in after.items() if before.get(path) != digest}
    changed.update(path for path in before if path not in after)
    return sorted(changed)


class _MutationJournal:
    def __init__(self, repo: Path, baseline: dict[str, str], *, interval: float = 0.02, include_run_artifacts: bool = True):
        self.repo = repo
        self.baseline = dict(baseline)
        self.interval = interval
        self.include_run_artifacts = include_run_artifacts
        self._changes: set[str] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="sdlc-mutation-journal", daemon=True)
        self._thread.start()

    def stop(self) -> list[str]:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
        self._thread = None
        return self.changes()

    def reset(self, baseline: dict[str, str]) -> None:
        self.baseline = dict(baseline)
        self._changes.clear()

    def changes(self) -> list[str]:
        return sorted(self._changes)

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                current = _repo_snapshot(self.repo, include_run_artifacts=self.include_run_artifacts)
            except OSError:
                continue
            changed = {path for path, digest in current.items() if self.baseline.get(path) != digest}
            changed.update(path for path in self.baseline if path not in current)
            self._changes.update(changed)


def _expand_worker_payloads(candidates: list[Any]) -> list[Any]:
    expanded: list[Any] = []
    for candidate in candidates[:200]:
        if len(expanded) < 200:
            expanded.append(candidate)
        if not isinstance(candidate, dict):
            continue
        for value in _nested_json_strings(candidate):
            for payload in _json_payloads_from_text(value)[:20]:
                expanded.append(payload)
                if len(expanded) >= 250:
                    return expanded
    return expanded


def _agent_message_texts(candidates: list[Any]) -> list[str]:
    texts: list[str] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        item = candidate.get("item")
        if not isinstance(item, dict) or item.get("type") != "agent_message":
            continue
        text = item.get("text")
        if isinstance(text, str):
            texts.append(text)
    return texts


def _json_payloads_from_text(text: str, *, include_lines: bool = True) -> list[Any]:
    payloads: list[Any] = []
    stripped = text.strip()
    if not stripped:
        return payloads
    try:
        payloads.append(json.loads(stripped))
        return payloads
    except json.JSONDecodeError:
        pass
    for match in re.finditer(r"```(?:json)?\s*([\s\S]*?)```", text, flags=re.IGNORECASE):
        chunk = match.group(1).strip()
        try:
            payloads.append(json.loads(chunk))
        except json.JSONDecodeError:
            continue
    if include_lines:
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith(("{", "[")):
                continue
            try:
                payloads.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if not payloads:
        start = min([idx for idx in [text.find("{"), text.find("[")] if idx >= 0], default=-1)
        end = max(text.rfind("}"), text.rfind("]"))
        if start >= 0 and end > start:
            try:
                payloads.append(json.loads(text[start : end + 1]))
            except json.JSONDecodeError:
                pass
    return payloads


def _parse_markdown_worker_findings(
    worker: str,
    output: str,
    existing: list[Finding],
    schema: dict[str, Any],
    ledger: Ledger,
) -> list[Finding]:
    severity = "LOW"
    parsed: list[Finding] = []
    patterns = [
        (re.compile(r"\bcritical\b", re.IGNORECASE), "CRITICAL"),
        (re.compile(r"\bhigh\b", re.IGNORECASE), "HIGH"),
        (re.compile(r"\bmedium\b", re.IGNORECASE), "MEDIUM"),
        (re.compile(r"\blow\b", re.IGNORECASE), "LOW"),
    ]
    finding_re = re.compile(r"(?:^[-*]\s*)?\*\*(F-\d+)\s+[—-]\s+(.+?)\*\*")
    current: dict[str, Any] | None = None
    body: list[str] = []

    def flush() -> None:
        nonlocal current, body
        if current is None:
            return
        details = " ".join(part.strip() for part in body if part.strip())
        item = Finding(
            id=_unique_finding_id(str(current["id"]), str(current["severity"]), existing + parsed),
            severity=str(current["severity"]),
            title=str(current["title"]),
            evidence=[f"worker:{worker}", details[:500] or "markdown red-team output"],
            impact="Worker supplied markdown finding; impact requires triage against recorded evidence.",
            required_fix="Triage and fix or independently accept with human override and evidence.",
            owner="agent_3_implementation_owner",
        )
        errors = validate_json_schema(item.to_dict(), schema)
        if errors:
            ledger.event("redteam.finding_rejected", worker=worker, errors=errors, payload=current)
        else:
            parsed.append(item)
        current = None
        body = []

    for line in output.splitlines():
        lowered = line.lower()
        if "finding" in lowered or "blocker" in lowered:
            for pattern, candidate_severity in patterns:
                if pattern.search(line):
                    severity = candidate_severity
                    break
        match = finding_re.search(line)
        if not match:
            if current is not None:
                body.append(line)
            continue
        flush()
        raw_title = re.sub(r"\s+\(`[^`]+`\)$", "", match.group(2).strip())
        current = {"id": match.group(1), "severity": severity, "title": raw_title}
        body = []
    flush()
    return parsed


def _nested_json_strings(candidate: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("result", "text", "response"):
        value = candidate.get(key)
        if isinstance(value, str):
            values.append(value)
    item = candidate.get("item")
    if isinstance(item, dict):
        value = item.get("text")
        if isinstance(value, str):
            values.append(value)
    return values


def _looks_like_finding(candidate: dict[str, Any]) -> bool:
    return any(key in candidate for key in ("severity", "title", "evidence", "impact", "required_fix"))


def _finding_schema() -> dict[str, Any]:
    return {
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
    }


def _next_finding_id(severity: str, findings: list[Finding]) -> str:
    prefix = severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "LOW"
    numbers = []
    for finding in findings:
        if finding.id.startswith(prefix + "-"):
            try:
                numbers.append(int(finding.id.split("-", 1)[1]))
            except (IndexError, ValueError):
                continue
    return f"{prefix}-{(max(numbers) if numbers else 0) + 1:03d}"


def _unique_finding_id(candidate: str, severity: str, findings: list[Finding]) -> str:
    existing_ids = {finding.id for finding in findings}
    if candidate and candidate not in existing_ids:
        return candidate
    return _next_finding_id(severity, findings)


def _redteam_execution_verdict(
    *,
    plan: RunPlan,
    findings: list[Finding],
    execute: bool,
    available_families: set[str],
    executed_families: set[str],
    executed_identity_groups: set[str] | None = None,
    worker_verdicts: list[dict[str, str]] | None = None,
    mutation_violations: list[str] | None = None,
    timed_out_workers: list[str] | None = None,
    truncated_workers: list[str] | None = None,
    skipped_due_total_timeout: list[str] | None = None,
    cross_model_required: bool = True,
) -> tuple[str, str]:
    if not execute:
        return "NO_GO", "Red-team execution was dry-run only; real worker execution evidence is required."
    high_stakes = plan.risk_level in {"HIGH", "EXTREME"}
    if mutation_violations:
        return "NO_GO", "Red-team worker mutated repository paths: " + ", ".join(mutation_violations[:10])
    if timed_out_workers:
        return "NO_GO", "Red-team worker timeouts require triage and rerun: " + ", ".join(timed_out_workers[:10])
    if truncated_workers:
        return "NO_GO", "Red-team worker output was truncated before complete verdict evidence was captured; rerun with bounded inspection: " + ", ".join(truncated_workers[:10])
    if skipped_due_total_timeout:
        return "NO_GO", "Red-team total command timeout expired before all workers ran: " + ", ".join(skipped_due_total_timeout[:10])
    no_go_workers = [item for item in worker_verdicts or [] if item.get("verdict") == "NO_GO"]
    if no_go_workers:
        workers = ", ".join(f"{item.get('worker')}@round{item.get('round')}" for item in no_go_workers)
        return "NO_GO", f"Worker-declared NO_GO verdicts require triage even without parsed findings: {workers}."
    unverified_positive_workers = [
        item for item in worker_verdicts or []
        if item.get("verdict") in {"GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"}
        and item.get("context_attested") is not True
    ]
    if unverified_positive_workers:
        workers = ", ".join(f"{item.get('worker')}@round{item.get('round')}" for item in unverified_positive_workers)
        return "NO_GO", "Positive red-team verdicts require reviewed_run_id and prompt_sha256 binding: " + workers
    positive_workers = {item.get("worker") for item in worker_verdicts or [] if item.get("verdict") in {"GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"}}
    missing_verdicts = sorted(executed_families - {str(item) for item in positive_workers if item})
    if missing_verdicts:
        return "NO_GO", "Successful red-team workers must emit an explicit positive verdict: " + ", ".join(missing_verdicts)
    if not executed_families:
        return "NO_GO", "Red-team workers must emit non-empty structured output with an explicit positive verdict."
    if high_stakes and cross_model_required and len(executed_families) < 2:
        available_note = ", ".join(sorted(available_families)) or "<none>"
        return "NO_GO", f"High-stakes run requires two independent executed worker families; executed={len(executed_families)}, available={available_note}."
    if high_stakes and cross_model_required and len(executed_identity_groups or set()) < 2:
        groups = ", ".join(sorted(executed_identity_groups or set())) or "<none>"
        return "NO_GO", f"High-stakes run requires two distinct red-team model identities; executed_model_groups={groups}."
    if open_findings(findings, {"CRITICAL", "HIGH"}):
        return "NO_GO", "Open CRITICAL/HIGH red-team findings block the gate."
    if open_findings(findings, {"MEDIUM"}):
        return "NO_GO", "Open MEDIUM findings require closure, deferral, or accepted residual-risk handling before a positive red-team verdict."
    return "GO", "Executed red-team evidence captured with no open blocking findings."


def _write_redteam_execution_summary(
    ledger: Ledger,
    *,
    workers: list[str],
    rounds: int,
    execute: bool,
    unavailable: list[str],
    available_families: list[str],
    executed_families: list[str],
    executed_identity_groups: list[str],
    parsed_findings: list[Finding],
    worker_verdicts: list[dict[str, str]] | None = None,
    mutation_violations: list[str] | None = None,
    timed_out_workers: list[str] | None = None,
    truncated_workers: list[str] | None = None,
    skipped_due_total_timeout: list[str] | None = None,
    hard_isolated_workers: list[str] | None = None,
    worker_providers: dict[str, str] | None = None,
    audit_isolation_attestations: list[str] | None = None,
    verdict: str,
    notes: str,
    worker_timeout_seconds: int | None = None,
    total_timeout_seconds: int | None = None,
    parallel_per_round_requested: bool = False,
    parallel_per_round_enabled: bool = False,
) -> str:
    lines = [
        "# Red-Team Execution Summary",
        "",
        f"execute_requested: {execute}",
        f"rounds: {rounds}",
        f"worker_timeout_seconds: {worker_timeout_seconds if worker_timeout_seconds is not None else '<none>'}",
        f"total_timeout_seconds: {total_timeout_seconds if total_timeout_seconds is not None else '<none>'}",
        f"parallel_per_round: {'enabled' if parallel_per_round_enabled else 'disabled'}",
        f"parallel_per_round_requested: {parallel_per_round_requested}",
        f"workers: {', '.join(workers) if workers else '<none>'}",
        f"available_families: {', '.join(available_families) if available_families else '<none>'}",
        f"executed_families: {', '.join(executed_families) if executed_families else '<none>'}",
        f"executed_model_groups: {', '.join(executed_identity_groups) if executed_identity_groups else '<none>'}",
        f"unavailable_workers: {', '.join(unavailable) if unavailable else '<none>'}",
        "worker_verdicts: " + (", ".join(f"{item.get('worker')}:{item.get('verdict')}:round{item.get('round')}" for item in worker_verdicts or []) or "<none>"),
        "unverified_positive_worker_verdicts: " + (
            ", ".join(
                f"{item.get('worker')}@round{item.get('round')}"
                for item in worker_verdicts or []
                if item.get("verdict") in {"GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"}
                and item.get("context_attested") is not True
            )
            or "<none>"
        ),
        "mutation_violations: " + (", ".join(mutation_violations or []) or "<none>"),
        "timed_out_workers: " + (", ".join(timed_out_workers or []) or "<none>"),
        "truncated_workers: " + (", ".join(truncated_workers or []) or "<none>"),
        "skipped_due_total_timeout: " + (", ".join(skipped_due_total_timeout or []) or "<none>"),
        "hard_audit_isolated_workers: " + (", ".join(hard_isolated_workers or []) or "<none>"),
        "worker_providers: " + (", ".join(f"{worker}:{provider}" for worker, provider in sorted((worker_providers or {}).items())) or "<none>"),
        "audit_isolation_attestations: " + (", ".join(audit_isolation_attestations or []) or "<none>"),
        f"parsed_findings: {', '.join(finding.id for finding in parsed_findings) if parsed_findings else '<none>'}",
        f"verdict: {verdict}",
        "",
        notes,
    ]
    return ledger.artifact("artifacts/redteam_execution_summary.md", "\n".join(lines) + "\n", event="redteam.execution_summary", verdict=verdict)


def final_verdict(findings: list[Finding], plan: RunPlan | None = None) -> str:
    if plan and any(gate.verdict == "NO_GO" or gate.state in {"NO_GO", "FIX_REQUIRED", "BLOCKED"} for gate in plan.gates):
        return "NO_GO"
    if plan and any(not _gate_complete_for_final(gate, plan) for gate in plan.gates):
        return "NO_GO"
    if invalid_findings(findings):
        return "NO_GO"
    critical_high = open_findings(findings, {"CRITICAL", "HIGH"})
    if critical_high:
        return "NO_GO"
    medium = open_findings(findings, {"MEDIUM"})
    if medium:
        return "NO_GO"
    accepted_or_deferred = [
        finding for finding in findings
        if finding.status in {"ACCEPTED", "DEFERRED"} and finding.severity in {"CRITICAL", "HIGH", "MEDIUM"}
    ]
    if accepted_or_deferred:
        return "GO_WITH_ACCEPTED_RESIDUAL_RISKS"
    if plan and any(gate.verdict == "GO_WITH_ACCEPTED_RESIDUAL_RISKS" for gate in plan.gates):
        return "GO_WITH_ACCEPTED_RESIDUAL_RISKS"
    return "GO"


def _gate_complete_for_final(gate: Any, plan: RunPlan | None = None) -> bool:
    if gate.state == "SKIPPED":
        return _skipped_gate_valid(gate, plan)
    if gate.state == "WAIVED":
        return True
    if gate.state != "GO":
        return False
    return gate.verdict in {"GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"} and bool(gate.evidence)


def _skipped_gate_valid(gate: Any, plan: RunPlan | None) -> bool:
    if gate.verdict != "SKIPPED" or not getattr(gate, "conditional_on", None):
        return False
    return plan_condition_value(plan, str(gate.conditional_on)) is False
