"""Role-agent planning and dry-run-safe scheduling."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .adapters import adapter_from_policy, capture_worker_result, worker_diagnostics
from .ledger import Ledger
from .models import RunPlan
from .pipeline import CONDITIONAL_AGENTS, DEFAULT_AGENTS
from .util import now_iso, read_json


AGENT_PLAN_PATH = "artifacts/agents/task-plan.json"
DEFAULT_AGENT_READ_PATHS = ["sdlc/**", "docs/**", "tests/**"]
DEFAULT_AGENT_DENY_PATHS = [".env*", "secrets/**", "infra/prod/**", ".sdlc/runs/**", ".sdlc/memory.sqlite"]
WORKSPACE_SCRATCH_DIRS = {".sdlc-redteam-tmp", ".sdlc-worker-tmp"}
WORKSPACE_GENERATED_DIRS = {"target", "node_modules", ".next", ".turbo", "dist"}

ROLE_DEFAULTS: dict[str, dict[str, Any]] = {
    "agent_1_pm_coordinator": {"worker": "codex", "mode": "PLAN", "write_paths": []},
    "agent_2_architecture_contracts": {"worker": "claude", "mode": "PLAN", "write_paths": []},
    "agent_3_implementation_owner": {"worker": "codex", "mode": "BUILD", "write_paths": ["sdlc/**", "docs/**"]},
    "agent_4_evidence_reporting_owner": {"worker": "codex", "mode": "PLAN", "write_paths": [".sdlc/templates/**", ".sdlc/schemas/**", ".sdlc/policies/**"]},
    "agent_5_qa_validation_owner": {"worker": "codex", "mode": "TEST", "write_paths": ["tests/**"]},
    "agent_6_redteam_deploy_rollback": {"worker": "openai-codex-adversary", "mode": "SECURITY_REVIEW", "write_paths": []},
    "agent_7_ui_architect": {"worker": "codex", "mode": "PLAN", "write_paths": ["docs/agents/agent_7_ui_architect/**"]},
    "agent_8_cybersecurity_engineer": {"worker": "openai-codex-adversary", "mode": "SECURITY_REVIEW", "write_paths": []},
    "agent_9_sre_sysadmin": {"worker": "codex", "mode": "PLAN", "write_paths": ["docs/agents/agent_9_sre_sysadmin/**"]},
    "agent_10_it_enterprise_integration": {"worker": "codex", "mode": "PLAN", "write_paths": ["docs/agents/agent_10_it_enterprise_integration/**"]},
    "agent_11_compliance_audit": {"worker": "codex", "mode": "PLAN", "write_paths": ["docs/agents/agent_11_compliance_audit/**"]},
    "agent_12_domain_specialist": {"worker": "codex", "mode": "PLAN", "write_paths": ["docs/agents/agent_12_domain_specialist/**"]},
}


def plan_agents(plan: RunPlan, policy: dict[str, Any], *, requested_parallelism: int | None = None) -> dict[str, Any]:
    agent_policy = policy.get("agents", {}) if isinstance(policy.get("agents"), dict) else {}
    max_parallel = int(agent_policy.get("max_parallel", 6) or 6)
    if requested_parallelism is None or requested_parallelism <= 0:
        requested_parallelism = max_parallel
    effective_parallelism = max(1, min(requested_parallelism, max_parallel))
    if plan.risk_level in {"HIGH", "EXTREME"}:
        effective_parallelism = max(effective_parallelism, int(agent_policy.get("min_parallel_for_high_or_extreme", 6) or 6))
    effective_parallelism = max(1, min(effective_parallelism, max_parallel if max_parallel >= 1 else 6))

    roster = _baseline_roster(plan, include_all_conditionals=requested_parallelism >= 12)
    tasks = [_task_for_agent(plan, policy, agent) for agent in roster]
    batches = _build_batches(tasks, effective_parallelism)
    return {
        "schema_version": 1,
        "run_id": plan.run_id,
        "created_at": now_iso(),
        "requested_parallelism": requested_parallelism,
        "effective_parallelism": effective_parallelism,
        "execute_default": "DRY_RUN",
        "tasks": tasks,
        "batches": batches,
    }


def write_agent_plan(run_dir: Path, plan: RunPlan, policy: dict[str, Any], *, requested_parallelism: int | None = None) -> dict[str, Any]:
    ledger = Ledger(run_dir, plan.run_id)
    payload = plan_agents(plan, policy, requested_parallelism=requested_parallelism)
    artifact = ledger.artifact(AGENT_PLAN_PATH, json.dumps(payload, indent=2, sort_keys=True) + "\n", event="agents.plan_created", redact=False, parallelism=payload["effective_parallelism"])
    payload["artifact"] = artifact
    return payload


def load_agent_plan(run_dir: Path) -> dict[str, Any]:
    return read_json(run_dir / AGENT_PLAN_PATH, {})


def execute_agent_plan(
    run_dir: Path,
    plan: RunPlan,
    policy: dict[str, Any],
    *,
    execute: bool,
    parallel: int | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    ledger = Ledger(run_dir, plan.run_id)
    payload = load_agent_plan(run_dir)
    if not payload:
        payload = write_agent_plan(run_dir, plan, policy, requested_parallelism=parallel)
    effective_parallelism = int(parallel or payload.get("effective_parallelism") or 6)
    tasks = [dict(task) for task in payload.get("tasks", [])]
    started_at = now_iso()
    ledger.event("agents.execution_started", execute_requested=execute, parallelism=effective_parallelism)
    completed: list[dict[str, Any]] = []
    dependency_blocked: list[dict[str, Any]] = []
    completed_ids: set[str] = set()
    runnable = []
    for task in tasks:
        dependencies = [str(item) for item in task.get("depends_on", [])]
        if dependencies and not set(dependencies).issubset(completed_ids):
            task["status"] = "blocked_by_dependency"
            task["blocked_reason"] = "Unresolved dependencies: " + ", ".join(dependencies)
            dependency_blocked.append(task)
            continue
        runnable.append(task)
    with ThreadPoolExecutor(max_workers=max(1, effective_parallelism)) as executor:
        futures = [executor.submit(_execute_task, run_dir, plan, policy, task, execute, timeout) for task in runnable]
        for future in as_completed(futures):
            result = future.result()
            completed.append(result)
            if result.get("status") == "completed":
                completed_ids.add(str(result.get("task_id")))
    for task in dependency_blocked:
        Ledger(run_dir, plan.run_id).event("agents.task_failed", agent_id=task["agent_id"], task_id=task["task_id"], reason=task["blocked_reason"])
        _write_task_artifacts(ledger, task)
    by_id = {task["task_id"]: task for task in completed + dependency_blocked}
    for task in tasks:
        if task["task_id"] in by_id:
            task.update(by_id[task["task_id"]])
    payload["tasks"] = tasks
    payload["last_execution"] = {
        "started_at": started_at,
        "ended_at": now_iso(),
        "execute_requested": execute,
        "parallelism": effective_parallelism,
    }
    artifact = ledger.artifact(AGENT_PLAN_PATH, json.dumps(payload, indent=2, sort_keys=True) + "\n", event="agents.parallel_batch_completed", redact=False, execute_requested=execute, completed=len(completed))
    payload["artifact"] = artifact
    return payload


def agent_status(run_dir: Path, plan: RunPlan, policy: dict[str, Any]) -> dict[str, Any]:
    payload = load_agent_plan(run_dir)
    if not payload:
        payload = plan_agents(plan, policy)
    counts: dict[str, int] = {}
    for task in payload.get("tasks", []):
        counts[str(task.get("status", "queued"))] = counts.get(str(task.get("status", "queued")), 0) + 1
    return {
        "schema_version": 1,
        "run_id": plan.run_id,
        "counts": counts,
        "tasks": payload.get("tasks", []),
        "effective_parallelism": payload.get("effective_parallelism"),
    }


def agents_doctor(policy: dict[str, Any]) -> dict[str, Any]:
    diagnostics = worker_diagnostics(policy)
    return {
        "schema_version": 1,
        "workers": diagnostics,
        "available_workers": [item["worker"] for item in diagnostics if item["available"]],
    }


def _baseline_roster(plan: RunPlan, *, include_all_conditionals: bool = False) -> list[dict[str, str]]:
    by_id = {agent["id"]: agent for agent in plan.agents}
    for agent in DEFAULT_AGENTS:
        by_id.setdefault(agent["id"], agent)
    if include_all_conditionals:
        for agent in CONDITIONAL_AGENTS:
            by_id.setdefault(agent["id"], agent)
    ordered = []
    seen = set()
    candidates = DEFAULT_AGENTS + plan.agents + (CONDITIONAL_AGENTS if include_all_conditionals else [])
    for agent in candidates:
        if agent["id"] not in seen:
            ordered.append(by_id[agent["id"]])
            seen.add(agent["id"])
    return ordered


def _task_for_agent(plan: RunPlan, policy: dict[str, Any], agent: dict[str, str]) -> dict[str, Any]:
    agent_id = agent["id"]
    defaults = ROLE_DEFAULTS.get(agent_id, {"worker": "codex", "mode": "PLAN", "write_paths": []})
    worker = _preferred_worker(agent_id, defaults["worker"], policy)
    mode = defaults["mode"]
    available = _worker_available(worker, policy)
    read_paths = _agent_read_paths(agent_id, policy)
    write_paths = _agent_write_paths(agent_id, policy, defaults)
    deny_paths = _agent_deny_paths(policy)
    return {
        "task_id": f"task-{agent_id}",
        "agent_id": agent_id,
        "role": agent.get("role", ""),
        "worker_family": worker,
        "worker_available": available,
        "mode": mode,
        "status": "queued",
        "depends_on": [],
        "read_paths": read_paths,
        "write_paths": write_paths,
        "deny_paths": deny_paths,
        "artifacts": {
            "task": f"artifacts/agents/{agent_id}/task.json",
            "summary": f"artifacts/agents/{agent_id}/summary.md",
        },
    }


def _agent_read_paths(agent_id: str, policy: dict[str, Any]) -> list[str]:
    if agent_id == "agent_3_implementation_owner":
        return _unique_paths([*DEFAULT_AGENT_READ_PATHS, *_implementer_allow_paths(policy)])
    return list(DEFAULT_AGENT_READ_PATHS)


def _agent_write_paths(agent_id: str, policy: dict[str, Any], defaults: dict[str, Any]) -> list[str]:
    if agent_id == "agent_3_implementation_owner":
        allow_paths = _implementer_allow_paths(policy)
        if allow_paths:
            return allow_paths
    return list(defaults.get("write_paths", []))


def _agent_deny_paths(policy: dict[str, Any]) -> list[str]:
    implementer = _implementer_permissions(policy)
    deny_paths = implementer.get("deny_paths", []) if isinstance(implementer, dict) else []
    if deny_paths:
        return list(deny_paths)
    return list(DEFAULT_AGENT_DENY_PATHS)


def _implementer_allow_paths(policy: dict[str, Any]) -> list[str]:
    implementer = _implementer_permissions(policy)
    allow_paths = implementer.get("allow_paths", []) if isinstance(implementer, dict) else []
    return list(allow_paths) if isinstance(allow_paths, list) else []


def _implementer_permissions(policy: dict[str, Any]) -> dict[str, Any]:
    permissions = policy.get("permissions", {}) if isinstance(policy.get("permissions"), dict) else {}
    implementer = permissions.get("implementer", {}) if isinstance(permissions.get("implementer"), dict) else {}
    return implementer


def _unique_paths(paths: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if path not in seen:
            unique.append(path)
            seen.add(path)
    return unique


def _preferred_worker(agent_id: str, default: str, policy: dict[str, Any]) -> str:
    agent_policy = policy.get("agents", {}) if isinstance(policy.get("agents"), dict) else {}
    role_preferences = agent_policy.get("role_worker_preferences", {}) if isinstance(agent_policy.get("role_worker_preferences"), dict) else {}
    preferred = role_preferences.get(agent_id)
    if isinstance(preferred, list) and preferred:
        return str(preferred[0])
    workers = policy.get("workers", {})
    if isinstance(workers, dict):
        role_key = {
            "agent_2_architecture_contracts": "architecture",
            "agent_3_implementation_owner": "implementation",
            "agent_5_qa_validation_owner": "qa",
            "agent_6_redteam_deploy_rollback": "redteam",
        }.get(agent_id)
        if role_key and isinstance(workers.get(role_key), str):
            return str(workers[role_key])
    return default


def _worker_available(worker: str, policy: dict[str, Any]) -> bool:
    adapter = adapter_from_policy(worker, policy)
    if adapter is None:
        return False
    command = adapter.build_command(Path("prompt.md"), Path("."), "READ_ONLY")
    return bool(command and shutil.which(command[0]))


def _build_batches(tasks: list[dict[str, Any]], parallelism: int) -> list[dict[str, Any]]:
    batches = []
    for index in range(0, len(tasks), max(1, parallelism)):
        batch_tasks = tasks[index:index + max(1, parallelism)]
        batches.append({
            "batch_id": f"batch-{len(batches) + 1}",
            "task_ids": [task["task_id"] for task in batch_tasks],
            "can_run_concurrently": True,
        })
    return batches


def _execute_task(run_dir: Path, plan: RunPlan, policy: dict[str, Any], task: dict[str, Any], execute: bool, timeout: int) -> dict[str, Any]:
    ledger = Ledger(run_dir, plan.run_id)
    task = dict(task)
    repo = Path(plan.repo)
    task["started_at"] = now_iso()
    task["status"] = "running"
    _write_task_artifacts(ledger, task)
    ledger.event("agents.task_started", agent_id=task["agent_id"], task_id=task["task_id"], worker=task["worker_family"], execute_requested=execute)
    adapter = adapter_from_policy(task["worker_family"], policy)
    if adapter is None:
        task["status"] = "blocked_unavailable_worker"
        task["blocked_reason"] = f"Unknown worker family: {task['worker_family']}"
        _write_task_artifacts(ledger, task)
        ledger.event("agents.task_failed", agent_id=task["agent_id"], task_id=task["task_id"], reason=task["blocked_reason"])
        return task
    prompt_path = _write_task_prompt(ledger, run_dir, plan, task)
    command = adapter.build_command(prompt_path, repo, task["mode"])
    task["worker_command"] = command
    task["worker_available"] = bool(command and shutil.which(command[0]))
    if execute and not task["worker_available"]:
        task["status"] = "blocked_unavailable_worker"
        task["blocked_reason"] = f"Worker not installed: {command[0] if command else task['worker_family']}"
        _write_task_artifacts(ledger, task)
        ledger.event("agents.task_failed", agent_id=task["agent_id"], task_id=task["task_id"], reason=task["blocked_reason"])
        return task
    workspace_holder: tempfile.TemporaryDirectory | None = None
    workspace = repo
    before: dict[str, str] = {}
    if execute:
        workspace_holder, workspace = _create_agent_workspace(repo, task["agent_id"])
        before = _workspace_snapshot(workspace)
    try:
        result = adapter.run(prompt_path, workspace, task["mode"], execute=execute, timeout=timeout)
    finally:
        after = _workspace_snapshot(workspace) if execute and workspace.exists() else {}
        if workspace_holder is not None:
            workspace_holder.cleanup()

    captured = capture_worker_result(
        run_dir=run_dir,
        mode=task["mode"],
        prompt_path=prompt_path,
        result=result,
        ledger=ledger,
        label=task["agent_id"],
    )
    task["worker_result"] = {
        key: captured.get(key)
        for key in ("result_path", "stdout_path", "stderr_path", "output_dir", "returncode", "executed", "available")
        if key in captured
    }
    task["execute_requested"] = execute
    task["worker_available"] = bool(result.available)
    task["returncode"] = result.returncode
    permission_violations = _permission_violations(before, after, task.get("write_paths", []), task.get("deny_paths", [])) if execute else []
    if permission_violations:
        task["status"] = "blocked_by_permissions"
        task["blocked_reason"] = "Workspace changes violated write ownership: " + ", ".join(permission_violations)
        task["permission_violations"] = permission_violations
        ledger.event("agents.task_policy_violation", agent_id=task["agent_id"], task_id=task["task_id"], violations=permission_violations)
    elif execute and result.returncode not in {0, None}:
        task["status"] = "failed"
        task["blocked_reason"] = f"Worker exited with return code {result.returncode}"
    elif execute and not result.executed:
        task["status"] = "blocked_unavailable_worker"
        task["blocked_reason"] = result.stderr or "Worker did not execute"
    else:
        task["status"] = "completed"
    task["ended_at"] = now_iso()
    _write_task_artifacts(ledger, task)
    if task["status"] == "completed":
        ledger.event("agents.task_completed", agent_id=task["agent_id"], task_id=task["task_id"], worker=task["worker_family"], execute_requested=execute, evidence=[task["artifacts"]["task"], task["artifacts"]["summary"], captured.get("result_path")])
    else:
        ledger.event("agents.task_failed", agent_id=task["agent_id"], task_id=task["task_id"], worker=task["worker_family"], status=task["status"], reason=task.get("blocked_reason"), evidence=[task["artifacts"]["task"], task["artifacts"]["summary"], captured.get("result_path")])
    return task


def _write_task_prompt(ledger: Ledger, run_dir: Path, plan: RunPlan, task: dict[str, Any]) -> Path:
    prompt = "\n".join([
        f"# SDLC Role Agent Task - {task['agent_id']}",
        "",
        f"Run ID: {plan.run_id}",
        f"Feature: {plan.feature}",
        f"Risk: {plan.risk_level}",
        f"Mode: {task.get('mode')}",
        f"Role: {task.get('role')}",
        "",
        "The orchestrator is authoritative. Follow the task permissions below.",
        f"Read paths: {', '.join(task.get('read_paths', []))}",
        f"Write paths: {', '.join(task.get('write_paths', [])) or '<none/read-only>'}",
        f"Deny paths: {', '.join(task.get('deny_paths', []))}",
        "",
        "Return concise JSON or Markdown evidence. Do not include secrets.",
        "Do not claim production readiness, security, compliance, profitability, or world-class maturity without gate evidence.",
        "Keep evidence reads bounded: do not cat full CSVs, large JSON files, logs, or generated trade/equity dumps. Use rg, wc, head, tail, and small sed ranges for targeted evidence.",
        "",
    ])
    rel = f"artifacts/agents/{task['agent_id']}/prompt.md"
    artifact = ledger.artifact(rel, prompt, event="agents.task_prompt", agent_id=task["agent_id"], task_id=task["task_id"])
    return run_dir / artifact


def _write_task_artifacts(ledger: Ledger, task: dict[str, Any]) -> None:
    ledger.artifact(task["artifacts"]["task"], json.dumps(task, indent=2, sort_keys=True) + "\n", event="agents.task_artifact", redact=False, agent_id=task["agent_id"], task_id=task["task_id"])
    summary = "\n".join([
        f"# Agent Task - {task['agent_id']}",
        "",
        f"Status: `{task.get('status')}`",
        f"Worker: `{task.get('worker_family')}`",
        f"Mode: `{task.get('mode')}`",
        f"Execute requested: `{task.get('execute_requested', False)}`",
        f"Write paths: {', '.join(task.get('write_paths', [])) or '<none>'}",
        f"Blocked reason: {task.get('blocked_reason') or '<none>'}",
        f"Worker result: {task.get('worker_result', {}).get('result_path', '<none>') if isinstance(task.get('worker_result'), dict) else '<none>'}",
        "",
    ])
    ledger.artifact(task["artifacts"]["summary"], summary, event="agents.task_summary", agent_id=task["agent_id"], task_id=task["task_id"])


def _create_agent_workspace(repo: Path, agent_id: str) -> tuple[tempfile.TemporaryDirectory, Path]:
    temp_dir = tempfile.TemporaryDirectory(prefix=f"sdlc-agent-{agent_id}-")
    destination = Path(temp_dir.name) / repo.name
    shutil.copytree(
        repo,
        destination,
        ignore=_ignore_agent_workspace_paths,
    )
    (destination / ".sdlc-redteam-tmp").mkdir(parents=True, exist_ok=True)
    (destination / ".sdlc-worker-tmp").mkdir(parents=True, exist_ok=True)
    return temp_dir, destination


def _ignore_agent_workspace_paths(src: str, names: list[str]) -> set[str]:
    ignored = set(shutil.ignore_patterns(
        ".venv",
        "venv",
        "__pycache__",
        "*.pyc",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    )(src, names))
    if Path(src).name == ".sdlc":
        ignored.update(name for name in names if name in {"runs", "memory.sqlite"})
    ignored.update(name for name in names if name in WORKSPACE_SCRATCH_DIRS)
    ignored.update(name for name in names if name in WORKSPACE_GENERATED_DIRS)
    return ignored


def _workspace_snapshot(root: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    excluded = {".git", ".venv", "venv", "__pycache__", *WORKSPACE_SCRATCH_DIRS, *WORKSPACE_GENERATED_DIRS}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_path = path.relative_to(root)
        if set(rel_path.parts) & excluded:
            continue
        rel = str(rel_path)
        snapshot[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return snapshot


def _permission_violations(before: dict[str, str], after: dict[str, str], write_paths: list[str], deny_paths: list[str]) -> list[str]:
    changed = {path for path, digest in after.items() if before.get(path) != digest}
    changed.update(path for path in before if path not in after)
    violations = []
    for path in sorted(changed):
        if _matches_any(path, deny_paths):
            violations.append(path)
            continue
        if not write_paths or not _matches_any(path, write_paths):
            violations.append(path)
    return violations


def _matches_any(path: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if pattern.endswith("/**") and path.startswith(pattern[:-3].rstrip("/") + "/"):
            return True
        if fnmatch.fnmatch(path, pattern):
            return True
    return False
