"""Worker adapters for Codex, Claude, and deterministic shell tools.

The adapters are intentionally conservative. They do not run unless the CLI user
passes explicit execution flags. This prevents the orchestrator from becoming a
surprise autonomous mutation machine.
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .ledger import Ledger
from .util import redact_secrets, relpath_under_base, run_cmd, now_iso


WORKER_ENV_ALLOWLIST = {
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
}

WORKER_MAX_OUTPUT_CHARS = 8_000_000


@dataclass
class WorkerResult:
    worker: str
    available: bool
    executed: bool
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    started_at: str
    ended_at: str
    mode: str | None = None
    prompt_path: str | None = None
    output_dir: str | None = None
    result_path: str | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    timeout_seconds: int | None = None
    timed_out: bool = False
    timeout_scope: str | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    max_output_chars: int | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "worker": self.worker,
            "available": self.available,
            "executed": self.executed,
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "timed_out": self.timed_out,
        }
        if self.timeout_seconds is not None:
            data["timeout_seconds"] = self.timeout_seconds
        if self.timeout_scope is not None:
            data["timeout_scope"] = self.timeout_scope
        data["stdout_truncated"] = self.stdout_truncated
        data["stderr_truncated"] = self.stderr_truncated
        if self.max_output_chars is not None:
            data["max_output_chars"] = self.max_output_chars
        if self.mode is not None:
            data["mode"] = self.mode
        if self.prompt_path is not None:
            data["prompt_path"] = self.prompt_path
        if self.output_dir is not None:
            data["output_dir"] = self.output_dir
        if self.result_path is not None:
            data["result_path"] = self.result_path
        if self.stdout_path is not None:
            data["stdout_path"] = self.stdout_path
        if self.stderr_path is not None:
            data["stderr_path"] = self.stderr_path
        return data


class WorkerAdapter:
    name = "base"
    provider = "local"

    def build_command(self, prompt_path: Path, repo: Path, mode: str) -> list[str]:
        raise NotImplementedError

    def build_stdin(self, prompt_path: Path, repo: Path, mode: str) -> str | None:
        return None

    def security_review_write_protected(self, policy: dict[str, Any] | None = None) -> bool:
        return False

    def build_env(self, prompt_path: Path, repo: Path, mode: str) -> dict[str, str]:
        run_id = _worker_run_id(prompt_path) or _adhoc_worker_run_id(prompt_path)
        temp_dir = _worker_temp_dir(prompt_path, repo, mode, run_id=run_id)
        temp_dir.mkdir(parents=True, exist_ok=True)
        env = _safe_worker_base_env()
        env.update({
            "SDLC_WORKER_EXECUTION": "1",
            "SDLC_WORKER_REPO": str(repo.resolve(strict=False)),
            "TMPDIR": str(temp_dir),
            "TMP": str(temp_dir),
            "TEMP": str(temp_dir),
            "PYTHONDONTWRITEBYTECODE": "1",
            "SDLC_WORKER_SANITIZED_ENV": "1",
        })
        if run_id:
            env["SDLC_WORKER_RUN_ID"] = run_id
        if _is_audit_workspace_security_review(mode):
            env["SDLC_WORKER_AUDIT_READONLY"] = "1"
        return env

    def run(self, prompt_path: Path, repo: Path, mode: str, *, execute: bool = False, timeout: int = 120) -> WorkerResult:
        command = self.build_command(prompt_path, repo, mode)
        input_text = self.build_stdin(prompt_path, repo, mode)
        available = bool(command and shutil.which(command[0]))
        started = now_iso()
        if not execute:
            return WorkerResult(self.name, available, False, command, None, "", "DRY_RUN: worker execution disabled", started, now_iso(), mode=mode, timeout_seconds=timeout)
        if not available:
            return WorkerResult(self.name, False, False, command, 127, "", f"Worker not installed: {command[0] if command else self.name}", started, now_iso(), mode=mode, timeout_seconds=timeout)
        result = run_cmd(
            command,
            repo,
            timeout=timeout,
            input_text=input_text,
            env=self.build_env(prompt_path, repo, mode),
            max_output_chars=WORKER_MAX_OUTPUT_CHARS,
        )
        timed_out = result["returncode"] == 124
        stderr = result["stderr"]
        if timed_out:
            timeout_note = f"Timed out after {timeout} seconds"
            stderr = timeout_note if not stderr or stderr == "Timed out" else f"{stderr}\n{timeout_note}"
        return WorkerResult(
            self.name,
            True,
            True,
            command,
            result["returncode"],
            result["stdout"],
            stderr,
            started,
            now_iso(),
            mode=mode,
            timeout_seconds=timeout,
            timed_out=timed_out,
            timeout_scope="per_worker" if timed_out else None,
            stdout_truncated=bool(result.get("stdout_truncated", False)),
            stderr_truncated=bool(result.get("stderr_truncated", False)),
            max_output_chars=int(result.get("max_output_chars", WORKER_MAX_OUTPUT_CHARS)),
        )


def _relative_to_run(run_dir: Path, path: Path) -> str:
    return relpath_under_base(run_dir, path, must_exist=False)


def _safe_worker_base_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for key, value in os.environ.items():
        if key in WORKER_ENV_ALLOWLIST or key.startswith("LC_"):
            env[key] = value
    env.setdefault("PATH", os.defpath)
    return env


def _worker_run_id(prompt_path: Path) -> str | None:
    parts = prompt_path.resolve(strict=False).parts
    for index, part in enumerate(parts[:-2]):
        if part == "runs":
            return parts[index + 1]
    return None


def _worker_temp_dir(prompt_path: Path, repo: Path, mode: str, *, run_id: str | None = None) -> Path:
    run_id = run_id or _worker_run_id(prompt_path) or _adhoc_worker_run_id(prompt_path)
    safe_mode = re.sub(r"[^a-z0-9_.-]+", "-", mode.lower()).strip("-") or "worker"
    if _is_security_review_mode(mode):
        repo_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", repo.resolve(strict=False).name).strip("-") or "repo"
        return repo.resolve(strict=False).parent / ".sdlc-worker-tmp" / repo_name / run_id / safe_mode
    return repo / ".sdlc-worker-tmp" / run_id / safe_mode


def _codex_security_review_workspace(prompt_path: Path, repo: Path, mode: str) -> Path:
    return _worker_temp_dir(prompt_path, repo, mode) / "codex-workspace"


def _adhoc_worker_run_id(prompt_path: Path) -> str:
    digest = hashlib.sha256(str(prompt_path.resolve(strict=False)).encode("utf-8")).hexdigest()[:12]
    return f"adhoc-{digest}"


def _is_security_review_mode(mode: str) -> bool:
    return mode == "SECURITY_REVIEW" or mode.startswith("SECURITY_REVIEW_")


def _is_audit_workspace_security_review(mode: str) -> bool:
    return mode == "SECURITY_REVIEW_AUDIT_WORKSPACE"


def _unique_capture_dir(run_dir: Path, worker: str, mode: str, *, label: str | None = None) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_label = f"{label}-" if label else ""
    base = run_dir / "worker-results" / f"{stamp}-{safe_label}{worker}-{mode.lower()}"
    candidate = base
    suffix = 2
    while candidate.exists():
        candidate = run_dir / "worker-results" / f"{stamp}-{safe_label}{worker}-{mode.lower()}-{suffix}"
        suffix += 1
    return candidate


def capture_worker_result(
    *,
    run_dir: Path,
    mode: str,
    prompt_path: Path,
    result: WorkerResult,
    ledger: Ledger,
    label: str | None = None,
) -> dict[str, Any]:
    """Persist worker stdout/stderr and metadata as run evidence."""
    capture_dir = _unique_capture_dir(run_dir, result.worker, mode, label=label)
    stdout_rel = _relative_to_run(run_dir, capture_dir / "stdout.txt")
    stderr_rel = _relative_to_run(run_dir, capture_dir / "stderr.txt")
    result_rel = _relative_to_run(run_dir, capture_dir / "result.json")
    prompt_rel = _relative_to_run(run_dir, prompt_path)

    result.mode = mode
    result.prompt_path = prompt_rel
    result.output_dir = _relative_to_run(run_dir, capture_dir)
    result.stdout_path = stdout_rel
    result.stderr_path = stderr_rel
    result.result_path = result_rel

    ledger.artifact(stdout_rel, result.stdout, event="worker.output_captured", worker=result.worker, mode=mode, stream="stdout")
    ledger.artifact(stderr_rel, result.stderr, event="worker.output_captured", worker=result.worker, mode=mode, stream="stderr")
    result_dict = _redacted_result_dict(result)
    ledger.artifact(
        result_rel,
        json.dumps(result_dict, indent=2, sort_keys=True) + "\n",
        event="worker.output_captured",
        redact=False,
        worker=result.worker,
        mode=mode,
        stream="result",
    )
    ledger.event(
        "worker.completed",
        worker=result.worker,
        mode=mode,
        executed=result.executed,
        available=result.available,
        returncode=result.returncode,
        output_dir=result.output_dir,
        result=result.result_path,
        stdout=result.stdout_path,
        stderr=result.stderr_path,
    )
    return result_dict


def _redacted_result_dict(result: WorkerResult) -> dict[str, Any]:
    return _redact_json_value(result.to_dict())


def _redact_json_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, list):
        return [_redact_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_json_value(item) for key, item in value.items()}
    return value


class CodexAdapter(WorkerAdapter):
    provider = "openai"

    def __init__(self, name: str = "codex", *, model: str | None = None, profile: str | None = None, profile_v2: str | None = None):
        self.name = name
        self.model = model
        self.profile = profile
        self.profile_v2 = profile_v2

    def build_stdin(self, prompt_path: Path, repo: Path, mode: str) -> str | None:
        return prompt_path.read_text(encoding="utf-8") if prompt_path.exists() else ""

    def build_command(self, prompt_path: Path, repo: Path, mode: str) -> list[str]:
        sandbox = "workspace-write" if mode in {"BUILD", "FIX", "TEST"} or _is_audit_workspace_security_review(mode) else "read-only"
        codex_cwd = repo
        if _is_security_review_mode(mode):
            codex_cwd = repo.resolve(strict=False)
        command = [
            "codex",
            "exec",
            "--cd",
            str(codex_cwd),
            "--sandbox",
            sandbox,
            "--skip-git-repo-check",
            "--json",
        ]
        if self.model:
            command.extend(["--model", self.model])
        if self.profile:
            command.extend(["--profile", self.profile])
        if self.profile_v2:
            command.extend(["--profile-v2", self.profile_v2])
        if mode in {"BUILD", "FIX", "TEST"} or _is_security_review_mode(mode):
            command.extend(["--add-dir", str(_worker_temp_dir(prompt_path, repo, mode))])
        command.append("-")
        return command

    def security_review_write_protected(self, policy: dict[str, Any] | None = None) -> bool:
        return True


class ClaudeAdapter(WorkerAdapter):
    name = "claude"
    provider = "anthropic"

    def build_stdin(self, prompt_path: Path, repo: Path, mode: str) -> str | None:
        return prompt_path.read_text(encoding="utf-8") if prompt_path.exists() else ""

    def build_command(self, prompt_path: Path, repo: Path, mode: str) -> list[str]:
        permission_mode = "plan" if mode in {"PLAN", "READ_ONLY"} or _is_security_review_mode(mode) else "default"
        return [
            "claude",
            "--print",
            "--output-format",
            "json",
            "--permission-mode",
            permission_mode,
        ]

    def security_review_write_protected(self, policy: dict[str, Any] | None = None) -> bool:
        return True


class GeminiAdapter(WorkerAdapter):
    name = "gemini"
    provider = "google"

    def build_stdin(self, prompt_path: Path, repo: Path, mode: str) -> str | None:
        return prompt_path.read_text(encoding="utf-8") if prompt_path.exists() else ""

    def build_command(self, prompt_path: Path, repo: Path, mode: str) -> list[str]:
        approval_mode = "plan" if mode in {"PLAN", "READ_ONLY"} or _is_security_review_mode(mode) else "default"
        command = [
            "gemini",
            "--prompt",
            "Read the complete task from stdin and return final JSON only.",
            "--approval-mode",
            approval_mode,
            "--output-format",
            "json",
        ]
        if mode in {"PLAN", "READ_ONLY"} or _is_security_review_mode(mode):
            command.append("--skip-trust")
        return command

    def security_review_write_protected(self, policy: dict[str, Any] | None = None) -> bool:
        return True


class KimiAdapter(WorkerAdapter):
    name = "kimi"
    provider = "moonshot"

    def build_stdin(self, prompt_path: Path, repo: Path, mode: str) -> str | None:
        return prompt_path.read_text(encoding="utf-8") if prompt_path.exists() else ""

    def build_command(self, prompt_path: Path, repo: Path, mode: str) -> list[str]:
        # Kimi-compatible local CLIs vary. Keep the default conservative and
        # stdin-based so prompts are not exposed in argv when the CLI supports it.
        return ["kimi", "--prompt", "-"]


class LocalCommandAdapter(WorkerAdapter):
    def __init__(self, name: str, command: list[str], *, security_review_protected: bool = False, provider: str = "local"):
        self.name = name
        self._command = command
        self._security_review_protected = security_review_protected
        self.provider = provider

    def build_stdin(self, prompt_path: Path, repo: Path, mode: str) -> str | None:
        return prompt_path.read_text(encoding="utf-8") if prompt_path.exists() else ""

    def build_command(self, prompt_path: Path, repo: Path, mode: str) -> list[str]:
        return list(self._command)

    def security_review_write_protected(self, policy: dict[str, Any] | None = None) -> bool:
        return self._security_review_protected


ADAPTERS: dict[str, WorkerAdapter] = {
    "codex": CodexAdapter(),
    "claude": ClaudeAdapter(),
    "gemini": GeminiAdapter(),
    "kimi": KimiAdapter(),
}


def adapter_from_policy(name: str, policy: dict[str, Any] | None = None) -> WorkerAdapter | None:
    if name in ADAPTERS:
        return ADAPTERS[name]
    policy = policy or {}
    configured = policy.get("worker_commands", {})
    family_config = policy.get("worker_families", {})
    candidates: list[tuple[Any, bool, str]] = []
    if isinstance(configured, dict):
        candidates.append((configured.get(name), False, "local"))
    if isinstance(family_config, dict):
        family = family_config.get(name)
        if isinstance(family, dict):
            adapter_name = str(family.get("adapter") or family.get("base_adapter") or "").strip().lower()
            if adapter_name == "codex":
                return CodexAdapter(
                    name,
                    model=_model_from_family_config(family),
                    profile=_optional_config_text(family.get("profile")),
                    profile_v2=_optional_config_text(family.get("profile_v2")),
                )
            protected = bool(family.get("security_review_write_protected") or family.get("read_only_security_review"))
            provider = str(family.get("provider") or "local")
            candidates.append((family.get("command"), protected, provider))
        else:
            candidates.append((family, False, "local"))
    for command, protected, provider in candidates:
        if isinstance(command, str) and command.strip():
            return LocalCommandAdapter(name, command.split(), security_review_protected=protected, provider=provider)
        if isinstance(command, list) and all(isinstance(item, str) for item in command) and command:
            return LocalCommandAdapter(name, command, security_review_protected=protected, provider=provider)
    return None


def worker_identity_group(name: str, policy: dict[str, Any] | None = None) -> str:
    """Return the independence group used for high-stakes red-team diversity."""
    policy = policy or {}
    family_config = policy.get("worker_families", {})
    family = family_config.get(name) if isinstance(family_config, dict) else None
    adapter = adapter_from_policy(name, policy)
    provider = getattr(adapter, "provider", "unknown") if adapter is not None else "unknown"
    model = getattr(adapter, "model", None) if adapter is not None else None
    if isinstance(family, dict):
        provider = str(family.get("provider") or provider or "unknown")
        model = _model_from_family_config(family) or model
    model_text = str(model or name).strip() or name
    return f"{provider}:{model_text}"


def _optional_config_text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _model_from_family_config(family: dict[str, Any]) -> str | None:
    model = _optional_config_text(family.get("model"))
    env_key = _optional_config_text(family.get("model_env"))
    if env_key:
        model = _optional_config_text(os.environ.get(env_key)) or model
    return model


def worker_diagnostics(policy: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    policy = policy or {}
    names = set(ADAPTERS)
    for key in ["worker_commands", "worker_families"]:
        configured = policy.get(key, {})
        if isinstance(configured, dict):
            names.update(str(item) for item in configured)
    diagnostics: list[dict[str, Any]] = []
    for name in sorted(names):
        adapter = adapter_from_policy(name, policy)
        command = adapter.build_command(Path("prompt.md"), Path("."), "READ_ONLY") if adapter else []
        binary = command[0] if command else name
        diagnostics.append({
            "worker": name,
            "available": bool(binary and shutil.which(binary)),
            "command": command,
            "provider": getattr(adapter, "provider", "local") if adapter else "unknown",
            "configured": name not in ADAPTERS,
        })
    return diagnostics
