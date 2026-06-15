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
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .audit_runtime import container_audit_command, is_hard_audit_isolation_method
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


def _worker_extra_read_dirs(adapter: object) -> list[Path]:
    raw = getattr(adapter, "_sdlc_extra_read_dirs", [])
    if not isinstance(raw, list):
        return []
    dirs: list[Path] = []
    for item in raw:
        try:
            path = Path(str(item)).resolve(strict=False)
        except OSError:
            continue
        dirs.append(path)
    return dirs


def _control_plane_pythonpath() -> str:
    return str(Path(__file__).resolve().parents[1])


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
    hard_audit_isolation: bool = False
    hard_audit_isolation_method: str | None = None
    advisory_audit_isolation: bool = False
    advisory_audit_isolation_method: str | None = None
    audit_isolation_attestation: dict[str, Any] | None = None

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
        data["hard_audit_isolation"] = self.hard_audit_isolation
        if self.hard_audit_isolation_method is not None:
            data["hard_audit_isolation_method"] = self.hard_audit_isolation_method
        data["advisory_audit_isolation"] = self.advisory_audit_isolation
        if self.advisory_audit_isolation_method is not None:
            data["advisory_audit_isolation_method"] = self.advisory_audit_isolation_method
        if self.audit_isolation_attestation is not None:
            data["audit_isolation_attestation"] = self.audit_isolation_attestation
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
        # Always surface cost/token usage for executed runs — real figures when the
        # worker reported them, explicit UNAVAILABLE otherwise. Never silently omit.
        from .usage import extract_usage
        if self.executed:
            data["usage"] = extract_usage(self.stdout)
        else:
            data["usage"] = {"status": "UNAVAILABLE", "reason": "worker not executed (dry-run or unavailable)"}
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
        _ensure_writable_worker_temp_dir(temp_dir)
        extra_read_dirs = _worker_extra_read_dirs(self)
        env = _safe_worker_base_env()
        env.update({
            "SDLC_WORKER_EXECUTION": "1",
            "SDLC_WORKER_REPO": str(repo.resolve(strict=False)),
            "TMPDIR": str(temp_dir),
            "TMP": str(temp_dir),
            "TEMP": str(temp_dir),
            "PYTHONPATH": _control_plane_pythonpath(),
            "SDLC_CONTROL_PLANE_PYTHONPATH": _control_plane_pythonpath(),
            "PYTHONDONTWRITEBYTECODE": "1",
            "SDLC_WORKER_SANITIZED_ENV": "1",
        })
        if run_id:
            env["SDLC_WORKER_RUN_ID"] = run_id
        if _is_audit_workspace_security_review(mode):
            env["SDLC_WORKER_AUDIT_READONLY"] = "1"
        if extra_read_dirs:
            env["SDLC_WORKER_READ_ONLY_REPOS"] = os.pathsep.join(str(path) for path in extra_read_dirs)
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
        try:
            env = self.build_env(prompt_path, repo, mode)
        except OSError as exc:
            return WorkerResult(
                self.name,
                available,
                False,
                command,
                126,
                "",
                f"Worker temp directory is not writable: {exc}",
                started,
                now_iso(),
                mode=mode,
                timeout_seconds=timeout,
            )
        hard_method = getattr(self, "_sdlc_hard_audit_isolation_method", None)
        if hasattr(self, "_sdlc_hard_audit_isolation_method"):
            delattr(self, "_sdlc_hard_audit_isolation_method")
        audit_runtime_config = getattr(self, "_sdlc_audit_isolation_config", None)
        if hasattr(self, "_sdlc_audit_isolation_config"):
            delattr(self, "_sdlc_audit_isolation_config")
        run_command = command
        hard_temp: tempfile.TemporaryDirectory[str] | None = None
        runtime_attestation: dict[str, Any] | None = None
        if hard_method == "macos_sandbox_exec":
            hard_temp = tempfile.TemporaryDirectory(prefix="sdlc-hard-audit-")
            temp_dir = Path(hard_temp.name)
            hard_home = _prepare_hard_audit_home(temp_dir, env)
            for key, child in {
                "XDG_CACHE_HOME": ".xdg-cache",
                "XDG_CONFIG_HOME": ".xdg-config",
                "XDG_DATA_HOME": ".xdg-data",
            }.items():
                path = temp_dir / child
                path.mkdir(parents=True, exist_ok=True)
                env[key] = str(path)
            env["TMPDIR"] = str(temp_dir)
            env["TMP"] = str(temp_dir)
            env["TEMP"] = str(temp_dir)
            env["HOME"] = str(hard_home)
            env["CARGO_TARGET_DIR"] = str(temp_dir / "cargo-target")
            env["SDLC_AUDIT_WRITABLE_DIR"] = str(temp_dir)
            try:
                run_command = _macos_sandbox_exec_command(
                    _external_hard_sandbox_command(command),
                    repo,
                    temp_dir,
                    home_dir=hard_home,
                )
            except OSError as exc:
                hard_temp.cleanup()
                return WorkerResult(
                    self.name,
                    available,
                    False,
                    command,
                    126,
                    "",
                    f"Hard audit isolation unavailable: {exc}",
                    started,
                    now_iso(),
                    mode=mode,
                    timeout_seconds=timeout,
                )
        elif hard_method:
            env["SDLC_AUDIT_HARD_SOURCE_ISOLATION_METHOD"] = str(hard_method)
        if isinstance(audit_runtime_config, dict):
            kind = str(audit_runtime_config.get("kind") or "").strip().lower()
            if kind == "container":
                try:
                    container_command = _external_hard_sandbox_command(run_command)
                    run_command, env, runtime_attestation = container_audit_command(
                        config=audit_runtime_config,
                        command=container_command,
                        repo=repo,
                        env=env,
                    )
                    hard_method = str(audit_runtime_config.get("method") or runtime_attestation.get("method") or "container")
                except (KeyError, OSError, ValueError) as exc:
                    if hard_temp is not None:
                        hard_temp.cleanup()
                    return WorkerResult(
                        self.name,
                        available,
                        False,
                        command,
                        126,
                        "",
                        f"Hard audit isolation runtime could not prepare command: {exc}",
                        started,
                        now_iso(),
                        mode=mode,
                        timeout_seconds=timeout,
                    )
            elif kind == "vm":
                if hard_temp is not None:
                    hard_temp.cleanup()
                return WorkerResult(
                    self.name,
                    available,
                    False,
                    command,
                    126,
                    "",
                    "VM hard audit isolation execution requires a configured VM runner adapter.",
                    started,
                    now_iso(),
                    mode=mode,
                    timeout_seconds=timeout,
                )
        try:
            result = run_cmd(
                run_command,
                repo,
                timeout=timeout,
                input_text=input_text,
                env=env,
                max_output_chars=WORKER_MAX_OUTPUT_CHARS,
            )
        finally:
            if hard_temp is not None:
                hard_temp.cleanup()
        timed_out = result["returncode"] == 124
        stderr = result["stderr"]
        if timed_out:
            timeout_note = f"Timed out after {timeout} seconds"
            stderr = timeout_note if not stderr or stderr == "Timed out" else f"{stderr}\n{timeout_note}"
        process_cleanup_ok = bool(result.get("process_tree_cleanup_ok", True))
        hard_method_text = str(hard_method) if hard_method else None
        hard_isolation = bool(
            hard_method_text
            and is_hard_audit_isolation_method(hard_method_text)
            and process_cleanup_ok
            and not _hard_audit_sandbox_apply_failed(result)
        )
        advisory_isolation = bool(
            hard_method_text
            and not is_hard_audit_isolation_method(hard_method_text)
            and _hard_audit_wrapper_enforced(run_command)
            and process_cleanup_ok
            and not _hard_audit_sandbox_apply_failed(result)
        )
        if runtime_attestation is not None:
            runtime_attestation["process_cleanup_ok"] = process_cleanup_ok
            runtime_attestation["worker_returncode"] = result["returncode"]
            runtime_attestation["hard_isolation"] = hard_isolation
        return WorkerResult(
            self.name,
            True,
            True,
            run_command,
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
            hard_audit_isolation=hard_isolation,
            hard_audit_isolation_method=hard_method_text if hard_isolation else None,
            advisory_audit_isolation=advisory_isolation,
            advisory_audit_isolation_method=hard_method_text if advisory_isolation else None,
            audit_isolation_attestation=runtime_attestation,
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


def _ensure_writable_worker_temp_dir(temp_dir: Path) -> None:
    temp_dir.mkdir(parents=True, exist_ok=True)
    probe = temp_dir / ".sdlc-tmpdir-probe"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError:
        try:
            probe.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def hard_audit_source_isolation_method() -> str | None:
    if _macos_sandbox_exec_usable():
        return "macos_sandbox_exec"
    return None


def hard_audit_source_isolation_available() -> bool:
    return hard_audit_source_isolation_method() is not None


def _macos_sandbox_exec_command(command: list[str], repo: Path, temp_dir: Path, *, home_dir: Path | None = None) -> list[str]:
    sandbox_exec = shutil.which("sandbox-exec")
    if not sandbox_exec:
        raise OSError("sandbox-exec is unavailable")
    repo_path = repo.resolve(strict=False)
    writable_paths = [temp_dir.resolve(strict=False), *_macos_codex_state_write_paths(home_dir)]
    overlapping = [path for path in writable_paths if _paths_overlap(repo_path, path)]
    if overlapping:
        formatted = ", ".join(str(path) for path in overlapping)
        raise OSError(f"macOS sandbox writable paths overlap audited source: {formatted}")
    profile = "\n".join([
        "(version 1)",
        "(deny default)",
        "(allow process*)",
        "(allow ipc*)",
        "(allow mach*)",
        "(allow file-read*)",
        "(allow network*)",
        "(allow sysctl*)",
        '(allow file-write* (literal "/dev/null"))',
        f"(allow file-write* (subpath {_sandbox_string(temp_dir.resolve(strict=False))}))",
    ])
    for path in _macos_sensitive_read_deny_paths(home_dir):
        profile += "\n" + f"(deny file-read* (subpath {_sandbox_string(path.resolve(strict=False))}))"
    for path in _macos_runtime_read_paths(command):
        profile += "\n" + f"(allow file-read* (subpath {_sandbox_string(path.resolve(strict=False))}))"
    for path in _macos_codex_state_write_paths(home_dir):
        profile += "\n" + f"(allow file-read* (subpath {_sandbox_string(path.resolve(strict=False))}))"
        profile += "\n" + f"(allow file-write* (subpath {_sandbox_string(path.resolve(strict=False))}))"
    return [sandbox_exec, "-p", profile, *command]


def _external_hard_sandbox_command(command: list[str]) -> list[str]:
    if len(command) < 2 or command[:2] != ["codex", "exec"]:
        return command
    transformed: list[str] = []
    skip_next = False
    inserted = False
    for item in command:
        if skip_next:
            skip_next = False
            continue
        if item == "--sandbox":
            skip_next = True
            if not inserted:
                transformed.append("--dangerously-bypass-approvals-and-sandbox")
                inserted = True
            continue
        transformed.append(item)
    if not inserted:
        transformed.insert(2, "--dangerously-bypass-approvals-and-sandbox")
    return transformed


def _macos_sandbox_exec_usable() -> bool:
    if sys.platform != "darwin" or not shutil.which("sandbox-exec"):
        return False
    with tempfile.TemporaryDirectory(prefix="sdlc-sandbox-probe-") as tmp:
        root = Path(tmp)
        source = root / "source"
        writable = root / "writable"
        source.mkdir()
        writable.mkdir()
        blocked = source / "blocked.txt"
        allowed = writable / "allowed.txt"
        profile = "\n".join([
            "(version 1)",
            "(deny default)",
            "(allow process*)",
            "(allow file-read*)",
            "(allow sysctl*)",
            '(allow file-write* (literal "/dev/null"))',
            f"(allow file-write* (subpath {_sandbox_string(writable.resolve(strict=False))}))",
        ])
        for path in _macos_sensitive_read_deny_paths():
            profile += "\n" + f"(deny file-read* (subpath {_sandbox_string(path.resolve(strict=False))}))"
        for path in _macos_runtime_read_paths(["sh"]):
            profile += "\n" + f"(allow file-read* (subpath {_sandbox_string(path.resolve(strict=False))}))"
        result = run_cmd([
            "sandbox-exec",
            "-p",
            profile,
            "sh",
            "-c",
            f"printf ok > {_shell_quote(str(allowed))}; (printf blocked > {_shell_quote(str(blocked))}) 2>/dev/null || true",
        ], root, timeout=5)
        return result["returncode"] == 0 and allowed.exists() and not blocked.exists()


def _hard_audit_sandbox_apply_failed(result: dict[str, Any]) -> bool:
    stderr = str(result.get("stderr", ""))
    return int(result.get("returncode", 0) or 0) == 71 or "sandbox_apply" in stderr


def _hard_audit_wrapper_enforced(command: list[str]) -> bool:
    return bool(command) and Path(command[0]).name == "sandbox-exec"


def _macos_codex_state_write_paths(home: Path | None = None) -> list[Path]:
    home = home or Path(os.environ.get("HOME", "")).expanduser()
    if not home.is_absolute():
        return []
    return [
        home / ".codex",
        home / "Library" / "Application Support" / "Codex",
        home / "Library" / "Caches" / "Codex",
        home / "Library" / "Logs" / "Codex",
    ]


def _macos_runtime_read_paths(command: list[str]) -> list[Path]:
    paths = [
        Path("/bin"),
        Path("/usr/bin"),
        Path("/usr/lib"),
        Path("/System/Library"),
        Path("/Library/Apple"),
        Path("/dev"),
        Path("/private/var/db"),
    ]
    for optional in ("/opt/homebrew", "/usr/local"):
        path = Path(optional)
        if path.exists():
            paths.append(path)
    if command:
        binary = shutil.which(command[0])
        if binary:
            paths.append(Path(binary).resolve(strict=False).parent)
    return paths


def _macos_sensitive_read_deny_paths(hard_home: Path | None = None) -> list[Path]:
    home = Path(os.environ.get("HOME", "")).expanduser()
    if not home.is_absolute():
        return []
    candidates = [
        home / ".ssh",
        home / ".aws",
        home / ".gcp",
        home / ".azure",
        home / ".kube",
        home / ".docker",
        home / ".gnupg",
        home / ".codex",
        home / ".config" / "gh",
        home / ".config" / "gcloud",
        home / ".netrc",
        home / "Library" / "Application Support" / "Codex",
        home / "Library" / "Caches" / "Codex",
        home / "Library" / "Logs" / "Codex",
        home / "Desktop",
        home / "Documents",
        home / "Downloads",
    ]
    if hard_home:
        hard_home_resolved = hard_home.resolve(strict=False)
        candidates = [
            path
            for path in candidates
            if not _paths_overlap(path.resolve(strict=False), hard_home_resolved)
        ]
    return [path for path in candidates if path.exists()]


def _prepare_hard_audit_home(temp_dir: Path, env: dict[str, str]) -> Path:
    hard_home = temp_dir / "home"
    hard_home.mkdir(parents=True, exist_ok=True)
    original_home = Path(os.environ.get("HOME", "")).expanduser()
    if original_home.is_absolute():
        source_codex = original_home / ".codex"
        target_codex = hard_home / ".codex"
        if source_codex.is_dir() and not target_codex.exists():
            shutil.copytree(
                source_codex,
                target_codex,
                symlinks=False,
                ignore=shutil.ignore_patterns(
                    "logs",
                    "sessions",
                    "history",
                    "*.log",
                    "*.sock",
                ),
            )
    for key in ("USER", "LOGNAME"):
        if key in os.environ and key not in env:
            env[key] = os.environ[key]
    return hard_home


def _paths_overlap(left: Path, right: Path) -> bool:
    try:
        left.relative_to(right)
        return True
    except ValueError:
        pass
    try:
        right.relative_to(left)
        return True
    except ValueError:
        return False


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _sandbox_string(path: Path) -> str:
    text = str(path)
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


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


def _unique_external_capture_dir(run_dir: Path, worker: str, mode: str, *, label: str | None = None) -> Path:
    repo = run_dir.parents[2]
    external_root = Path(os.environ.get("SDLC_EXTERNAL_EVIDENCE_ROOT", repo.parent / ".sdlc-external-evidence"))
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_label = f"{label}-" if label else ""
    base = external_root / run_dir.name / "worker-results" / f"{stamp}-{safe_label}{worker}-{mode.lower()}"
    candidate = base
    suffix = 2
    while candidate.exists():
        candidate = external_root / run_dir.name / "worker-results" / f"{stamp}-{safe_label}{worker}-{mode.lower()}-{suffix}"
        suffix += 1
    return candidate


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _capture_redteam_result_external(
    *,
    run_dir: Path,
    mode: str,
    prompt_path: Path,
    result: WorkerResult,
    ledger: Ledger,
    label: str | None = None,
) -> dict[str, Any]:
    capture_dir = _unique_external_capture_dir(run_dir, result.worker, mode, label=label)
    capture_dir.mkdir(parents=True, exist_ok=False)
    stdout_path = capture_dir / "stdout.txt"
    stderr_path = capture_dir / "stderr.txt"
    external_result_path = capture_dir / "result.json"

    stdout_text = redact_secrets(result.stdout)
    stderr_text = redact_secrets(result.stderr)
    result.mode = mode
    result.prompt_path = _relative_to_run(run_dir, prompt_path)
    result.output_dir = str(capture_dir)
    result.stdout_path = str(stdout_path)
    result.stderr_path = str(stderr_path)

    stdout_path.write_text(stdout_text, encoding="utf-8")
    stderr_path.write_text(stderr_text, encoding="utf-8")
    result_dict = _redacted_result_dict(result)
    external_result_path.write_text(json.dumps(result_dict, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    manifest_rel = f"artifacts/redteam/worker-captures/{capture_dir.name}/capture.json"
    manifest = {
        "schema_version": 1,
        "externalized": True,
        "worker": result.worker,
        "mode": mode,
        "prompt_path": result.prompt_path,
        "external_output_dir": str(capture_dir),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "external_result_path": str(external_result_path),
        "stdout_sha256": _sha256_text(stdout_text),
        "stderr_sha256": _sha256_text(stderr_text),
        "result_sha256": hashlib.sha256(external_result_path.read_bytes()).hexdigest(),
        "stdout_bytes": len(stdout_text.encode("utf-8")),
        "stderr_bytes": len(stderr_text.encode("utf-8")),
        "returncode": result.returncode,
        "executed": result.executed,
        "available": result.available,
        "timed_out": result.timed_out,
        "stdout_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
    }
    result.result_path = manifest_rel
    ledger.artifact(
        manifest_rel,
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        event="worker.output_externalized",
        redact=False,
        worker=result.worker,
        mode=mode,
        stream="manifest",
        stdout_sha256=manifest["stdout_sha256"],
        stderr_sha256=manifest["stderr_sha256"],
        result_sha256=manifest["result_sha256"],
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
        externalized=True,
    )
    captured = result.to_dict()
    captured["external_result_path"] = str(external_result_path)
    captured["external_capture_manifest"] = manifest_rel
    return captured


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
    if mode.startswith("REDTEAM_ROUND_") and result.executed:
        return _capture_redteam_result_external(
            run_dir=run_dir,
            mode=mode,
            prompt_path=prompt_path,
            result=result,
            ledger=ledger,
            label=label,
        )
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
        sandbox = "workspace-write" if mode in {"BUILD", "FIX", "TEST"} else "read-only"
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
        for extra_dir in _worker_extra_read_dirs(self):
            command.extend(["--add-dir", str(extra_dir)])
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
        command = [
            "claude",
            "--print",
            "--output-format",
            "json",
            "--permission-mode",
            permission_mode,
        ]
        for extra_dir in _worker_extra_read_dirs(self):
            command.extend(["--add-dir", str(extra_dir)])
        return command

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
        candidates.append((configured.get(name), False, "external-custom"))
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
            provider = str(family.get("provider") or "external-custom")
            candidates.append((family.get("command"), protected, provider))
        else:
            candidates.append((family, False, "external-custom"))
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
