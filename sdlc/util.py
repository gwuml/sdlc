"""Small utility functions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any


SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)(\s*[:=]\s*)([^\s\"']+)"),
    re.compile(r"(?i)(bearer\s+)[a-z0-9._~+/=-]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
]

SUBPROCESS_ENV_ALLOWLIST = {
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "TMPDIR",
    "TMP",
    "TEMP",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
}

SENSITIVE_ENV_PREFIXES = (
    "SDLC_",
    "OPENAI_",
    "ANTHROPIC_",
    "GEMINI_",
    "GOOGLE_",
    "KIMI_",
    "MOONSHOT_",
    "AWS_",
    "AZURE_",
    "GCP_",
    "GITHUB_",
    "GH_",
)

SENSITIVE_ENV_FRAGMENTS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
    "SESSION",
    "CREDENTIAL",
)


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def slugify(text: str, max_len: int = 52) -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return (text[:max_len].strip("-") or "feature")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_json(path: Path, default: Any | None = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(data, sort_keys=True) + "\n")


def redact_secrets(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        if pattern.groups >= 3:
            redacted = pattern.sub(r"\1\2[REDACTED]", redacted)
        elif pattern.groups >= 1:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def sanitized_subprocess_env(*, disable_git_hooks: bool = True) -> dict[str, str]:
    env: dict[str, str] = {}
    for key, value in os.environ.items():
        if key in SUBPROCESS_ENV_ALLOWLIST or key.startswith("LC_"):
            if not _sensitive_env_key(key):
                env[key] = value
    env.setdefault("PATH", os.defpath)
    if disable_git_hooks:
        env.update({
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        })
    return env


def _sensitive_env_key(key: str) -> bool:
    upper = key.upper()
    return upper.startswith(SENSITIVE_ENV_PREFIXES) or any(fragment in upper for fragment in SENSITIVE_ENV_FRAGMENTS)


def resolve_under_base(base: Path, path: Path, *, must_exist: bool = True) -> tuple[Path | None, str | None]:
    base_resolved = base.resolve(strict=False)
    candidate = path if path.is_absolute() else base_resolved / path
    try:
        resolved = candidate.resolve(strict=must_exist)
    except FileNotFoundError:
        return None, f"Path does not exist: {path}"
    try:
        resolved.relative_to(base_resolved)
    except ValueError:
        return None, f"Path escapes allowed root {base_resolved}: {path}"
    if must_exist and not resolved.exists():
        return None, f"Path does not exist: {path}"
    return resolved, None


def relpath_under_base(base: Path, path: Path, *, must_exist: bool = False) -> str:
    resolved, error = resolve_under_base(base, path, must_exist=must_exist)
    if error or resolved is None:
        raise ValueError(error or f"Path escapes allowed root {base}: {path}")
    return str(resolved.relative_to(base.resolve(strict=False)))


def resolve_repo_paths(repo: Path, paths: list[str], *, required: bool = True) -> tuple[list[str], str | None]:
    if required and not paths:
        return [], "--evidence is required"
    resolved_paths: list[str] = []
    for item in paths:
        resolved, error = resolve_under_base(repo, Path(item), must_exist=True)
        if error or resolved is None:
            return [], error or f"Invalid path: {item}"
        resolved_paths.append(str(resolved.relative_to(repo.resolve(strict=False))))
    return resolved_paths, None


def run_cmd(
    cmd: list[str],
    cwd: Path,
    timeout: int = 30,
    input_text: str | None = None,
    max_output_chars: int = 1_000_000,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    def _read_limited(handle: Any) -> tuple[str, bool]:
        handle.seek(0)
        data = handle.read(max_output_chars + 1)
        truncated = len(data) > max_output_chars
        if truncated:
            data = data[:max_output_chars]
        return _subprocess_text(data), truncated

    try:
        with tempfile.TemporaryFile(mode="w+b") as stdout, tempfile.TemporaryFile(mode="w+b") as stderr:
            proc = subprocess.Popen(
                cmd,
                cwd=str(cwd),
                text=False,
                stdin=subprocess.PIPE if input_text is not None else None,
                stdout=stdout,
                stderr=stderr,
                env=env if env is not None else sanitized_subprocess_env(),
            )
            try:
                proc.communicate(input=input_text.encode("utf-8") if input_text is not None else None, timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                out, out_truncated = _read_limited(stdout)
                err, err_truncated = _read_limited(stderr)
                return {
                    "cmd": cmd,
                    "returncode": 124,
                    "stdout": out,
                    "stderr": err or "Timed out",
                    "stdout_truncated": out_truncated,
                    "stderr_truncated": err_truncated,
                    "max_output_chars": max_output_chars,
                }
            out, out_truncated = _read_limited(stdout)
            err, err_truncated = _read_limited(stderr)
            return {
                "cmd": cmd,
                "returncode": proc.returncode,
                "stdout": out,
                "stderr": err,
                "stdout_truncated": out_truncated,
                "stderr_truncated": err_truncated,
                "max_output_chars": max_output_chars,
            }
    except FileNotFoundError:
        return {"cmd": cmd, "returncode": 127, "stdout": "", "stderr": f"Command not found: {cmd[0]}", "stdout_truncated": False, "stderr_truncated": False, "max_output_chars": max_output_chars}


def _subprocess_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def git_current_branch(repo: Path) -> str:
    result = run_cmd(["git", "branch", "--show-current"], repo)
    branch = result["stdout"].strip()
    return branch or "unknown"


def is_git_repo(repo: Path) -> bool:
    return (repo / ".git").exists() or run_cmd(["git", "rev-parse", "--is-inside-work-tree"], repo)["returncode"] == 0


def find_files(repo: Path, patterns: list[str], max_files: int = 50) -> list[str]:
    found: list[str] = []
    for pattern in patterns:
        for path in repo.glob(pattern):
            if path.is_file():
                try:
                    found.append(str(path.relative_to(repo)))
                except ValueError:
                    found.append(str(path))
                if len(found) >= max_files:
                    return found
    return found


def env_truthy(name: str) -> bool:
    return os.getenv(name, "").lower() in {"1", "true", "yes", "on"}
