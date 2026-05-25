"""External audit worker isolation runtimes and attestations."""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .util import now_iso, run_cmd


HARD_AUDIT_RUNTIME_KINDS = {"container", "vm"}
ADVISORY_AUDIT_RUNTIME_KINDS = {"macos_sandbox_exec"}
UNSAFE_CREDENTIAL_DIRS = (
    ".codex",
    ".ssh",
    ".aws",
    ".gcp",
    ".azure",
    ".kube",
    ".docker",
    ".gnupg",
    ".config/gh",
    ".config/gcloud",
)


@dataclass
class AuditIsolationPreflight:
    worker: str
    provider: str
    requested_kind: str
    runtime_kind: str
    method: str | None
    available: bool
    hard_isolation: bool
    advisory_isolation: bool
    reason: str
    network_mode: str
    auth_mode: str
    attestation: dict[str, Any] = field(default_factory=dict)
    adapter_config: dict[str, Any] | None = None


def audit_isolation_policy(policy: dict[str, Any]) -> dict[str, Any]:
    redteam = policy.get("redteam", {})
    if not isinstance(redteam, dict):
        return {}
    configured = redteam.get("audit_isolation", {})
    return configured if isinstance(configured, dict) else {}


def is_hard_audit_isolation_method(method: str | None) -> bool:
    if not method:
        return False
    return method.startswith("container:") or method.startswith("vm:")


def audit_isolation_preflight(
    *,
    policy: dict[str, Any],
    repo: Path,
    worker: str,
    provider: str,
    prompt_sha256: str,
    allow_network: bool,
) -> AuditIsolationPreflight:
    configured = audit_isolation_policy(policy)
    requested_kind = str(configured.get("runtime") or configured.get("kind") or "auto").strip().lower()
    if requested_kind in {"", "auto"}:
        requested_kind = "container"
    network_mode = _network_mode(configured, allow_network=allow_network)
    auth_mode, auth_reason = _auth_mode(configured)
    base_attestation = {
        "worker": worker,
        "provider": provider,
        "requested_kind": requested_kind,
        "network_mode": network_mode,
        "auth_mode": auth_mode,
        "prompt_sha256": prompt_sha256,
        "source": str(repo.resolve(strict=False)),
        "created_at": now_iso(),
        "unsafe_host_credential_mounts": [],
        "host_credential_dirs_mounted": False,
        "source_mount_readonly": False,
        "source_write_probe": {"attempted": False, "passed": False},
        "home_isolated": False,
        "writable_temp_ephemeral": False,
        "process_containment": False,
        "cleanup_result": {"attempted": False, "passed": False},
    }
    if requested_kind == "none":
        return _preflight_result(
            worker,
            provider,
            requested_kind,
            "none",
            None,
            False,
            False,
            False,
            "Hard audit isolation disabled by policy.",
            network_mode,
            auth_mode,
            base_attestation,
        )
    if requested_kind in ADVISORY_AUDIT_RUNTIME_KINDS:
        base_attestation.update({
            "runtime_kind": requested_kind,
            "method": requested_kind,
            "advisory_isolation": True,
            "hard_isolation": False,
            "disqualifying_reasons": [
                "macOS sandbox-exec is advisory/source-write protection only until strict host-read and credential containment are attested."
            ],
        })
        return _preflight_result(
            worker,
            provider,
            requested_kind,
            requested_kind,
            requested_kind,
            True,
            False,
            True,
            "Advisory isolation is available but does not satisfy high-stakes external hard-isolation policy.",
            network_mode,
            auth_mode,
            base_attestation,
            {"kind": requested_kind, "method": requested_kind},
        )
    if requested_kind == "container":
        return _container_preflight(
            policy=configured,
            repo=repo,
            worker=worker,
            provider=provider,
            prompt_sha256=prompt_sha256,
            allow_network=allow_network,
            base_attestation=base_attestation,
            auth_mode=auth_mode,
            auth_reason=auth_reason,
            network_mode=network_mode,
        )
    if requested_kind == "vm":
        return _vm_preflight(
            policy=configured,
            repo=repo,
            worker=worker,
            provider=provider,
            prompt_sha256=prompt_sha256,
            base_attestation=base_attestation,
            auth_mode=auth_mode,
            auth_reason=auth_reason,
            network_mode=network_mode,
        )
    base_attestation["disqualifying_reasons"] = [f"Unsupported audit isolation runtime: {requested_kind}"]
    return _preflight_result(
        worker,
        provider,
        requested_kind,
        requested_kind,
        None,
        False,
        False,
        False,
        f"Unsupported audit isolation runtime: {requested_kind}",
        network_mode,
        auth_mode,
        base_attestation,
    )


def container_audit_command(
    *,
    config: dict[str, Any],
    command: list[str],
    repo: Path,
    env: dict[str, str],
) -> tuple[list[str], dict[str, str], dict[str, Any]]:
    engine = str(config["engine"])
    image = str(config["image"])
    container_repo = str(config.get("container_repo") or "/workspace/repo")
    container_tmp = str(config.get("container_tmp") or "/workspace/tmp")
    container_home = str(config.get("container_home") or "/workspace/home")
    network_mode = str(config.get("network_mode") or "none")
    auth_env = [str(item) for item in config.get("auth_env", []) if str(item)]
    rewritten_command = _rewrite_repo_paths(command, repo, container_repo)
    container_env = _container_env(env, container_repo, container_tmp, container_home)
    process_env = dict(container_env)
    if "PATH" in env:
        process_env["PATH"] = env["PATH"]
    docker_command = [
        engine,
        "run",
        "--rm",
        "--network",
        network_mode,
        "--workdir",
        container_repo,
        "--mount",
        f"type=bind,src={str(repo.resolve(strict=False))},dst={container_repo},readonly",
        "--tmpfs",
        f"{container_tmp}:rw,nosuid,nodev,size=512m",
        "--tmpfs",
        f"{container_home}:rw,nosuid,nodev,size=256m",
    ]
    for key, value in sorted(container_env.items()):
        docker_command.extend(["--env", f"{key}={value}"])
    for key in auth_env:
        if key in os.environ:
            process_env[key] = os.environ[key]
            docker_command.extend(["--env", key])
    docker_command.append(image)
    docker_command.extend(rewritten_command)
    runtime_attestation = {
        "runtime_kind": "container",
        "method": f"container:{Path(engine).name}",
        "image": image,
        "image_digest": str(config.get("image_digest") or ""),
        "engine": engine,
        "network_mode": network_mode,
        "source_mount": {
            "host": str(repo.resolve(strict=False)),
            "container": container_repo,
            "readonly": True,
        },
        "home": {"container": container_home, "isolated": True},
        "temp": {"container": container_tmp, "ephemeral": True},
        "auth_env_names": auth_env,
        "command_sha256": hashlib.sha256("\0".join(rewritten_command).encode("utf-8")).hexdigest(),
    }
    return docker_command, process_env, runtime_attestation


def _container_preflight(
    *,
    policy: dict[str, Any],
    repo: Path,
    worker: str,
    provider: str,
    prompt_sha256: str,
    allow_network: bool,
    base_attestation: dict[str, Any],
    auth_mode: str,
    auth_reason: str,
    network_mode: str,
) -> AuditIsolationPreflight:
    engine = _container_engine(policy)
    image = str(policy.get("image") or policy.get("container_image") or "").strip()
    auth_env = [str(item).strip() for item in policy.get("auth_env", []) if str(item).strip()] if isinstance(policy.get("auth_env", []), list) else []
    disqualifying: list[str] = []
    if engine is None:
        disqualifying.append("Docker or Podman is not available on PATH.")
    if not image:
        disqualifying.append("redteam.audit_isolation.container_image is required for container hard isolation.")
    if auth_mode == "unsafe":
        disqualifying.append(auth_reason)
    if auth_mode == "scoped_env":
        missing_auth_env = [key for key in auth_env if key not in os.environ or not os.environ.get(key)]
        if not auth_env:
            disqualifying.append("scoped_env audit auth requires at least one auth_env variable name.")
        elif missing_auth_env:
            disqualifying.append("scoped_env audit auth variables are not set: " + ", ".join(missing_auth_env))
    unsafe_mounts = _unsafe_host_credential_mounts(policy)
    if unsafe_mounts:
        disqualifying.append("Policy attempts to mount host credential directories into the audit worker.")
    probe = {"attempted": False, "passed": False}
    if engine and image:
        probe = _container_readonly_probe(engine, image, repo, network_mode)
        if not probe.get("passed"):
            disqualifying.append(str(probe.get("reason") or "Container read-only source probe failed."))
    hard = not disqualifying
    method = f"container:{Path(engine).name}" if engine else None
    base_attestation.update({
        "runtime_kind": "container",
        "method": method,
        "engine": engine,
        "image": image,
        "image_digest": str(policy.get("image_digest") or ""),
        "hard_isolation": hard,
        "advisory_isolation": False,
        "source_mount_readonly": True,
        "source_write_probe": probe,
        "home_isolated": True,
        "writable_temp_ephemeral": True,
        "process_containment": bool(engine),
        "cleanup_result": {"attempted": bool(engine), "passed": bool(engine)},
        "auth_env_names": auth_env,
        "unsafe_host_credential_mounts": unsafe_mounts,
        "host_credential_dirs_mounted": bool(unsafe_mounts),
        "disqualifying_reasons": disqualifying,
    })
    config = None
    if hard and engine:
        config = {
            "kind": "container",
            "engine": engine,
            "image": image,
            "image_digest": str(policy.get("image_digest") or ""),
            "network_mode": network_mode,
            "auth_mode": auth_mode,
            "auth_env": auth_env,
            "container_repo": str(policy.get("container_repo") or "/workspace/repo"),
            "container_tmp": str(policy.get("container_tmp") or "/workspace/tmp"),
            "container_home": str(policy.get("container_home") or "/workspace/home"),
        }
    return _preflight_result(
        worker,
        provider,
        "container",
        "container",
        method,
        bool(engine),
        hard,
        False,
        "Container hard audit isolation preflight passed." if hard else "; ".join(disqualifying),
        network_mode,
        auth_mode,
        base_attestation,
        config,
    )


def _vm_preflight(
    *,
    policy: dict[str, Any],
    repo: Path,
    worker: str,
    provider: str,
    prompt_sha256: str,
    base_attestation: dict[str, Any],
    auth_mode: str,
    auth_reason: str,
    network_mode: str,
) -> AuditIsolationPreflight:
    runner = str(policy.get("runner") or policy.get("vm_runner") or "").strip()
    disqualifying = []
    if not runner:
        disqualifying.append("redteam.audit_isolation.vm_runner is required for VM hard isolation.")
    if runner and shutil.which(runner) is None:
        disqualifying.append(f"Configured VM runner is unavailable: {runner}")
    if auth_mode == "unsafe":
        disqualifying.append(auth_reason)
    hard = not disqualifying
    method = f"vm:{Path(runner).name}" if runner else None
    base_attestation.update({
        "runtime_kind": "vm",
        "method": method,
        "runner": runner,
        "hard_isolation": hard,
        "advisory_isolation": False,
        "source_mount_readonly": hard,
        "source_write_probe": {"attempted": False, "passed": hard, "reason": "VM runner attestation required from runner."},
        "home_isolated": hard,
        "writable_temp_ephemeral": hard,
        "process_containment": hard,
        "cleanup_result": {"attempted": hard, "passed": hard},
        "unsafe_host_credential_mounts": [],
        "disqualifying_reasons": disqualifying,
    })
    config = {"kind": "vm", "runner": runner, "network_mode": network_mode, "auth_mode": auth_mode} if hard else None
    return _preflight_result(
        worker,
        provider,
        "vm",
        "vm",
        method,
        bool(runner),
        hard,
        False,
        "VM hard audit isolation preflight passed." if hard else "; ".join(disqualifying),
        network_mode,
        auth_mode,
        base_attestation,
        config,
    )


def _preflight_result(
    worker: str,
    provider: str,
    requested_kind: str,
    runtime_kind: str,
    method: str | None,
    available: bool,
    hard: bool,
    advisory: bool,
    reason: str,
    network_mode: str,
    auth_mode: str,
    attestation: dict[str, Any],
    config: dict[str, Any] | None = None,
) -> AuditIsolationPreflight:
    attestation.setdefault("runtime_kind", runtime_kind)
    attestation.setdefault("method", method)
    attestation["available"] = available
    attestation["hard_isolation"] = hard
    attestation["advisory_isolation"] = advisory
    attestation["reason"] = reason
    return AuditIsolationPreflight(
        worker=worker,
        provider=provider,
        requested_kind=requested_kind,
        runtime_kind=runtime_kind,
        method=method,
        available=available,
        hard_isolation=hard,
        advisory_isolation=advisory,
        reason=reason,
        network_mode=network_mode,
        auth_mode=auth_mode,
        attestation=attestation,
        adapter_config=config,
    )


def _container_engine(policy: dict[str, Any]) -> str | None:
    configured = str(policy.get("engine") or policy.get("container_engine") or "auto").strip()
    candidates = ["docker", "podman"] if configured in {"", "auto"} else [configured]
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    return None


def _container_readonly_probe(engine: str, image: str, repo: Path, network_mode: str) -> dict[str, Any]:
    probe_name = ".sdlc-readonly-probe"
    command = [
        engine,
        "run",
        "--rm",
        "--network",
        network_mode,
        "--workdir",
        "/workspace/repo",
        "--mount",
        f"type=bind,src={str(repo.resolve(strict=False))},dst=/workspace/repo,readonly",
        "--tmpfs",
        "/workspace/tmp:rw,nosuid,nodev,size=64m",
        image,
        "sh",
        "-c",
        f"rm -f /workspace/tmp/{probe_name}; if (printf blocked > /workspace/repo/{probe_name}) 2>/dev/null; then exit 42; fi; printf ok > /workspace/tmp/{probe_name}",
    ]
    result = run_cmd(command, repo, timeout=30)
    try:
        (repo / probe_name).unlink(missing_ok=True)
    except OSError:
        pass
    passed = result["returncode"] == 0
    return {
        "attempted": True,
        "passed": passed,
        "returncode": result["returncode"],
        "stdout_sha256": hashlib.sha256(str(result.get("stdout") or "").encode("utf-8")).hexdigest(),
        "stderr_sha256": hashlib.sha256(str(result.get("stderr") or "").encode("utf-8")).hexdigest(),
        "reason": "" if passed else "Container read-only source probe failed or could write to the source mount.",
    }


def _auth_mode(policy: dict[str, Any]) -> tuple[str, str]:
    auth = policy.get("auth", {})
    if isinstance(auth, dict):
        mode = str(auth.get("mode") or policy.get("auth_mode") or "absent").strip().lower()
    else:
        mode = str(policy.get("auth_mode") or "absent").strip().lower()
    if mode in {"brokered", "scoped_env", "absent"}:
        return mode, ""
    return "unsafe", f"Unsupported or unsafe audit auth mode: {mode or '<empty>'}"


def _network_mode(policy: dict[str, Any], *, allow_network: bool) -> str:
    configured = str(policy.get("network_mode") or "").strip().lower()
    if configured:
        return configured
    return "bridge" if allow_network else "none"


def _unsafe_host_credential_mounts(policy: dict[str, Any]) -> list[str]:
    raw_mounts = policy.get("mounts", [])
    if not isinstance(raw_mounts, list):
        return []
    home = Path(os.environ.get("HOME", "")).expanduser().resolve(strict=False)
    unsafe: list[str] = []
    for item in raw_mounts:
        host_path = None
        if isinstance(item, str):
            host_path = item
        elif isinstance(item, dict):
            host_path = item.get("host") or item.get("source")
        if not host_path:
            continue
        path = Path(str(host_path)).expanduser().resolve(strict=False)
        for rel in UNSAFE_CREDENTIAL_DIRS:
            try:
                path.relative_to(home / rel)
                unsafe.append(str(path))
                break
            except ValueError:
                continue
    return sorted(set(unsafe))


def _container_env(env: dict[str, str], repo_path: str, temp_path: str, home_path: str) -> dict[str, str]:
    allowed = {
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "SDLC_WORKER_EXECUTION",
        "SDLC_WORKER_RUN_ID",
        "SDLC_WORKER_SANITIZED_ENV",
        "SDLC_WORKER_AUDIT_READONLY",
        "PYTHONDONTWRITEBYTECODE",
    }
    cleaned = {key: value for key, value in env.items() if key in allowed or key.startswith("LC_")}
    cleaned.update({
        "HOME": home_path,
        "TMPDIR": temp_path,
        "TMP": temp_path,
        "TEMP": temp_path,
        "SDLC_WORKER_REPO": repo_path,
        "SDLC_AUDIT_HARD_SOURCE_ISOLATION_METHOD": "container",
    })
    return cleaned


def _rewrite_repo_paths(command: list[str], repo: Path, container_repo: str) -> list[str]:
    repo_text = str(repo.resolve(strict=False))
    rewritten: list[str] = []
    for item in command:
        if item == repo_text:
            rewritten.append(container_repo)
        elif item.startswith(repo_text + os.sep):
            rewritten.append(container_repo + "/" + item[len(repo_text) + 1:])
        else:
            rewritten.append(item)
    return rewritten
