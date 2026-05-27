"""Release-lane prerequisite checks.

These checks intentionally run before expensive worker execution. They do not
replace release validation; they fail fast when the known release prerequisites
are absent so users do not discover the same blockers at the end of a run.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .adapters import adapter_from_policy
from .audit_runtime import audit_isolation_preflight, audit_isolation_policy
from .util import git_current_branch, is_git_repo, run_cmd


DEFAULT_ATTESTATION_KEY_PATH = Path("~/.sdlc-control-plane/attestation.key").expanduser()
DEFAULT_ACTOR_PROOF_KEY_PATH = Path("~/.sdlc-control-plane/actor-proof.key").expanduser()
PROTECTED_BRANCHES = {"main", "master", "trunk", "prod", "production"}
SAFE_AUDIT_AUTH_MODES = {"absent", "brokered", "scoped_env", "host_oauth"}


@dataclass
class ReleaseRequirement:
    requirement_id: str
    title: str
    status: str
    blocking: bool
    detail: str
    remediation: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReleasePreflightResult:
    repo: str
    risk_level: str
    policy_profile: str
    status: str
    requirements: list[ReleaseRequirement]

    @property
    def blockers(self) -> list[ReleaseRequirement]:
        return [item for item in self.requirements if item.blocking and item.status != "GO"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "repo": self.repo,
            "risk_level": self.risk_level,
            "policy_profile": self.policy_profile,
            "status": self.status,
            "blockers": [item.to_dict() for item in self.blockers],
            "requirements": [item.to_dict() for item in self.requirements],
        }


def release_preflight(
    *,
    repo: Path,
    policy: dict[str, Any],
    policy_profile: str,
    risk_level: str,
    allow_network: bool = False,
    workers: list[str] | None = None,
    run_id: str | None = None,
    prompt_sha256: str = "",
    check_isolation_runtime: bool = False,
    require_clean_worktree: bool = True,
    require_branch: bool = True,
    require_attestation_key: bool = True,
    require_actor_proof_key: bool = True,
    require_scanner_policy: bool = True,
    require_hard_isolation: bool = True,
) -> ReleasePreflightResult:
    normalized_risk = str(risk_level or "HIGH").upper()
    requirements: list[ReleaseRequirement] = []
    requirements.append(_git_repo_requirement(repo))
    if require_branch:
        requirements.append(_branch_requirement(repo, policy))
    if require_clean_worktree:
        requirements.append(_worktree_requirement(repo))
    if require_scanner_policy:
        requirements.append(_scanner_policy_requirement(repo, policy, normalized_risk))
    requirements.append(_deployment_authority_requirement(policy))
    if require_attestation_key:
        requirements.append(_key_file_requirement(
            repo=repo,
            run_id=run_id,
            requirement_id="attestation-key",
            title="Attestation signing key",
            env_file="SDLC_ATTESTATION_KEY_FILE",
            env_value="",
            default_path=DEFAULT_ATTESTATION_KEY_PATH,
            remediation=(
                "Create a signing key outside the repo, then run "
                "`sdlc attest sign <run-id> --key ~/.sdlc-control-plane/attestation.key --execute`."
            ),
        ))
    if require_actor_proof_key and bool(policy.get("actor_proof_required_for_finding_closure", False)):
        requirements.append(_key_file_requirement(
            repo=repo,
            run_id=run_id,
            requirement_id="actor-proof-key",
            title="Actor proof key",
            env_file="SDLC_ACTOR_PROOF_KEY_FILE",
            env_value="SDLC_ACTOR_PROOF_KEY",
            default_path=DEFAULT_ACTOR_PROOF_KEY_PATH,
            remediation=(
                "Set SDLC_ACTOR_PROOF_KEY_FILE to a key outside the repo, or set "
                "SDLC_ACTOR_PROOF_KEY in the invoking environment."
            ),
        ))
    if require_hard_isolation:
        requirements.extend(_hard_isolation_requirements(
            repo=repo,
            policy=policy,
            risk_level=normalized_risk,
            workers=workers,
            allow_network=allow_network,
            prompt_sha256=prompt_sha256,
            check_runtime=check_isolation_runtime,
        ))
    status = "NO_GO" if any(item.blocking and item.status != "GO" for item in requirements) else "GO"
    return ReleasePreflightResult(
        repo=str(repo),
        risk_level=normalized_risk,
        policy_profile=policy_profile,
        status=status,
        requirements=requirements,
    )


def release_preflight_error(result: ReleasePreflightResult) -> str | None:
    blockers = result.blockers
    if not blockers:
        return None
    lines = ["Release prerequisites are not satisfied:"]
    for item in blockers:
        lines.append(f"- {item.title}: {item.detail}")
        lines.append(f"  Fix: {item.remediation}")
    lines.append("Run `sdlc release doctor --json` for machine-readable details.")
    return "\n".join(lines)


def default_policy_redteam_workers(policy: dict[str, Any]) -> list[str]:
    redteam = policy.get("redteam", {})
    configured = redteam.get("default_workers") if isinstance(redteam, dict) else None
    if isinstance(configured, list):
        workers = [str(worker).strip() for worker in configured if str(worker).strip()]
        if workers:
            return workers
    workers_policy = policy.get("workers", {})
    if isinstance(workers_policy, dict):
        redteam_worker = str(workers_policy.get("redteam") or "").strip()
        if redteam_worker:
            return [redteam_worker]
    return ["codex"]


def _requirement(
    requirement_id: str,
    title: str,
    status: str,
    detail: str,
    remediation: str,
    *,
    blocking: bool = True,
    metadata: dict[str, Any] | None = None,
) -> ReleaseRequirement:
    return ReleaseRequirement(
        requirement_id=requirement_id,
        title=title,
        status=status,
        blocking=blocking,
        detail=detail,
        remediation=remediation,
        metadata=metadata or {},
    )


def _git_repo_requirement(repo: Path) -> ReleaseRequirement:
    if is_git_repo(repo):
        return _requirement("git-repo", "Git repository", "GO", "Repository is inside a Git worktree.", "No action required.")
    return _requirement(
        "git-repo",
        "Git repository",
        "NO_GO",
        "Release runs require Git provenance, but the target path is not a Git worktree.",
        "Initialize Git or run SDLC against the real repository checkout.",
    )


def _branch_requirement(repo: Path, policy: dict[str, Any]) -> ReleaseRequirement:
    if not is_git_repo(repo):
        return _requirement(
            "feature-branch",
            "Feature branch",
            "NO_GO",
            "Cannot determine a release branch outside a Git worktree.",
            "Initialize Git and create a non-protected feature branch.",
        )
    branch = git_current_branch(repo)
    if not branch or branch in {"unknown", "<unknown>", "HEAD"}:
        return _requirement(
            "feature-branch",
            "Feature branch",
            "NO_GO",
            "Current Git checkout is detached or branch name is unavailable.",
            "Create or switch to a feature branch before release-lane execution.",
        )
    direct_main_allowed = bool(policy.get("direct_main_push_allowed", False))
    if branch in PROTECTED_BRANCHES and not direct_main_allowed:
        return _requirement(
            "feature-branch",
            "Feature branch",
            "NO_GO",
            f"Current branch `{branch}` is protected and direct main push is not allowed by policy.",
            "Run `sdlc git branch <run-id>` or switch to a non-protected feature branch.",
            metadata={"branch": branch},
        )
    return _requirement(
        "feature-branch",
        "Feature branch",
        "GO",
        f"Current branch `{branch}` is acceptable for release-lane provenance.",
        "No action required.",
        metadata={"branch": branch},
    )


def _worktree_requirement(repo: Path) -> ReleaseRequirement:
    if not is_git_repo(repo):
        return _requirement(
            "clean-worktree",
            "Clean worktree",
            "NO_GO",
            "Cannot verify worktree cleanliness outside a Git repository.",
            "Initialize Git and commit the SDLC baseline before release-lane execution.",
        )
    result = run_cmd(["git", "status", "--porcelain=v1", "--untracked-files=all"], repo, timeout=60)
    if result["returncode"] != 0:
        return _requirement(
            "clean-worktree",
            "Clean worktree",
            "NO_GO",
            "Git status failed while checking release baseline cleanliness.",
            "Fix the Git checkout and rerun `sdlc release doctor`.",
            metadata={"returncode": result["returncode"], "stderr": result.get("stderr", "")},
        )
    dirty = [line for line in str(result.get("stdout") or "").splitlines() if line.strip()]
    if dirty:
        preview = ", ".join(dirty[:8])
        suffix = "" if len(dirty) <= 8 else f", ... ({len(dirty)} total)"
        return _requirement(
            "clean-worktree",
            "Clean worktree",
            "NO_GO",
            f"Worktree has uncommitted or untracked files: {preview}{suffix}",
            "Commit, stash, or move unrelated changes before starting a release-lane run.",
            metadata={"dirty_count": len(dirty), "dirty_preview": dirty[:25]},
        )
    return _requirement("clean-worktree", "Clean worktree", "GO", "Worktree is clean.", "No action required.")


def _scanner_policy_requirement(repo: Path, policy: dict[str, Any], risk_level: str) -> ReleaseRequirement:
    thresholds = policy.get("scanner_thresholds", {})
    dependency_required = bool(thresholds.get("dependency_audit_required", False)) if isinstance(thresholds, dict) else False
    if risk_level not in {"HIGH", "EXTREME"} or not dependency_required:
        return _requirement(
            "scanner-policy",
            "Scanner policy",
            "GO",
            "Release scanner policy does not require network dependency audit for this risk level.",
            "No action required.",
        )
    if not bool(policy.get("network_allowed", False)):
        return _requirement(
            "scanner-policy",
            "Scanner policy",
            "NO_GO",
            "Policy requires dependency audit evidence, but network_allowed=false blocks pip-audit.",
            "Use a release policy with network_allowed=true for scanner execution or explicitly revise the scanner policy.",
        )
    pip_audit = _tool_path(repo, "pip-audit")
    if pip_audit is None:
        return _requirement(
            "scanner-policy",
            "Scanner policy",
            "NO_GO",
            "Policy requires dependency audit evidence, but pip-audit is unavailable.",
            "Install the package scanner in the active environment before release-lane execution.",
        )
    return _requirement(
        "scanner-policy",
        "Scanner policy",
        "GO",
        "Dependency audit policy and pip-audit availability are compatible with release validation.",
        "No action required.",
        metadata={"pip_audit": str(pip_audit)},
    )


def _deployment_authority_requirement(policy: dict[str, Any]) -> ReleaseRequirement:
    if bool(policy.get("production_rollout_allowed", False)):
        return _requirement(
            "deployment-authority",
            "Deployment authority",
            "GO",
            "Production rollout is policy-enabled, but execution still requires human approval, rollback evidence, and release validation.",
            "No action required before release validation; keep production execution explicit.",
            blocking=False,
        )
    return _requirement(
        "deployment-authority",
        "Deployment authority",
        "GO",
        "Production rollout is locked by policy; SDLC outputs are advisory/PR evidence until a human release owner approves deployment.",
        "No action required unless this run is explicitly intended to deploy production.",
        blocking=False,
    )


def _key_file_requirement(
    *,
    repo: Path,
    run_id: str | None,
    requirement_id: str,
    title: str,
    env_file: str,
    env_value: str,
    default_path: Path,
    remediation: str,
) -> ReleaseRequirement:
    if env_value and os.environ.get(env_value):
        return _requirement(
            requirement_id,
            title,
            "GO",
            f"{env_value} is set in the invoking environment.",
            "No action required.",
            metadata={"source": env_value},
        )
    configured = os.environ.get(env_file)
    path = Path(configured).expanduser() if configured else default_path
    if not path.exists() or not path.is_file():
        return _requirement(
            requirement_id,
            title,
            "NO_GO",
            f"Required key file is unavailable: {path}",
            remediation,
            metadata={"path": str(path), "env_file": env_file},
        )
    if _path_inside_repo_or_run(path, repo, run_id):
        return _requirement(
            requirement_id,
            title,
            "NO_GO",
            f"Key file must live outside the repository and run artifacts: {path}",
            remediation,
            metadata={"path": str(path), "env_file": env_file},
        )
    return _requirement(
        requirement_id,
        title,
        "GO",
        f"Key file exists outside the repository: {path}",
        "No action required.",
        metadata={"path": str(path), "env_file": env_file},
    )


def _hard_isolation_requirements(
    *,
    repo: Path,
    policy: dict[str, Any],
    risk_level: str,
    workers: list[str] | None,
    allow_network: bool,
    prompt_sha256: str,
    check_runtime: bool,
) -> list[ReleaseRequirement]:
    worker_names = workers or default_policy_redteam_workers(policy)
    external_workers = _external_workers(policy, worker_names)
    if risk_level not in {"HIGH", "EXTREME"} or not external_workers:
        return [_requirement(
            "redteam-hard-isolation",
            "Red-team hard isolation",
            "GO",
            "No high-stakes external red-team worker requires hard audit isolation for this run.",
            "No action required.",
            metadata={"workers": worker_names, "external_workers": external_workers},
        )]
    configured = audit_isolation_policy(policy)
    runtime = str(configured.get("runtime") or configured.get("kind") or "auto").strip().lower()
    if runtime in {"", "auto"}:
        runtime = "macos_sandbox_exec" if sys.platform == "darwin" else "container"
    requirements: list[ReleaseRequirement] = []
    if runtime == "container":
        requirements.append(_container_policy_requirement(repo, configured))
    elif runtime == "vm":
        requirements.append(_vm_policy_requirement(configured))
    elif runtime == "macos_sandbox_exec":
        requirements.append(_macos_sandbox_policy_requirement(
            repo=repo,
            policy=policy,
            workers=external_workers,
            allow_network=allow_network,
            prompt_sha256=prompt_sha256,
        ))
    else:
        requirements.append(_requirement(
            "redteam-hard-isolation",
            "Red-team hard isolation",
            "NO_GO",
            f"High-stakes external red-team requires hard audit isolation, but policy runtime is `{runtime}`.",
            "Set redteam.audit_isolation.runtime to `macos_sandbox_exec`, `container`, or `vm` and configure the runner.",
            metadata={"runtime": runtime, "external_workers": external_workers},
        ))
    requirements.append(_audit_auth_requirement(configured))
    if check_runtime:
        requirements.extend(_runtime_probe_requirements(
            repo=repo,
            policy=policy,
            workers=external_workers,
            allow_network=allow_network,
            prompt_sha256=prompt_sha256,
        ))
    for requirement in requirements:
        requirement.metadata.setdefault("external_workers", external_workers)
    return requirements


def _external_workers(policy: dict[str, Any], workers: list[str]) -> list[str]:
    external: list[str] = []
    for worker in workers:
        adapter = adapter_from_policy(worker, policy)
        provider = str(getattr(adapter, "provider", "unknown") if adapter is not None else "unknown").strip().lower()
        if provider != "local":
            external.append(worker)
    return external


def _container_policy_requirement(repo: Path, configured: dict[str, Any]) -> ReleaseRequirement:
    engine = str(configured.get("container_engine") or configured.get("engine") or "auto").strip()
    image = str(configured.get("container_image") or configured.get("image") or "").strip()
    digest = str(configured.get("image_digest") or "").strip()
    engine_path = _container_engine_path(engine)
    if engine_path is None:
        return _requirement(
            "redteam-container-runtime",
            "Red-team container runtime",
            "NO_GO",
            f"Configured container engine is unavailable: {engine or 'auto'}",
            "Install Docker/Podman or configure redteam.audit_isolation.container_engine to an available runtime.",
            metadata={"engine": engine},
        )
    if not image:
        return _requirement(
            "redteam-container-image",
            "Red-team audit image",
            "NO_GO",
            "redteam.audit_isolation.container_image is empty.",
            "Configure a real audit worker image pinned by digest, for example `image@sha256:<digest>`.",
            metadata={"engine_path": engine_path},
        )
    if not _image_pinned_by_digest(image, digest):
        return _requirement(
            "redteam-container-image",
            "Red-team audit image",
            "NO_GO",
            f"Audit image is not digest-pinned: {image}",
            "Use an immutable image reference such as `your-audit-worker-image@sha256:<digest>`.",
            metadata={"image": image, "image_digest": digest, "engine_path": engine_path},
        )
    return _requirement(
        "redteam-container-image",
        "Red-team audit image",
        "GO",
        "Container audit image is configured with an immutable digest pin.",
        "No action required.",
        metadata={"image": image, "image_digest": digest, "engine_path": engine_path, "repo": str(repo)},
    )


def _vm_policy_requirement(configured: dict[str, Any]) -> ReleaseRequirement:
    runner = str(configured.get("vm_runner") or configured.get("runner") or "").strip()
    if not runner:
        return _requirement(
            "redteam-vm-runtime",
            "Red-team VM runtime",
            "NO_GO",
            "redteam.audit_isolation.vm_runner is empty.",
            "Configure the VM runner used for read-only audit isolation.",
        )
    if shutil.which(runner) is None:
        return _requirement(
            "redteam-vm-runtime",
            "Red-team VM runtime",
            "NO_GO",
            f"Configured VM runner is unavailable: {runner}",
            "Install the VM runner or correct redteam.audit_isolation.vm_runner.",
            metadata={"runner": runner},
        )
    return _requirement(
        "redteam-vm-runtime",
        "Red-team VM runtime",
        "GO",
        f"Configured VM runner is available: {runner}",
        "No action required.",
        metadata={"runner": runner},
    )


def _macos_sandbox_policy_requirement(
    *,
    repo: Path,
    policy: dict[str, Any],
    workers: list[str],
    allow_network: bool,
    prompt_sha256: str,
) -> ReleaseRequirement:
    worker = workers[0] if workers else "redteam"
    adapter = adapter_from_policy(worker, policy)
    provider = str(getattr(adapter, "provider", "unknown") if adapter is not None else "unknown").strip().lower()
    result = audit_isolation_preflight(
        policy=policy,
        repo=repo,
        worker=worker,
        provider=provider,
        prompt_sha256=prompt_sha256,
        allow_network=allow_network,
    )
    if result.hard_isolation:
        return _requirement(
            "redteam-local-sandbox",
            "Red-team local sandbox",
            "GO",
            "Local macOS sandbox-exec audit isolation passed; red-team will use host OAuth from an ephemeral sandbox home.",
            "No action required.",
            metadata={
                "method": result.method,
                "runtime_kind": result.runtime_kind,
                "auth_mode": result.auth_mode,
                "worker": worker,
            },
        )
    return _requirement(
        "redteam-local-sandbox",
        "Red-team local sandbox",
        "NO_GO",
        result.reason,
        "Use a macOS host with sandbox-exec and host Codex/OpenAI OAuth, or explicitly configure a container/VM audit runtime.",
        metadata={
            "method": result.method,
            "runtime_kind": result.runtime_kind,
            "auth_mode": result.auth_mode,
            "worker": worker,
        },
    )


def _audit_auth_requirement(configured: dict[str, Any]) -> ReleaseRequirement:
    runtime = str(configured.get("runtime") or configured.get("kind") or "auto").strip().lower()
    auth = configured.get("auth", {})
    if isinstance(auth, dict):
        mode = str(auth.get("mode") or configured.get("auth_mode") or "absent").strip().lower().replace("-", "_")
    else:
        mode = str(configured.get("auth_mode") or "absent").strip().lower().replace("-", "_")
    auth_env = [str(item).strip() for item in configured.get("auth_env", []) if str(item).strip()] if isinstance(configured.get("auth_env", []), list) else []
    if mode not in SAFE_AUDIT_AUTH_MODES:
        return _requirement(
            "redteam-audit-auth",
            "Red-team scoped auth",
            "NO_GO",
            f"Audit auth mode is unsafe or unsupported: {mode or '<empty>'}",
            "Use auth.mode `host_oauth`, `absent`, `brokered`, or `scoped_env`; never mount host credential directories.",
            metadata={"auth_mode": mode},
        )
    if mode == "host_oauth":
        codex_dir = Path.home() / ".codex"
        if runtime != "macos_sandbox_exec":
            return _requirement(
                "redteam-audit-auth",
                "Red-team scoped auth",
                "NO_GO",
                "host_oauth auth is only accepted with local macOS sandbox-exec audit isolation.",
                "Set redteam.audit_isolation.runtime to `macos_sandbox_exec` or use brokered/scoped auth.",
                metadata={"auth_mode": mode, "runtime": runtime},
            )
        if not codex_dir.is_dir():
            return _requirement(
                "redteam-audit-auth",
                "Red-team scoped auth",
                "NO_GO",
                f"Host Codex/OpenAI OAuth state is unavailable: {codex_dir}",
                "Authenticate Codex/OpenAI on the host so ~/.codex exists; SDLC copies it only into an ephemeral sandbox home.",
                metadata={"auth_mode": mode, "path": str(codex_dir)},
            )
        return _requirement(
            "redteam-audit-auth",
            "Red-team scoped auth",
            "GO",
            "Host OAuth is available and will be copied only into the ephemeral local audit sandbox home.",
            "No action required.",
            metadata={"auth_mode": mode, "path": str(codex_dir)},
        )
    if mode == "scoped_env":
        missing = [name for name in auth_env if not os.environ.get(name)]
        if not auth_env:
            return _requirement(
                "redteam-audit-auth",
                "Red-team scoped auth",
                "NO_GO",
                "scoped_env audit auth requires at least one auth_env variable name.",
                "Configure redteam.audit_isolation.auth_env with scoped broker token variable names.",
                metadata={"auth_mode": mode},
            )
        if missing:
            return _requirement(
                "redteam-audit-auth",
                "Red-team scoped auth",
                "NO_GO",
                "Scoped audit auth variables are not set: " + ", ".join(missing),
                "Set only scoped, brokered audit credentials in the invoking environment.",
                metadata={"auth_mode": mode, "missing": missing},
            )
    return _requirement(
        "redteam-audit-auth",
        "Red-team scoped auth",
        "GO",
        f"Audit auth mode is policy-scoped: {mode}",
        "No action required.",
        metadata={"auth_mode": mode, "auth_env": auth_env},
    )


def _runtime_probe_requirements(
    *,
    repo: Path,
    policy: dict[str, Any],
    workers: list[str],
    allow_network: bool,
    prompt_sha256: str,
) -> list[ReleaseRequirement]:
    requirements: list[ReleaseRequirement] = []
    for worker in workers:
        adapter = adapter_from_policy(worker, policy)
        provider = str(getattr(adapter, "provider", "unknown") if adapter is not None else "unknown").strip().lower()
        result = audit_isolation_preflight(
            policy=policy,
            repo=repo,
            worker=worker,
            provider=provider,
            prompt_sha256=prompt_sha256,
            allow_network=allow_network,
        )
        status = "GO" if result.hard_isolation else "NO_GO"
        requirements.append(_requirement(
            f"redteam-isolation-runtime-{worker}",
            f"Runtime isolation probe for {worker}",
            status,
            result.reason,
            "Fix the audit isolation policy/runtime and rerun `sdlc isolation preflight <run-id>`.",
            metadata={
                "worker": worker,
                "method": result.method,
                "runtime_kind": result.runtime_kind,
                "network_mode": result.network_mode,
                "auth_mode": result.auth_mode,
            },
        ))
    return requirements


def _container_engine_path(configured: str) -> str | None:
    candidates = ["docker", "podman"] if configured in {"", "auto"} else [configured]
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    return None


def _image_pinned_by_digest(image: str, digest: str) -> bool:
    if re.search(r"@sha256:[a-f0-9]{64}$", image):
        return True
    return bool(re.fullmatch(r"sha256:[a-f0-9]{64}|[a-f0-9]{64}", digest))


def _tool_path(repo: Path, executable: str) -> Path | None:
    found = shutil.which(executable)
    if found:
        return Path(found)
    package_root = Path(__file__).resolve().parents[1]
    for directory in (Path(sys.executable).parent, package_root / ".scanner-venv" / "bin", package_root / ".venv" / "bin"):
        candidate = directory / executable
        if candidate.exists():
            return candidate
    repo_candidate = repo / ".venv" / "bin" / executable
    if repo_candidate.exists():
        return repo_candidate
    return None


def _path_inside_repo_or_run(path: Path, repo: Path, run_id: str | None) -> bool:
    resolved = path.expanduser().resolve(strict=False)
    boundaries = [repo.resolve(strict=False)]
    if run_id:
        boundaries.append((repo / ".sdlc" / "runs" / run_id).resolve(strict=False))
    for boundary in boundaries:
        try:
            resolved.relative_to(boundary)
            return True
        except ValueError:
            continue
    return False
