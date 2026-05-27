"""Policy profile loading and defaults."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .util import read_json, write_json


DEFAULT_POLICY: dict[str, Any] = {
    "name": "default",
    "direct_main_push_allowed": False,
    "network_allowed": False,
    "production_rollout_allowed": False,
    "deploy_default": "LOCKED",
    "claim_discipline": "STRICT",
    "actor_proof_required_for_finding_closure": True,
    "redteam": {
        "required": True,
        "min_rounds_high_stakes": 3,
        "cross_model_required_for_high_or_extreme": True,
        "cross_model_independence": "distinct_openai_model_identity",
        "allowed_providers": ["openai"],
        "default_workers": ["openai-codex-primary", "openai-codex-adversary"],
        "critical_high_auto_fix_required": True,
        "implementer_cannot_close_findings": True,
        "audit_isolation": {
            "runtime": "macos_sandbox_exec",
            "container_engine": "auto",
            "container_image": "",
            "network_mode": "host",
            "auth": {"mode": "host_oauth"},
            "auth_env": [],
        },
    },
    "scanner_thresholds": {
        "block_severities": ["CRITICAL", "HIGH"],
        "block_medium_for_high_risk": True,
        "block_medium": False,
        "block_low": False,
        "dependency_audit_required": True,
    },
    "protected_operations": [
        "git push origin main",
        "production deploy",
        "production restart",
        "database migration",
        "secret creation/deletion",
        "IAM/RBAC change",
        "destructive filesystem command",
        "external network access",
    ],
    "workers": {
        "implementation": "codex",
        "architecture": "claude",
        "redteam": "openai-codex-primary",
        "qa": "codex",
    },
    "worker_families": {
        "openai-codex-primary": {
            "adapter": "codex",
            "provider": "openai",
            "model": "gpt-5.5",
            "model_env": "SDLC_OPENAI_REDTEAM_PRIMARY_MODEL",
            "read_only_security_review": True,
        },
        "openai-codex-adversary": {
            "adapter": "codex",
            "provider": "openai",
            "model": "gpt-5.4-mini",
            "model_env": "SDLC_OPENAI_REDTEAM_ADVERSARY_MODEL",
            "read_only_security_review": True,
        },
    },
    "agents": {
        "max_parallel": 12,
        "min_parallel_for_high_or_extreme": 6,
        "allowed_workers": ["codex", "openai-codex-primary", "openai-codex-adversary", "claude", "gemini", "kimi"],
        "role_worker_preferences": {},
    },
    "permissions": {
        "redteam": {"mode": "READ_ONLY", "deny": ["edit", "write", "git push", "deploy", "secrets access"]},
        "implementer": {
            "mode": "BUILD",
            "allow_paths": ["sdlc/**", "tests/**", "docs/**", ".sdlc/templates/**", ".sdlc/schemas/**", ".sdlc/policies/**"],
            "deny_paths": [".env*", "secrets/**", "infra/prod/**", ".sdlc/runs/**", ".sdlc/memory.sqlite"],
        },
    },
}

HIGH_RISK_POLICY: dict[str, Any] = {
    **DEFAULT_POLICY,
    "name": "high-risk",
    "redteam": {
        **DEFAULT_POLICY["redteam"],
        "min_rounds_high_stakes": 3,
        "cross_model_required_for_high_or_extreme": True,
    },
}

HOST_OAUTH_TOOLS_POLICY: dict[str, Any] = {
    **DEFAULT_POLICY,
    "name": "host-oauth-tools",
    "network_allowed": True,
    "permissions": {
        **DEFAULT_POLICY["permissions"],
        "implementer": {
            **DEFAULT_POLICY["permissions"]["implementer"],
            "allow_paths": [
                "docs/**",
                "tests/**",
                ".codex/prompts/**",
                ".sdlc/templates/**",
                ".sdlc/schemas/**",
                ".sdlc/policies/**",
            ],
            "deny_paths": [
                ".env*",
                "secrets/**",
                "infra/prod/**",
                ".sdlc/runs/**",
                ".sdlc/memory.sqlite",
            ],
        },
    },
    "redteam": {
        **DEFAULT_POLICY["redteam"],
        "audit_isolation": {
            **DEFAULT_POLICY["redteam"]["audit_isolation"],
            "runtime": "macos_sandbox_exec",
            "network_mode": "host",
            "auth": {"mode": "host_oauth"},
        },
    },
}


def ensure_policy_files(base: Path) -> None:
    policies = base / ".sdlc" / "policies"
    policies.mkdir(parents=True, exist_ok=True)
    write_json(policies / "default.json", DEFAULT_POLICY)
    write_json(policies / "high-risk.json", HIGH_RISK_POLICY)
    write_json(policies / "host-oauth-tools.json", HOST_OAUTH_TOOLS_POLICY)


def load_policy(repo: Path, profile: str = "default") -> dict[str, Any]:
    path = repo / ".sdlc" / "policies" / f"{profile}.json"
    if path.exists():
        return read_json(path, DEFAULT_POLICY)
    if profile == "host-oauth-tools":
        return HOST_OAUTH_TOOLS_POLICY
    return HIGH_RISK_POLICY if profile == "high-risk" else DEFAULT_POLICY
