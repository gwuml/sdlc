"""Feature classifier used to activate pipeline gates and specialist agents."""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from .pipeline import HIGH_STAKES_TERMS, UI_TERMS, INFRA_TERMS, SECURITY_TERMS, DEFAULT_AGENTS, CONDITIONAL_AGENTS


@dataclass(frozen=True)
class FeatureClassification:
    risk_level: str
    has_ui: bool
    has_security: bool
    has_infra: bool
    has_data_or_evidence: bool
    high_stakes: bool
    reasons: list[str]
    activated_agents: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9][a-z0-9_.-]*", text.lower()))


def _contains_any(text: str, terms: set[str]) -> bool:
    lower = text.lower()
    token_set = _tokens(lower)
    return any(term in token_set or term in lower for term in terms)


def _repo_has_ui(repo: Path) -> bool:
    patterns = ["**/*.tsx", "**/*.jsx", "**/*.vue", "**/*.svelte", "**/*.css", "**/*.scss"]
    for pattern in patterns:
        try:
            if next(repo.glob(pattern), None) is not None:
                return True
        except OSError:
            return False
    return False


def _repo_has_infra(repo: Path) -> bool:
    patterns = ["**/*.tf", "**/Dockerfile", "**/docker-compose*.yml", "**/k8s/**", "**/helm/**"]
    for pattern in patterns:
        try:
            if next(repo.glob(pattern), None) is not None:
                return True
        except OSError:
            return False
    return False


def classify_feature(
    feature: str,
    repo: Path,
    requested_risk: str = "auto",
    ui: str = "auto",
    security: str = "auto",
    infra: str = "auto",
) -> FeatureClassification:
    """Classify a feature request with deliberately conservative defaults."""

    reasons: list[str] = []
    repo = repo.resolve()
    toy_request = any(term in feature.lower() for term in ["fibonacci", "hello world", "toy example", "sample script"])
    has_ui = _contains_any(feature, UI_TERMS) or (ui == "auto" and not toy_request and _repo_has_ui(repo))
    if ui == "yes":
        has_ui = True
    if ui == "no":
        has_ui = False

    has_security = _contains_any(feature, SECURITY_TERMS)
    if security == "yes":
        has_security = True
    if security == "no":
        has_security = False

    has_infra = _contains_any(feature, INFRA_TERMS) or (infra == "auto" and not toy_request and _repo_has_infra(repo))
    if infra == "yes":
        has_infra = True
    if infra == "no":
        has_infra = False

    has_data_or_evidence = any(term in feature.lower() for term in ["data", "evidence", "dataset", "report", "replay", "backtest", "analytics"]) and not toy_request
    finance_stakes = any(term in feature.lower() for term in ["trading", "trade", "portfolio", "alpha", "broker", "market", "exchange"])
    high_stakes = _contains_any(feature, HIGH_STAKES_TERMS) or has_security or has_infra

    if has_ui:
        reasons.append("UI/UX or frontend surface detected")
    if has_security:
        reasons.append("Security-sensitive feature or authorization surface detected")
    if has_infra:
        reasons.append("Infrastructure/deployment/operations surface detected")
    if has_data_or_evidence:
        reasons.append("Data/evidence/reporting surface detected")
    if high_stakes:
        reasons.append("High-stakes blast radius detected; claim discipline and brutal red-team are mandatory")

    if requested_risk != "auto":
        risk_level = requested_risk.upper()
        reasons.append(f"Risk explicitly set by user: {risk_level}")
    elif high_stakes and (has_security or has_infra or finance_stakes):
        risk_level = "EXTREME"
    elif high_stakes:
        risk_level = "HIGH"
    elif has_ui or has_data_or_evidence:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    activated_agents = list(DEFAULT_AGENTS)
    conditional_by_id = {agent["id"]: agent for agent in CONDITIONAL_AGENTS}
    if has_ui:
        activated_agents.append(conditional_by_id["agent_7_ui_architect"])
    if has_security or high_stakes:
        activated_agents.append(conditional_by_id["agent_8_cybersecurity_engineer"])
    if has_infra:
        activated_agents.append(conditional_by_id["agent_9_sre_sysadmin"])
    if any(term in feature.lower() for term in ["sso", "okta", "ldap", "device", "enterprise", "it"]):
        activated_agents.append(conditional_by_id["agent_10_it_enterprise_integration"])
    if any(term in feature.lower() for term in ["compliance", "audit", "soc2", "sox", "hipaa", "pci", "gdpr"]):
        activated_agents.append(conditional_by_id["agent_11_compliance_audit"])
    if any(term in feature.lower() for term in ["trading", "portfolio", "healthcare", "medical", "payment", "bank"]):
        activated_agents.append(conditional_by_id["agent_12_domain_specialist"])

    # Deduplicate while preserving order.
    seen = set()
    deduped = []
    for agent in activated_agents:
        if agent["id"] not in seen:
            deduped.append(agent)
            seen.add(agent["id"])

    if not reasons:
        reasons.append("No high-risk terms detected; low-risk default applies until gates prove otherwise")

    return FeatureClassification(
        risk_level=risk_level,
        has_ui=has_ui,
        has_security=has_security,
        has_infra=has_infra,
        has_data_or_evidence=has_data_or_evidence,
        high_stakes=high_stakes,
        reasons=reasons,
        activated_agents=deduped,
    )
