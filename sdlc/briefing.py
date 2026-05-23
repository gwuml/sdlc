"""Developer-autopilot intake, standards mapping, and prework reports."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from .classifier import classify_feature
from .ledger import Ledger
from .models import RunPlan
from .pipeline import DEFAULT_GATES
from .util import now_iso, redact_secrets, sha256_text


FINANCE_TERMS = {"trading", "trade", "portfolio", "alpha", "broker", "market", "exchange", "order", "risk", "backtest"}
AI_TERMS = {"ai", "llm", "model", "agent", "prompt", "rag", "embedding", "classifier"}
AUTH_TERMS = {"auth", "login", "sso", "oauth", "rbac", "permission", "tenant"}


def build_intake_brief(repo: Path, request: str, run_id: str, memory_context: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    classification = classify_feature(request, repo)
    lower = request.lower()
    domains = _domains(lower)
    ambiguity = _ambiguity_level(lower, classification.risk_level, domains)
    questions = _questions(lower, classification.risk_level, domains)
    assumptions = _assumptions(lower, classification.risk_level, domains)
    requirements = _requirements(lower, classification.risk_level, domains)
    forbidden_claims = [
        "production-ready",
        "secure",
        "compliant",
        "profitable",
        "world class",
        "fully autonomous",
    ]
    return {
        "schema_version": 1,
        "run_id": run_id,
        "created_at": now_iso(),
        "request": redact_secrets(request),
        "request_sha256": sha256_text(request),
        "intent": _intent(lower),
        "domains": domains,
        "risk_level": classification.risk_level,
        "classification": classification.to_dict(),
        "ambiguity_level": ambiguity,
        "question_budget": _question_budget(classification.risk_level),
        "blocking_questions": questions,
        "assumptions": assumptions,
        "requirements": requirements,
        "acceptance_criteria": _acceptance_criteria(classification.risk_level, domains),
        "non_goals": _non_goals(domains),
        "forbidden_claims": forbidden_claims,
        "human_approval_required": classification.risk_level in {"HIGH", "EXTREME"},
        "memory_context_used": bool(memory_context),
        "memory_context": memory_context or [],
    }


def build_standards_mapping(brief: dict[str, Any], *, network_allowed: bool = False) -> dict[str, Any]:
    domains = set(brief.get("domains", []))
    risk = str(brief.get("risk_level", "LOW"))
    standards = [
        _standard("NIST SSDF SP 800-218", "Secure software development practice baseline", "https://csrc.nist.gov/pubs/sp/800/218/final", ["secure development", "verification", "vulnerability response"]),
        _standard("OWASP SAMM", "Software assurance maturity structure", "https://owasp.org/www-project-samm/", ["governance", "design", "implementation", "verification", "operations"]),
        _standard("SLSA", "Supply-chain provenance and artifact integrity", "https://slsa.dev/spec/", ["provenance", "build integrity", "attestations"]),
        _standard("OpenSSF Scorecard", "Open-source project security posture signals", "https://openssf.org/scorecard/", ["branch protection", "dependency hygiene", "CI security"]),
    ]
    if risk in {"MEDIUM", "HIGH", "EXTREME"} or "web" in domains or "auth" in domains:
        standards.append(_standard("OWASP ASVS", "Application security verification requirements", "https://owasp.org/www-project-application-security-verification-standard/", ["authentication", "authorization", "session management", "input validation"]))
    if "ai" in domains:
        standards.extend([
            _standard("OWASP Top 10 for LLM Applications", "LLM application threat focus", "https://owasp.org/www-project-top-10-for-large-language-model-applications/", ["prompt injection", "data leakage", "agent/tool misuse"]),
            _standard("NIST AI RMF", "AI risk governance", "https://www.nist.gov/itl/ai-risk-management-framework", ["govern", "map", "measure", "manage"]),
            _standard("NIST AI 600-1 Generative AI Profile", "Generative AI risk profile", "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf", ["genAI risk", "content provenance", "misuse"]),
        ])
    if "finance" in domains:
        standards.append({
            "name": "Financial-system internal control baseline",
            "purpose": "Separate simulation from live execution and require auditability, risk limits, and human authorization",
            "source_url": "offline-domain-baseline",
            "controls": ["simulation/live separation", "broker credential isolation", "kill switches", "risk limits", "audit logs"],
        })
    return {
        "schema_version": 1,
        "created_at": now_iso(),
        "network_refreshed": bool(network_allowed),
        "currency_note": "Offline baseline mapping; not proof of latest-current standard text." if not network_allowed else "Network refresh requested; implementation must cite official retrieved source versions.",
        "standards": standards,
        "acceptance_criteria": _standards_acceptance(standards),
    }


def write_prework_artifacts(run_dir: Path, run_id: str, brief: dict[str, Any], standards: dict[str, Any]) -> dict[str, str]:
    ledger = Ledger(run_dir, run_id)
    artifacts: dict[str, str] = {}
    artifacts["intake_json"] = ledger.artifact("artifacts/prework/intake_brief.json", json.dumps(brief, indent=2, sort_keys=True) + "\n", event="intake.brief_created", redact=True)
    artifacts["intake_md"] = ledger.artifact("artifacts/prework/intake_brief.md", render_intake_markdown(brief), event="intake.brief_markdown_written")
    artifacts["standards_json"] = ledger.artifact("artifacts/prework/standards_mapping.json", json.dumps(standards, indent=2, sort_keys=True) + "\n", event="standards.mapping_created", redact=True)
    artifacts["standards_md"] = ledger.artifact("artifacts/prework/standards_mapping.md", render_standards_markdown(standards), event="standards.mapping_markdown_written")
    expectation = build_expectations_payload(brief, standards)
    artifacts["expectations_json"] = ledger.artifact("artifacts/prework/expectations.json", json.dumps(expectation, indent=2, sort_keys=True) + "\n", event="prework.expectations_created", redact=True)
    artifacts["expectations_md"] = ledger.artifact("artifacts/prework/expectations.md", render_expectations_markdown(expectation), event="prework.expectations_markdown_written")
    artifacts["expectations_html"] = ledger.artifact("artifacts/prework/expectations.html", render_expectations_html(expectation), event="prework.expectations_html_written")
    return artifacts


def build_expectations_payload(brief: dict[str, Any], standards: dict[str, Any]) -> dict[str, Any]:
    risk = str(brief.get("risk_level", "LOW"))
    phases = [
        {"phase": "intake", "time_band": "minutes", "exit_criteria": "brief, assumptions, and blocking questions recorded"},
        {"phase": "planning", "time_band": "minutes to hours", "exit_criteria": "25-gate plan and agent schedule created"},
        {"phase": "implementation", "time_band": "risk-dependent", "exit_criteria": "constrained diff with tests"},
        {"phase": "red-team", "time_band": "risk-dependent", "exit_criteria": "findings fixed or explicitly accepted by policy"},
        {"phase": "attestation", "time_band": "minutes", "exit_criteria": "manifest/sign/verify evidence captured"},
    ]
    return {
        "schema_version": 1,
        "run_id": brief["run_id"],
        "request": brief["request"],
        "risk_level": risk,
        "release_ready": False,
        "release_readiness_note": "Not release-ready until release validation and final report gates prove it.",
        "assumptions": brief["assumptions"],
        "blocking_questions": brief["blocking_questions"],
        "expected_gates": [gate.id for gate in DEFAULT_GATES],
        "expected_artifacts": [
            "artifacts/prework/intake_brief.json",
            "artifacts/prework/standards_mapping.json",
            "artifacts/prework/expectations.html",
            "worker-results/",
            "events.jsonl",
            "final-report.md",
        ],
        "success_criteria": brief["acceptance_criteria"] + standards.get("acceptance_criteria", []),
        "forbidden_claims": brief["forbidden_claims"],
        "anticipated_redteam_attacks": _redteam_attack_areas(brief),
        "phases": phases,
    }


def render_intake_markdown(brief: dict[str, Any]) -> str:
    return "\n".join([
        f"# Intake Brief - {brief['run_id']}",
        "",
        f"Request: `{brief['request']}`",
        f"Risk: `{brief['risk_level']}`",
        f"Intent: `{brief['intent']}`",
        f"Domains: {', '.join(brief['domains']) or '<none>'}",
        f"Ambiguity: `{brief['ambiguity_level']}`",
        "",
        "## Blocking Questions",
        _md_list(brief["blocking_questions"]),
        "",
        "## Assumptions",
        _md_list(brief["assumptions"]),
        "",
        "## Requirements",
        _md_list(brief["requirements"]),
        "",
        "## Acceptance Criteria",
        _md_list(brief["acceptance_criteria"]),
        "",
    ])


def render_standards_markdown(mapping: dict[str, Any]) -> str:
    lines = ["# Standards Mapping", "", mapping["currency_note"], ""]
    for item in mapping["standards"]:
        lines.append(f"## {item['name']}")
        lines.append(item["purpose"])
        lines.append(f"Source: {item['source_url']}")
        lines.append("")
        lines.append(_md_list(item["controls"]))
        lines.append("")
    return "\n".join(lines)


def render_expectations_markdown(payload: dict[str, Any]) -> str:
    lines = [
        f"# Prework Expectations - {payload['run_id']}",
        "",
        f"Risk: `{payload['risk_level']}`",
        f"Release-ready: `{payload['release_ready']}`",
        payload["release_readiness_note"],
        "",
        "## Success Criteria",
        _md_list(payload["success_criteria"]),
        "",
        "## Anticipated Red-Team Attacks",
        _md_list(payload["anticipated_redteam_attacks"]),
        "",
        "## Phases",
    ]
    for phase in payload["phases"]:
        lines.append(f"- {phase['phase']}: {phase['time_band']} - {phase['exit_criteria']}")
    lines.append("")
    return "\n".join(lines)


def render_expectations_html(payload: dict[str, Any]) -> str:
    criteria = "".join(f"<li>{html.escape(item)}</li>" for item in payload["success_criteria"])
    attacks = "".join(f"<li>{html.escape(item)}</li>" for item in payload["anticipated_redteam_attacks"])
    phases = "".join(
        f"<tr><td>{html.escape(item['phase'])}</td><td>{html.escape(item['time_band'])}</td><td>{html.escape(item['exit_criteria'])}</td></tr>"
        for item in payload["phases"]
    )
    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>SDLC Prework Expectations - {html.escape(payload['run_id'])}</title>
  <style>
    body {{ margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif; background: #eef3f7; color: #182026; }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 32px 18px 48px; }}
    section, .metric {{ background: #fff; border: 1px solid #cdd6df; border-radius: 8px; padding: 16px; }}
    h1 {{ font-size: clamp(28px, 5vw, 44px); line-height: 1.05; margin: 0 0 8px; }}
    h2 {{ margin: 0 0 12px; font-size: 19px; }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }}
    .metrics {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin: 18px 0; }}
    .metric span {{ display: block; color: #55616d; font-size: 12px; font-weight: 700; text-transform: uppercase; }}
    .metric strong {{ display: block; margin-top: 8px; font-size: 22px; }}
    .red {{ color: #cf222e; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td, th {{ padding: 9px; border-bottom: 1px solid #cdd6df; text-align: left; vertical-align: top; }}
    @media (max-width: 820px) {{ .grid, .metrics {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
<main>
  <h1>Prework Expectations</h1>
  <p>{html.escape(payload['request'])}</p>
  <div class=\"metrics\">
    <div class=\"metric\"><span>Run</span><strong>{html.escape(payload['run_id'])}</strong></div>
    <div class=\"metric\"><span>Risk</span><strong>{html.escape(payload['risk_level'])}</strong></div>
    <div class=\"metric\"><span>Release Ready</span><strong class=\"red\">NO</strong></div>
  </div>
  <div class=\"grid\">
    <section><h2>Success Criteria</h2><ul>{criteria}</ul></section>
    <section><h2>Red-Team Attack Areas</h2><ul>{attacks}</ul></section>
    <section style=\"grid-column: 1 / -1\"><h2>Work Phases</h2><table><thead><tr><th>Phase</th><th>Time Band</th><th>Exit Criteria</th></tr></thead><tbody>{phases}</tbody></table></section>
  </div>
</main>
</body>
</html>
"""


def _domains(lower: str) -> list[str]:
    domains: list[str] = []
    if any(term in lower for term in FINANCE_TERMS):
        domains.append("finance")
    if any(term in lower for term in AI_TERMS):
        domains.append("ai")
    if any(term in lower for term in AUTH_TERMS):
        domains.append("auth")
    if any(term in lower for term in ["ui", "dashboard", "frontend", "page", "screen"]):
        domains.append("web")
    if any(term in lower for term in ["deploy", "infra", "kubernetes", "terraform", "aws", "production"]):
        domains.append("infra")
    if not domains and any(term in lower for term in ["fibonacci", "hello world", "script"]):
        domains.append("toy")
    return domains


def _intent(lower: str) -> str:
    if any(term in lower for term in ["fix", "bug", "repair"]):
        return "fix"
    if any(term in lower for term in ["review", "audit", "red-team", "red team"]):
        return "review"
    if any(term in lower for term in ["build", "create", "add", "implement", "need"]):
        return "build"
    return "clarify"


def _ambiguity_level(lower: str, risk: str, domains: list[str]) -> str:
    if "finance" in domains or risk in {"HIGH", "EXTREME"}:
        return "HIGH"
    if len(lower.split()) < 6:
        return "MEDIUM"
    return "LOW"


def _question_budget(risk: str) -> dict[str, int]:
    if risk == "LOW":
        return {"min": 0, "max": 2}
    if risk == "MEDIUM":
        return {"min": 1, "max": 4}
    return {"min": 3, "max": 8}


def _questions(lower: str, risk: str, domains: list[str]) -> list[str]:
    if "toy" in domains or "fibonacci" in lower:
        return []
    questions = []
    if "finance" in domains:
        questions.extend([
            "Is this simulation/backtesting only, or will it place live orders?",
            "Which markets, instruments, data sources, and broker/exchange integrations are in scope?",
            "What risk limits, kill switches, and human approvals are mandatory before live execution?",
            "Which regulatory/compliance constraints apply to the intended users and jurisdictions?",
        ])
    if "auth" in domains:
        questions.append("Which identity provider, roles, tenants, and audit requirements are in scope?")
    if risk in {"HIGH", "EXTREME"} and not questions:
        questions.append("What production, data, security, and rollback boundaries are in scope?")
    return questions


def _assumptions(lower: str, risk: str, domains: list[str]) -> list[str]:
    if "toy" in domains or "fibonacci" in lower:
        return ["Implement the smallest testable solution in the current repository language unless the user specifies otherwise."]
    assumptions = ["No production deployment is allowed by default.", "No secrets are required or stored in run artifacts."]
    if "finance" in domains:
        assumptions.extend(["Default to simulation/backtesting, not live trading.", "No profitability claim is allowed without audited evidence and explicit scope."])
    if risk in {"HIGH", "EXTREME"}:
        assumptions.append("Human approval is required for residual risk, production rollout, and high-impact scope changes.")
    return assumptions


def _requirements(lower: str, risk: str, domains: list[str]) -> list[str]:
    if "fibonacci" in lower:
        return ["Provide a deterministic Fibonacci implementation.", "Add focused tests for base cases and representative sequence values."]
    requirements = ["Create a scoped implementation plan.", "Capture evidence for every gate touched.", "Run tests and validation before final claims."]
    if "finance" in domains:
        requirements.extend(["Separate research/backtest/live execution modes.", "Add audit logs for decisions and orders.", "Require risk limits and kill-switch design before live execution."])
    return requirements


def _acceptance_criteria(risk: str, domains: list[str]) -> list[str]:
    criteria = ["Required tests pass.", "Repository validation passes.", "Final report includes residual risks and release blockers."]
    if risk in {"HIGH", "EXTREME"}:
        criteria.append("Independent red-team evidence is positive or residual risks are explicitly accepted by policy.")
    if "finance" in domains:
        criteria.append("The system makes no profitability or investment-advice claim.")
    return criteria


def _non_goals(domains: list[str]) -> list[str]:
    goals = ["No direct main push.", "No production deployment by default.", "No unsupported safety/security/compliance claims."]
    if "finance" in domains:
        goals.append("No live trading until explicitly approved with risk and rollback evidence.")
    return goals


def _standard(name: str, purpose: str, source_url: str, controls: list[str]) -> dict[str, Any]:
    return {"name": name, "purpose": purpose, "source_url": source_url, "controls": controls}


def _standards_acceptance(standards: list[dict[str, Any]]) -> list[str]:
    return [f"Map implementation evidence to {item['name']} controls: {', '.join(item['controls'][:3])}" for item in standards]


def _redteam_attack_areas(brief: dict[str, Any]) -> list[str]:
    attacks = ["unsupported release-readiness claims", "missing evidence", "stale reports", "worker output without context binding"]
    if "finance" in brief.get("domains", []):
        attacks.extend(["profitability overclaim", "live trading without approval", "missing risk limits"])
    if brief.get("memory_context_used"):
        attacks.append("memory leakage or unexplained personalization")
    return attacks


def _md_list(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items) if items else "- <none>"
