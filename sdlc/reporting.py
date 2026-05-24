"""Final report generation."""

from __future__ import annotations

from pathlib import Path

from .engine import RunStore, final_verdict
from .ledger import Ledger
from .models import open_findings
from .util import read_json


def build_report(repo: Path, run_id: str, *, verdict_override: str | None = None, readiness_errors: list[str] | None = None) -> str:
    store = RunStore(repo)
    plan = store.load_plan(run_id)
    findings = store.load_findings(run_id)
    computed_verdict = final_verdict(findings, plan)
    verdict = verdict_override or computed_verdict
    readiness_errors = readiness_errors or []
    release_satisfied = not readiness_errors
    release_verdict = computed_verdict if release_satisfied else "NO_GO"
    authority_mode = "RELEASE_CANDIDATE_ADVISORY" if release_satisfied else "ADVISORY"

    gate_rows = "\n".join(
        f"| {gate.order:02d} | {_md_cell(gate.id)} | {_md_cell(gate.owner)} | {_md_cell(gate.state)} | {_md_cell(gate.verdict or '')} | {_md_cell(', '.join(gate.evidence))} |"
        for gate in plan.gates
    )
    finding_rows = "\n".join(
        f"| {_md_cell(finding.id)} | {_md_cell(finding.severity)} | {_md_cell(finding.status)} | {_md_cell(finding.title)} | {_md_cell(finding.impact)} |"
        for finding in findings
    ) or "| - | - | - | No findings recorded | - |"
    deploy_gate = next((gate for gate in plan.gates if gate.id == "deploy_rollout_postdeploy"), None)
    production_record = read_json(store.run_dir(run_id) / "artifacts" / "deploy" / "production.json", {})
    attestation_gate = next((gate for gate in plan.gates if gate.id == "evidence_traceability_attestations"), None)
    deploy_state = deploy_gate.state if deploy_gate else "UNKNOWN"
    deploy_verdict = deploy_gate.verdict if deploy_gate else "UNKNOWN"
    deploy_notes = deploy_gate.notes if deploy_gate else "Deployment gate missing"
    accepted_risks = production_record.get("accepted_residual_risks", [])

    return f"""# Secure SDLC Final Report

Run: `{plan.run_id}`
Feature: {plan.feature}
Risk: {plan.risk_level}
Verdict: **{verdict}**

## Claim discipline
This report only claims that recorded gates and evidence exist. It does **not** claim profitability, safety, security, compliance, or production readiness unless those claims are explicitly backed by gate evidence.

## Authority Mode
- Mode: {authority_mode}
- Production authority: DISABLED
- Use: advisory PR and operator evidence only.
- Important: this report is not production deployment clearance; deployment still requires explicit human authorization, rollout evidence, monitoring evidence, and rollback evidence.

## Release Readiness
- Local final verdict: {computed_verdict}
- Release verdict: {release_verdict}
- Release satisfied: {str(release_satisfied).lower()}
- Readiness blockers: {len(readiness_errors)}
- Open findings: {len(open_findings(findings))}
- Important: local gate `GO` does not imply release-satisfied.
{_readiness_block(report_errors=readiness_errors)}

## Gate status

| # | Gate | Owner | State | Verdict | Evidence |
|---:|---|---|---|---|---|
{gate_rows}

## Findings

| ID | Severity | Status | Finding | Impact |
|---|---|---|---|---|
{finding_rows}

## Production rollout
- Gate state/verdict: {deploy_state}/{deploy_verdict}
- Notes: {deploy_notes or '<none>'}
- Accepted residual risks: {', '.join(accepted_risks) if accepted_risks else '<none>'}

## Attestations
- Gate state/verdict: {attestation_gate.state if attestation_gate else 'UNKNOWN'}/{attestation_gate.verdict if attestation_gate else 'UNKNOWN'}
- Evidence: {', '.join(attestation_gate.evidence) if attestation_gate and attestation_gate.evidence else '<none>'}

## Residual risks
- Review all OPEN MEDIUM/LOW findings.
- Re-run this pipeline after dependency, model, infrastructure, or threat-model changes.
- Deployment remains locked unless the deployment gate has explicit authorization and rollback evidence.

## Next audit triggers
- New authentication/authorization behavior
- New dependency or lockfile change
- New deployment target or infrastructure change
- Any production incident or failed smoke test
- Any model/worker change used by the orchestration platform
"""


def generate_report(repo: Path, run_id: str, *, verdict_override: str | None = None, readiness_errors: list[str] | None = None) -> str:
    store = RunStore(repo)
    report = build_report(repo, run_id, verdict_override=verdict_override, readiness_errors=readiness_errors)
    event_verdict = verdict_override or final_verdict(store.load_findings(run_id), store.load_plan(run_id))
    Ledger(store.run_dir(run_id), run_id).artifact(
        "final-report.md",
        report,
        event="report.generated",
        verdict=event_verdict,
    )
    return report


def _readiness_block(*, report_errors: list[str]) -> str:
    if not report_errors:
        return ""
    lines = "\n## Release Readiness Blockers\n\n"
    lines += "\n".join(f"- {error}" for error in report_errors[:25])
    return lines + "\n"


def _md_cell(value: object) -> str:
    text = str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace("|", "\\|")
    text = text.replace("\r", " ")
    text = text.replace("\n", "<br>")
    return text
