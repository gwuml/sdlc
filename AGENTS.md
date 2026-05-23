# AGENTS.md — Secure SDLC Control Plane

This repository is an AI-native Secure SDLC orchestrator. Codex, Claude, and other AI agents must follow this file when working in the repo.

## Mission

Build a terminal-native Secure SDLC control plane that turns a feature request into a gated, evidence-driven, adversarial software delivery run.

The orchestrator is the authority. Models are workers.

## Non-goals

Do not turn this into:

- a generic chatbot
- a prompt-only generator
- a direct-main-push automation tool
- a production deploy bot without explicit human approval
- a system that claims safety, security, profitability, compliance, or production readiness without evidence

## Hard safety rules

1. Do not remove or weaken the red-team loop.
2. Do not let implementers close their own findings.
3. Do not make direct `origin/main` push the default.
4. Do not make production deploy/restart the default.
5. Do not hide failed tests, missing scanners, or unavailable worker tools.
6. Do not claim world-class maturity unless the implementation and evidence support the exact claim.
7. Do not store secrets in repo files, prompts, logs, or run artifacts.
8. Do not add network calls unless the policy and user explicitly allow them.
9. Do not make policy bypasses silent; every bypass requires an event ledger entry.
10. Do not degrade terminal usability for non-interactive CI usage.

## Current architecture

```text
sdlc/
  cli.py          command interface
  pipeline.py     canonical 25-gate pipeline
  classifier.py   feature/risk/specialist classifier
  models.py       run, gate, and finding dataclasses
  engine.py       gate operations and deterministic checks
  ledger.py       JSONL event and artifact ledger
  policies.py     default policy profiles
  prompts.py      execution/red-team/UI prompt rendering
  adapters.py     Codex and Claude worker adapter shells
  reporting.py    final report generation
```

## Product pipeline

All meaningful changes to this repo should themselves follow the same 25-gate pipeline:

1. Intake, scope, and ambiguity reduction
2. Stakeholders, RACI, and approval authority
3. Mission, non-goals, and claim discipline
4. Repo, production, branch, and environment context
5. Risk classification and blast-radius controls
6. Data, privacy, secrets, and exfiltration policy
7. Baseline/freeze gate and reproducibility snapshot
8. Supply-chain, dependency, SBOM, and license review
9. Agent plan, dependency graph, write ownership, and permissions
10. Architecture, contracts, invariants, and failure modes
11. UI architecture, UX states, accessibility, and dark-pattern review if UI is touched
12. Threat model, abuse cases, misuse cases, and adversarial assumptions
13. Implementation plan and minimal change-set contract
14. Implementation with constrained write ownership
15. Deterministic quality gate: format, lint, typecheck, static checks
16. QA: focused tests, fixtures, integration, regression, and smoke tests
17. Security scans: SAST, dependency, secrets, IaC, and policy checks
18. Observability, telemetry, runbooks, and incident response
19. Implementer self-review and claim check
20. Independent brutal red-team and cross-model audit
21. CRITICAL/HIGH automatic fix loop and second validation
22. Evidence traceability, provenance, and attestations
23. Commit, branch, PR, and CI gate
24. Deployment, rollout, restart, monitoring, and rollback gate
25. Final report, residual risks, next audit, and maintenance plan

## Agent roles

Default roles:

- Agent 1: PM/coordinator, scope control, dependency graph, GO/NO-GO calls
- Agent 2: architecture/contracts/invariants
- Agent 3: implementation owner for constrained code changes
- Agent 4: evidence/data/replay/reporting owner
- Agent 5: QA/tests/fixtures/integration validation owner
- Agent 6: red-team/deploy/rollback/post-deploy verification owner

Conditional roles:

- Agent 7: UI architect / UX systems owner
- Agent 8: cybersecurity engineer
- Agent 9: SRE / sysadmin / infrastructure owner
- Agent 10: IT / enterprise integration owner
- Agent 11: compliance / audit owner
- Agent 12: domain specialist

## Write ownership

Implementation agents may edit:

- `sdlc/**`
- `tests/**`
- `docs/**`
- `.sdlc/templates/**`
- `.sdlc/schemas/**`
- `.sdlc/policies/**`

Implementation agents must not edit without explicit approval:

- `.env*`
- secrets or credentials
- production deployment configs
- generated run evidence in `.sdlc/runs/**` except for the active run
- git metadata

Red-team agents are read-only and must not edit code.

## Required commands

Before claiming a change is complete, run:

```bash
python -m unittest discover -s tests
python -m sdlc validate
```

For a self-run feature plan, use:

```bash
python -m sdlc plan "<feature>" --risk auto --ui auto --security auto --infra auto
python -m sdlc run <run-id> --redteam
python -m sdlc report <run-id> --print
```

## Red-team standard

Red-team reviews must be brutal and evidence-driven. Assume:

- the user may go all in
- attackers exploit ambiguity
- UX confusion causes harm
- tests can be misleading
- missing evidence is a defect
- overconfidence is a defect

Findings must use CRITICAL/HIGH/MEDIUM/LOW severity.

Allowed verdicts only:

- `GO`
- `NO_GO`
- `GO_WITH_ACCEPTED_RESIDUAL_RISKS`

## Commit discipline

Use:

```text
verb: subject
```

Examples:

```text
feat: add finding closure workflow
fix: enforce skipped deploy gate validation
refactor: isolate worker adapter policy mapping
test: cover high-risk classifier activation
```

Default workflow is feature branch + PR. Do not push directly to main by default.
