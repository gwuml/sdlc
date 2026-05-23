# Product Spec — SDLC Control Plane

## Product vision

Build a terminal-native Secure SDLC orchestration layer for AI-assisted software delivery, with maturity claims limited to what the current gates and evidence prove.

The product should make AI engineering safer, faster, and more auditable by converting every feature request into a gated, evidence-driven workflow with role-specific agents, deterministic checks, adversarial review, and strict claim discipline.

## Primary user

A founder, staff engineer, security engineer, or platform team that wants to build high-stakes software with AI workers while preserving control, evidence, and accountability.

## Core jobs to be done

1. Turn vague feature requests into rigorous execution plans.
2. Activate the right specialist agents for UI, security, infra, IT, compliance, and domain risk.
3. Generate prompts that Codex/Claude can execute directly.
4. Enforce gates with evidence instead of trusting model prose.
5. Capture every meaningful action in a run ledger.
6. Make red-team review brutal, repeated, and authoritative.
7. Block direct main push and production deploy unless explicitly authorized.
8. Produce final reports with residual risk and evidence traceability.

## Product principles

- Stateful gates, not vibes.
- Evidence is currency.
- Red-team is an authority, not a suggestion box.
- Models are replaceable workers.
- Terminal-first, CI-compatible.
- Human approval for irreversible operations.
- Claim discipline for high-stakes systems.

## MVP capabilities already implemented

- CLI commands: `init`, `plan`, `status`, `run`, `worker`, `redteam`, `report`, `validate`
- 25-gate pipeline in code
- risk classifier
- specialist agent activation
- prompt bundle generation
- JSON policies and schemas
- event ledger
- dry-run worker adapters for Codex and Claude
- deterministic red-team finding generation
- finding lifecycle commands
- manual gate completion command
- simple terminal dashboard command
- final report generation
- unit tests

## Next capabilities

### 1. Rich full-screen TUI

A terminal command center showing:

- gates
- agents
- findings
- diffs
- evidence
- worker logs
- approval queue
- permissions matrix

### 2. Finding lifecycle enhancements

Basic finding lifecycle commands are implemented. Next enhancements:

```bash
sdlc finding send-to-worker <run-id> HIGH-003 --worker codex
sdlc finding reopen <run-id> HIGH-003 --reason "regression found"
sdlc finding matrix <run-id>
```

Hard rules remain:

- Implementer cannot close own findings.
- CRITICAL/HIGH cannot be accepted without explicit human override flag.
- Closure requires evidence.
- Every lifecycle change writes a ledger event.

### 3. Real worker orchestration

- feed prompt through STDIN correctly for Codex
- capture streaming JSON events
- map worker outputs to ledger events
- enforce adapter permissions by gate
- support cancellation and quarantine

### 4. Git/PR integration

- create or switch to a run-scoped feature branch
- commit only after blocking findings and prerequisite release gates are clear
- prepare PRs as dry-runs by default; remote PR creation remains explicitly
  network-gated
- capture ledger-backed Git provenance for branch, HEAD, commit, PR plan or PR
  creation, and local CI/release-gate status
- require CI/release-gate and red-team GO before release-satisfied status

### 5. Scanner integrations

- secret scan
- dependency scan
- SAST
- IaC scan
- SBOM generation
- license review

### 6. Artifact provenance

- artifact hashes already exist in ledger
- add signed attestations
- add run bundle export
- add immutable evidence manifest
- bind release claims to Git branch, commit, PR/CI provenance, ledger events,
  and artifact hashes instead of accepting narrative evidence alone

### 7. Policy-as-code

- richer policy profiles
- path-specific ownership
- protected operation enforcement
- network allowlists
- model/worker allowlists
- budget limits

### 8. Longitudinal memory

- compare current run to prior runs
- identify recurring findings
- track flaky tests
- track model drift
- schedule re-audits

## Success metrics

- number of blocked unsafe operations
- percent of features with complete evidence traceability
- red-team finding closure rate
- mean fix-loop rounds per feature
- CI pass rate after red-team GO
- reduction in escaped defects
- reduction in unsupported final claims

## Risks

- Product becomes too bureaucratic for low-risk work.
- Agents learn to satisfy templates without real quality.
- Users over-trust the platform's verdict.
- Worker CLI changes break adapters.
- Cost and latency grow with too many agents.

## Mitigations

- adaptive gates based on risk
- deterministic tests/scanners before model judgment
- strict claim discipline
- adapter compatibility tests
- budget controls
- run evidence review
