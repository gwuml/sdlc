# SDLC Control Plane

A terminal-native, evidence-driven, adversarial Secure SDLC orchestrator for AI software delivery.

This starter product treats Codex and Claude as **workers**, not as the authority. The orchestrator owns gates, policies, permissions, evidence, red-team loops, and final claims.

For hands-on use before full production clearance, follow [docs/HANDS_ON_ADVISORY_USAGE.md](docs/HANDS_ON_ADVISORY_USAGE.md). The current workflow is advisory by default: it can organize runs, evidence, findings, reports, and next actions, but it does not grant production deployment authority.

## What this is

```text
feature request
  -> risk classifier
  -> 25-gate Secure SDLC plan
  -> role/agent ownership
  -> execution prompt bundle
  -> deterministic gate evidence
  -> worker adapters for Codex/Claude
  -> brutal red-team findings
  -> fix/re-audit loop
  -> final report
```

## What this is not

- Not a new LLM.
- Not a generic prompt generator.
- Not a tool that blindly lets agents mutate production.
- Not a direct-main-push machine.

## Install locally

Use an isolated environment. On macOS/Homebrew Python and many Linux distributions,
system Python is externally managed, so installing into a virtual environment is the
most reliable path.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Equivalent requirements-file install:

```bash
python -m pip install -r requirements.txt
```

Or run without installing:

```bash
python3 -m sdlc init
```

The package dependencies in `pyproject.toml` install the scanner/runtime tools used
by the control plane:

- `jsonschema` for gate-result schema validation
- `bandit` for Python SAST evidence
- `detect-secrets` for secret scanning evidence
- `pip-audit` for Python dependency vulnerability evidence
- `checkov` for IaC/policy scanning evidence

Verify the install:

```bash
python -m sdlc --help
python -m sdlc validate
python -m sdlc validate --run-id <run-id> --release
```

## Quick start

```bash
# 1. Initialize the repo
python -m sdlc init

# 2. Create a gated SDLC run
python -m sdlc plan "Build multi-tenant RBAC dashboard with audit logs" \
  --risk auto \
  --ui auto \
  --security auto \
  --infra auto

# 3. Inspect status
python -m sdlc status <run-id>

# 4. Advance deterministic dry gates and full advisory role artifacts
python -m sdlc run <run-id> --redteam

# 5. Capture security scanner evidence
python -m sdlc scan <run-id>

# 6. Dry-run a worker adapter command
python -m sdlc worker <run-id> codex --mode BUILD
python -m sdlc worker <run-id> claude --mode PLAN

# 7. Generate report
python -m sdlc report <run-id> --print

# 8. Prepare local Git workflow
python -m sdlc git branch <run-id>
python -m sdlc git commit <run-id> --message "feat: ..."
python -m sdlc git pr <run-id>
python -m sdlc git provenance <run-id>
python -m sdlc validate --run-id <run-id> --release
```

Every completed run must now record branch housekeeping. If policy and human
approval allow direct `main` integration, the run should merge or fast-forward
the approved work into `main`, push `origin/main`, and delete only the SDLC
branches/worktrees created for that run after recording their SHAs. If approval
is missing, the final report must preserve the feature branch and include the
exact merge, PR, and cleanup commands still required. Do not merge stale,
failed, unrelated, or abandoned branches as part of housekeeping.

By default, worker commands are **dry-run only**. Use `--execute` explicitly if you want the adapter to call Codex or Claude.
The local `run` command now performs a full advisory pass: it creates
architecture/dev/QA/red-team gate artifacts without external workers, runs
available deterministic local checks, and marks unsupported implementation or
independent red-team gates `NO_GO` instead of leaving them invisible or falsely
complete.

By default, network scanners are blocked by policy. `pip-audit` only runs when both
`--allow-network` is passed and the active policy has `network_allowed=true`.

Git helper output is release evidence only when it is written through the run
ledger. Release validation rejects prose-only branch, commit, PR, or CI claims.
Executed workers cannot write run ledgers, memory, gate state, or finding state;
attempted control-plane mutations are restored and recorded as policy violations.

## Core principle

```text
Models may suggest.
The orchestrator decides.
Evidence proves.
Red-team attacks.
Policy gates ship.
```

## The 25-gate pipeline

The product uses the same pipeline it generates for other software projects:

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
11. UI architecture, UX states, accessibility, and dark-pattern review
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

Gate 23 requires ledger-backed Git provenance from `sdlc git provenance` or the
safe Git helpers. Release validation checks the feature branch, HEAD commit, PR
plan or PR evidence, and local CI/release-gate status before treating the gate as
release-satisfied.

## Directory layout

```text
.sdlc/
  pipeline.json
  policies/
  prompts/
  runs/
  schemas/
  templates/
sdlc/
  adapters.py
  classifier.py
  cli.py
  engine.py
  ledger.py
  models.py
  pipeline.py
  policies.py
  prompts.py
  reporting.py
  scanners.py
  deploy.py
  attestations.py
```

## Worker adapter safety

- Codex and Claude are never invoked unless `--execute` is passed.
- Codex implementation/fix/test modes use workspace-scoped sandbox settings by default.
- Claude planning/review modes use plan/read-style permissions by default.
- Direct `origin/main` push and deployment are blocked by default.

## Scanner policy

Security scanner gates are based on normalized scanner results, not just process
return codes.

- Bandit JSON is parsed into severity/confidence counts.
- CRITICAL/HIGH findings block by default.
- MEDIUM findings block for HIGH/EXTREME runs by default.
- LOW findings are recorded as residual risk unless policy says to block.
- `pip-audit` remains `BLOCKED_BY_POLICY` unless both `--allow-network` and
  `network_allowed=true` are present; dependency audit evidence is mandatory by
  default when dependency manifests exist.

## Red-team execution

Deterministic red-team generation remains available:

```bash
python -m sdlc redteam <run-id>
```

Explicit worker execution is separate and dry-run by default:

```bash
python -m sdlc redteam execute <run-id>
python -m sdlc redteam execute <run-id> --rounds 3 --execute --allow-network
```

By default, red-team execution uses the policy's OpenAI/Codex worker aliases
(`openai-codex-primary`, `openai-codex-adversary`). For HIGH/EXTREME runs, the
red-team gate requires independent executed worker families, distinct OpenAI
model identities, and the active policy's minimum round count. Executed worker CLIs also require both
`--allow-network` and `network_allowed=true` in policy. Unavailable or rejected
workers are recorded as evidence.

## Deployment gate

Deployment commands capture rollout evidence and remain locked by default:

```bash
python -m sdlc deploy plan <run-id> --env production --rollback-command "rollback-command --flag"
python -m sdlc deploy approve <run-id> --env production --actor human_release_manager --evidence approval.md
python -m sdlc deploy execute <run-id> --env production --execute --command "deploy-command --flag"
python -m sdlc deploy verify <run-id> --env production --evidence smoke.md
python -m sdlc deploy verify <run-id> --env production --evidence smoke.md --accepted-residual-risk "reason..." --actor human_security_owner --actor-proof "$HMAC"
python -m sdlc deploy rollback <run-id> --env production --execute --command "rollback-command --flag"
```

Production execution requires explicit rollout allowance, human approval, clean
blocking findings, all prior release gates through commit/CI, non-blocking
security and red-team gates, rollback command planning, and an explicit command.
The deployment gate itself does not become positive until execution,
smoke/monitoring verification, and rollback operability evidence are captured.
Plain `GO` requires successful executed rollback evidence. Non-destructive
rollback readiness or staging rollback proof recorded with
`deploy rollback --evidence ...` is treated as residual risk and requires
explicit accepted residual-risk evidence from an authenticated human
release/security actor, yielding
`GO_WITH_ACCEPTED_RESIDUAL_RISKS`. A deploy or rollback `--execute` without
`--command` is rejected so the ledger cannot record a no-op as executed.
Commands are parsed without a shell and stdout/stderr are redacted before evidence is written. No production
deploy/restart is the default.

## Attestations

Runs can produce deterministic artifact manifests and local-key signatures:

```bash
python -m sdlc attest manifest <run-id>
python -m sdlc attest sign <run-id> --key /path/to/key --execute
python -m sdlc attest verify <run-id> --key /path/to/key
```

Key material is read from the provided path and is not written to repo artifacts
or event logs. Manifests include signed snapshots of `plan.json`,
`findings.json`, filtered `events.jsonl`, and `final-report.md` when present;
manifest generation and verification reject symlinked or run-boundary-escaping
artifacts. Verification failure marks the attestation gate `NO_GO`.

## Current maturity

This is a strong v0.1 foundation:

- ✅ runnable CLI
- ✅ 25-gate product pipeline
- ✅ classifier and specialist activation
- ✅ prompt bundle generation
- ✅ policy files and JSON schemas
- ✅ event ledger
- ✅ Codex/Claude adapter shells
- ✅ worker stdout/stderr/result capture into run evidence
- ✅ protected run ledger and finding/gate mutation controls for executed workers
- ✅ deterministic red-team finding generator
- ✅ finding lifecycle controls
- ✅ schema-, actor-, and dependency-validated manual gate completion controls
- ✅ security scanner orchestration with evidence capture
- ✅ locked command-backed deploy/rollback evidence workflow
- ✅ deterministic artifact manifests and local-key attestations
- ✅ safe local Git branch/commit helpers, PR dry-run planning, and ledger-backed
  Git provenance validation
- ✅ simple terminal dashboard command
- ✅ final report generator
- ✅ unit tests

Still to build:

- richer full-screen TUI dashboard
- policy-approved remote PR execution / GitHub integration
- long-term memory and run comparison
- external signing-provider integration, if explicitly approved

## Run tests

```bash
python -m unittest discover -s tests
```
