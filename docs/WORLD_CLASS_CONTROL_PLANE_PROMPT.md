# World-Class Control Plane Prompt

Use this prompt to continue the Secure SDLC Control Plane toward a developer-first,
evidence-backed orchestration system that handles vague user requests without
weakening gates, red-team review, deployment locks, or claim discipline.

This prompt intentionally translates ambitious language such as "all-knowing AGI",
"digital twin", or "world class" into implementable product requirements:
local context memory, consentful preference learning, better intake, standards-aware
requirements generation, explainable prework reports, and stronger evidence gates.
Do not claim omniscience, production readiness, security, compliance, financial
fitness, or world-class maturity unless the active run proves that exact claim.

```text
# Codex Takeover Prompt - Developer-First Secure SDLC Control Plane

You are Codex taking over implementation in the `sdlc-control-plane` repository.

## Mission

Make this terminal-native Secure SDLC control plane radically easier for developers
to use while preserving the core authority model:

- The user may provide vague requests.
- Models may suggest, plan, implement, and review.
- The orchestrator decides gate state.
- Evidence proves claims.
- Red-team attacks before release.
- Human approval remains required for production and risk acceptance.

The target product should turn inputs like:

- "I need a fibonacci series"
- "Build a world class trading system"
- "Add login"
- "Make this production ready"

into scoped, risk-classified, evidence-driven delivery runs with the smallest
necessary clarification burden for the developer.

## Mandatory First Actions

1. Read `AGENTS.md`.
2. Read `README.md`.
3. Read:
   - `docs/PRODUCTION_GRADE_COMPLETION_PROMPT.md`
   - `docs/RED_TEAM_GO_REMEDIATION_PROMPT.md`
   - `docs/PIPELINE.md`
   - `docs/RED_TEAM_STANDARD.md`
4. Run:
   - `python -m unittest discover -s tests`
   - `python -m sdlc validate`
   If `python` is unavailable, run the same commands with `python3` and the
   project virtualenv, then record the exact failure and fallback.
5. Inspect current release readiness:
   - `python -m sdlc validate --run-id production-grade-release-blockers --release`
   - `python -m sdlc report production-grade-release-blockers --print`

Do not begin feature implementation until a prework expectation report is written
for the active run.

## Current Findings To Address

Resolve every current open finding with code, tests, run evidence, and a fresh
brutal red-team review:

- `HIGH-042`: Production deploy gate can be satisfied by fabricated deploy record
  fields without ledger provenance.
- `HIGH-043`: Open MEDIUM findings can still pass commit and production deployment
  gates.
- `HIGH-044`: Gate evidence can still be satisfied by shallow assertion text.
- `HIGH-045`: Active run has many GO gates while release validation rejects the run.
- `RT-LOW-001`: Unit test evidence could not be reproduced in the read-only audit
  sandbox.

Expected remediation direction:

- Gate deploy evidence on ledger provenance, not mutable JSON fields alone.
- Gate commit/branch/PR/CI evidence on ledger-backed Git command provenance, not
  mutable JSON fields, stale plan values, or shallow/manual evidence.
- Protect run ledgers, memory, gate state, and finding state from executed
  worker writes; workers may propose evidence, but only the orchestrator records
  authoritative control-plane events.
- Block commit, PR, deploy, attestation, and finalization on unresolved findings
  that the release validator treats as blocking.
- Require substantive, gate-specific source evidence for typed gate evidence.
- Make reports and status views clearly distinguish "local gate state" from
  "release-satisfied state".
- Run tests in a disposable audit workspace or record exact environmental limits
  as evidence.

## Non-Negotiable Rules

- Preserve the 25-gate pipeline.
- Do not remove or weaken the red-team loop.
- Do not let implementers close their own findings.
- Do not enable direct `origin/main` push by default.
- Do not enable production deploy/restart by default.
- Do not execute workers unless `--execute` is passed.
- Do not add network calls unless policy and user explicitly allow them.
- Do not hide failed tests, missing scanners, unavailable workers, blocked network
  scans, stale reports, or release validation failures.
- Do not store secrets, credentials, private tokens, or raw sensitive prompts in
  repo files, logs, reports, memory, or run artifacts.
- Every bypass, unavailable tool, policy exception, and accepted residual risk must
  be written to the event ledger.

## Product Capability 0 - Six-Agent Parallel Orchestration

The current codebase defines six default SDLC roles, but the implementation must
support true parallel execution rather than only sequential worker calls.

Build an orchestrator-controlled agent scheduler that can run at least six role
agents in parallel when their tasks are independent.

Important distinction:

- Role agents are SDLC responsibilities such as PM, architecture, implementation,
  evidence, QA, and red-team.
- Worker families are local CLIs such as Codex, Claude, Gemini, Kimi, or other
  authenticated tools.
- A role agent may be backed by any available worker family, but the orchestrator
  remains the authority and must enforce role permissions, write ownership, and
  gate dependencies.

Suggested commands:

- `sdlc agents plan <run-id> --parallel 6`
- `sdlc agents execute <run-id> --parallel 6 --execute`
- `sdlc agents status <run-id>`
- `sdlc agents doctor`

Requirements:

- Default to dry-run. No worker execution unless `--execute` is passed.
- Enforce a configurable concurrency limit with a default of at least 6 when six
  independent tasks exist.
- Use only standard-library concurrency unless a dependency is strongly justified.
- Start from `concurrent.futures` or equivalent simple process/thread orchestration;
  do not add a heavy queue system for the first implementation.
- Generate a dependency graph before launching work.
- Do not parallelize tasks with unresolved dependencies.
- Assign disjoint write ownership for each write-capable role.
- Run read-only roles concurrently with write roles only when their inputs are
  stable enough to audit.
- Red-team agents are read-only and cannot close their own findings.
- Implementation agents cannot close findings they created or own.
- Capture each agent task under:
  - `worker-results/<timestamp>-<agent-id>-<worker>-<mode>/`
  - `artifacts/agents/<agent-id>/task.json`
  - `artifacts/agents/<agent-id>/summary.md`
- Write scheduler events:
  - `agents.plan_created`
  - `agents.task_started`
  - `agents.task_completed`
  - `agents.task_failed`
  - `agents.parallel_batch_completed`
- Record unavailable workers without hiding the failure.
- If fewer than six workers are locally available, still schedule six role tasks
  when possible, but mark unavailable worker assignments as blocked evidence.
- Provide a policy knob:
  - `agents.max_parallel`
  - `agents.min_parallel_for_high_or_extreme`
  - `agents.allowed_workers`
  - `agents.role_worker_preferences`
- Add status output that shows:
  - queued
  - running
  - completed
  - failed
  - blocked by dependency
  - blocked by unavailable worker
  - blocked by permissions

Minimum six-agent work split for this release:

- Agent 1: PM/coordinator, dependency graph, GO/NO-GO calls.
- Agent 2: architecture/contracts/invariants.
- Agent 3: implementation owner with constrained write scope.
- Agent 4: evidence, ledger, attestations, reports, memory artifacts.
- Agent 5: QA, tests, fixtures, smoke validation.
- Agent 6: read-only brutal red-team, deployment lock, rollback review.

For high-risk requests such as trading systems, activate additional specialist
agents when relevant, but the baseline implementation must prove six-way parallel
execution with tests.

Parallel orchestration tests:

- six independent dry-run role tasks are scheduled in one batch
- `--parallel 6` is honored and recorded in the ledger
- dependency-blocked tasks do not start early
- write ownership violations fail the responsible task
- unavailable workers are recorded as blocked evidence
- red-team tasks are read-only
- implementation and red-team findings cannot be closed by the same role
- non-interactive JSON status is stable for CI

## Product Capability 1 - Vague Request Intake Autopilot

Implement an intake layer that can transform vague requests into a scoped run with
minimal developer overhead.

Requirements:

- Add a command such as:
  - `sdlc brief "<request>"`
  - or extend `sdlc plan` with `--autobrief`.
- Classify the request by:
  - intent
  - domain
  - risk level
  - UI/security/infra/data involvement
  - likely stakeholder and approval needs
  - ambiguity level
  - whether the request is toy/demo, internal tool, production software, regulated,
    financial, safety-critical, or security-sensitive.
- Ask only blocking clarification questions.
- Use an explicit question budget:
  - LOW risk: ask 0 to 2 questions, default safely.
  - MEDIUM risk: ask 1 to 4 questions.
  - HIGH/EXTREME risk: ask enough to prevent unsafe implementation, but group the
    questions into concise decision blocks.
- When the user request is trivial, move fast:
  - "I need a fibonacci series" should default to a small, testable implementation
    unless language, repo target, or interface is genuinely unknown.
- When the user request is high consequence, slow down:
  - "Build a world class trading system" must trigger financial-risk scoping,
    market/data/execution boundaries, compliance assumptions, simulation vs live
    trading separation, secrets policy, audit logs, kill switches, and explicit
    non-claims about profitability or investment advice.
- Convert assumptions into explicit, reviewable requirements.
- Never treat vague ambition as evidence.

Outputs:

- `artifacts/prework/intake_brief.json`
- `artifacts/prework/intake_brief.md`
- event ledger entry `intake.brief_created`

## Product Capability 2 - Standards-Aware Requirements Builder

Build a requirements-generation path that uses stable local mappings and, when
policy permits network access, refreshes standards references from official sources.

Baseline standards radar:

- NIST SP 800-218 SSDF for secure software development practices.
- OWASP SAMM for software assurance maturity structure.
- OWASP ASVS for application security verification requirements.
- OWASP Top 10 and OWASP Top 10 for LLM Applications for web and LLM threat focus.
- SLSA for supply-chain provenance and artifact integrity.
- OpenSSF Scorecard for open-source project security posture signals.
- NIST AI RMF and NIST AI 600-1 Generative AI Profile for AI risk governance when
  AI features or AI workers are part of the system.

Requirements:

- Add a standards mapping artifact per run:
  - `artifacts/prework/standards_mapping.json`
  - `artifacts/prework/standards_mapping.md`
- Do not scrape or browse by default.
- If standards lookup uses the network, require both policy allowance and explicit
  user or CLI allowance, then cite official sources.
- Record standards version/date/source URL when available.
- If offline, use built-in baseline mappings and mark them as offline reference
  material rather than latest-current evidence.
- Convert standards into concrete acceptance criteria and evidence requirements.

## Product Capability 3 - Prework HTML Expectation Report

Before implementation starts, generate a temporary, local HTML report explaining:

- interpreted request
- assumptions
- blocking questions
- risk level and why
- expected gates
- expected artifacts
- estimated work phases
- success criteria
- non-goals and forbidden claims
- anticipated red-team attack areas
- estimated time bands, with uncertainty

Requirements:

- Add a command such as:
  - `sdlc brief "<request>" --html`
  - or `sdlc report <run-id> --prework-html`
- Write:
  - `artifacts/prework/expectations.html`
  - `artifacts/prework/expectations.json`
- The report must be static HTML with no external dependencies by default.
- The report must not include secrets or raw credentials.
- The report must show "not release-ready" until release validation proves otherwise.
- Keep it useful in terminals and CI by also producing Markdown or JSON.

## Product Capability 4 - Local Episodic Memory With Consent

Implement a local memory layer that helps the tool learn from previous runs without
becoming a surveillance system or a false "digital twin".

Use SQLite unless a stronger reason exists. Do not add a network database by default.

Suggested command set:

- `sdlc memory init`
- `sdlc memory status`
- `sdlc memory record <run-id>`
- `sdlc memory search "<topic>"`
- `sdlc memory export`
- `sdlc memory delete --all`
- `sdlc memory disable`

Suggested database:

- `.sdlc/memory.sqlite`

Suggested tables:

- `episodes`: run id, timestamp, request summary, risk, domain, outcome, verdict,
  residual risks, artifacts, commit hash.
- `user_preferences`: explicit user preferences only, with source run and timestamp.
- `decision_patterns`: recurring decisions, accepted defaults, rejected defaults.
- `question_outcomes`: questions asked, whether they were useful, answer impact.
- `standards_cache`: official source URL, version/date, retrieved_at, hash.
- `feedback`: user correction, rating, or approval notes.
- `privacy_events`: export, deletion, redaction, consent changes.

Privacy and safety requirements:

- Memory is opt-in or clearly disclosed at first use.
- Store summaries and hashes by default, not raw prompts.
- Never store secrets or credentials.
- Redact likely PII/secrets before write.
- Provide export and delete.
- Record memory writes in the event ledger.
- Do not claim the system "knows the user better than the user".
- Treat memory as preference support and audit context, not authority.

Learning methodology:

- Start with retrieval-augmented preference memory and explicit user feedback.
- Use simple scoring to prefer defaults that previously worked for this user.
- Do not implement autonomous reinforcement learning that changes release policy.
- Do not train external models or transmit memory without explicit policy and user
  approval.
- Preserve explainability: every memory-influenced decision must show which prior
  episode or preference affected it.

## Product Capability 5 - Developer-No-Overhead UX

Make the happy path short while preserving evidence depth behind the scenes.

Target flows:

```bash
sdlc brief "I need a fibonacci series"
sdlc plan --from-brief <brief-id>
sdlc run <run-id>
sdlc report <run-id> --print
```

```bash
sdlc brief "build a world class trading system" --html
sdlc plan --from-brief <brief-id> --risk auto --security auto --infra auto
sdlc tui <run-id>
```

Requirements:

- Provide safe defaults and clear next commands.
- Make the next blocking action obvious.
- Use concise language.
- Generate artifacts automatically where possible.
- Keep non-interactive CI behavior stable.
- Add `--json` output for new commands.
- Do not force a full-screen TUI for automation.

## Product Capability 6 - Status Truthfulness

Resolve the UX risk where many gates show `GO` while release validation is `NO_GO`.

Requirements:

- Add a release-readiness overlay to status/report/TUI:
  - local gate state
  - release-satisfied state
  - blocker reason
  - next required command
- A gate may retain local state, but the UI must not imply release readiness when
  release validation rejects the evidence.
- Final reports must always include release blockers when any exist.
- Add tests showing a forged or stale local GO does not appear as release-satisfied.

## Product Capability 7 - Red-Team Loop Until GO Or Explicit Accepted Risk

After implementation, run a real red-team loop:

1. Run required tests and validation.
2. Execute cross-model red-team with at least two worker families when available.
3. Normalize findings.
4. Fix CRITICAL/HIGH/MEDIUM findings or route them through explicit residual-risk
   acceptance if policy allows.
5. Re-run tests, scanners, release validation, attestations, and red-team.
6. Repeat until the final verdict is one of:
   - `GO`
   - `GO_WITH_ACCEPTED_RESIDUAL_RISKS`

Do not stop at known blockers unless an external dependency is unavailable. If a
worker is unavailable or quota-limited, record it as evidence, try another configured
worker family, and keep the release verdict honest.

## Expected Tests

Add focused unit tests for every new command and policy control:

- six-agent parallel scheduler creates a dependency-aware execution plan
- six independent dry-run tasks run in parallel-capable batches with ledger events
- agent status reports queued, running, completed, failed, and blocked states
- worker availability checks support Codex, Claude, Gemini, Kimi, and configured
  custom local CLIs without hardcoding Codex as the only path
- vague request produces intake brief with risk, assumptions, and question budget
- trivial request asks zero or minimal questions
- high-risk trading request triggers finance/security/compliance gates
- standards mapping uses offline baseline when network is not allowed
- network standards refresh requires explicit allowance
- prework HTML and JSON reports are generated and ledgered
- memory writes are opt-in/disclosed and redacted
- memory export/delete works
- memory-influenced defaults are explainable
- open MEDIUM findings block commit, deploy, attestation, and finalization when
  release validation treats them as blocking
- deploy gate cannot pass from mutable JSON without ledger provenance
- shallow gate evidence is rejected
- status/report show release-readiness blockers despite local GO gate state
- forged or stale Git branch, commit, PR, or CI evidence does not appear
  release-satisfied
- managed worker attempts to spoof actors or mutate `.sdlc/runs/**` are blocked,
  restored, and ledgered as policy violations

Always run:

```bash
python -m unittest discover -s tests
python -m sdlc validate
python -m sdlc validate --run-id production-grade-release-blockers --release
```

## Definition Of Done

The work is not done until:

- all current open findings are closed by authorized actors with evidence
- required tests pass
- repository validation passes
- release validation passes or returns accepted residual risk with explicit evidence
- cross-model red-team is executed and positive, or unavailability is documented
  without overstating readiness
- attestation manifest/sign/verify succeeds
- final report is regenerated and finalized atomically
- release validation proves Git provenance before any release-ready claim
- no unsupported production-ready, secure, compliant, profitable, or world-class
  claims remain

## Implementer Self-Review Required

Before final response, produce:

- What changed?
- What tests ran?
- What risks remain?
- What unsupported claims were removed?
- What would a brutal red-team still attack?
```

## Official Reference Set

Use current official sources when network access is explicitly allowed. Baseline
references for the prompt design:

- NIST SSDF SP 800-218: https://csrc.nist.gov/pubs/sp/800/218/final
- NIST SSDF project: https://csrc.nist.gov/projects/ssdf
- OWASP SAMM: https://owasp.org/www-project-samm/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Top 10 for LLM Applications: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- SLSA specification: https://slsa.dev/spec/
- OpenSSF Scorecard: https://openssf.org/scorecard/
- NIST AI RMF: https://www.nist.gov/itl/ai-risk-management-framework
- NIST AI 600-1 Generative AI Profile: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
