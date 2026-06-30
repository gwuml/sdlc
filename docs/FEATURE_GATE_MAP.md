# Feature → Gate Map — how to exercise every feature across all 25 gates

This is the single reference an auditor (or new operator) uses to drive every feature
in the repo and touch all 25 Secure-SDLC gates. Each row gives the gate, the
command(s) that exercise it, and where its evidence lands.

## End-to-end happy path (touches all 25 gates)

For a single-command auto run that asks for request-specific approvals, creates
a fresh implementation artifact, and prints all 25 gates with proof paths:

```bash
python -m sdlc auto "Create a web site for a local bakery with an accessible contact form"
```

The same command path is generic; the intake plan/LLM decides the artifact type,
questions, architecture, and generated content:

```bash
python -m sdlc auto "Generate a simple fibonacci series script"
```

For model-driven interpretation, execute a configured intake worker:

```bash
python -m sdlc auto "Build a small incident status tool" \
  --policy host-oauth-tools \
  --execute-intake-llm \
  --intake-model codex \
  --allow-network
```

Executed intake workers follow the same safety rule as other workers: networked
model CLIs require `--allow-network` and a policy with `network_allowed=true`
such as `--policy host-oauth-tools`. If `--execute-intake-llm` is requested and
the worker is blocked or does not return a valid plan, the command fails before
creating a run instead of silently falling back.
For deterministic tests or audited demos, provide the model output directly:

```bash
python -m sdlc auto "Build a small incident status tool" \
  --intake-plan .sdlc/intake-plans/status-tool.json
```

The auto command is intentionally approval-driven: it creates, executes, or
loads a structured intake plan, then renders questions from that plan's
`questions[]`. The plan supplies the request interpretation, Mermaid
architecture, request-appropriate follow-up questions, artifact kind, generated
content, cloud/cleanup posture, and default choices. The best and most complete
demonstration should be option 1/default in the plan. If no worker or intake
plan is provided, the command records a visible `schema_fallback` intake rather
than claiming model interpretation. AWS resources or destructive cleanup are
created only when the user explicitly approves execution.

For a live, evidence-heavy demo, use `--showcase`. It implies the
`host-oauth-tools` policy when no policy is supplied, enables network worker
execution, runs the intake LLM, role agents, formal red-team workers, Claude
honesty validation, execution-log export, presentation generation, and browser
opening. It still does not silently create AWS resources or clean them up; cloud
hosting and decommission remain behind the explicit AWS approval flags.

```bash
python -m sdlc auto \
  "Build a public release-readiness status website with gate status cards, audit evidence links, accessible incident banner, S3 hosting plan, rollback instructions, and cleanup plan" \
  --showcase
```

Every auto run writes an evidence index at
`.sdlc/runs/<run-id>/artifacts/auto/evidence-index.md`. Per-gate proof artifacts
land under `.sdlc/runs/<run-id>/artifacts/auto/gates/`, including
`02-stakeholders_raci.md` and `08-supply_chain_sbom.md`. The browsable summary
dashboard is `.sdlc/runs/<run-id>/artifacts/auto/summary.html`; it links each
gate proof, the 25-phase report, architecture/QA/SBOM/red-team shortcuts, and
LLM intake plus role-agent/LLM activity. The raw intake prompt and result are
stored at `artifacts/auto/llm-intake-prompt.md` and
`artifacts/auto/llm-intake.json`.
Showcase runs additionally write `artifacts/auto/execution-log.md`,
`artifacts/auto/execution-events.json`,
`artifacts/auto/validation/claude-validation.json`, and
`artifacts/auto/presentation/index.html` with a companion Manim scene.

Website auto runs plan an AWS S3 static website by default using the logical
gateway prefix `sdlc-web-gateway`. The prefix can be changed with
`--aws-gateway-name`, or an exact bucket can be supplied with `--aws-bucket`.

```bash
python -m sdlc auto "Create a web site for a local bakery with an accessible contact form" \
  --execute-aws \
  --approve-aws-deploy "host this generated static website in AWS using the default profile" \
  --public-read
```

Decommission follows the same auto evidence pattern. It discovers the target
from a prior auto run or accepts `--aws-bucket`, writes
`artifacts/auto/decommission-plan.json`, and remains plan-only unless cleanup is
explicitly approved:

```bash
python -m sdlc auto decommission prod website --target-run-id <run-id>
python -m sdlc auto decommission prod website \
  --target-run-id <run-id> \
  --execute-cleanup \
  --approve-cleanup "approved: decommission AWS static website resources for this sdlc auto run"
```

```bash
python -m sdlc init                                              # bootstrap .sdlc/
RID=$(python -m sdlc plan "add OAuth login with audit logging" \
       --risk auto --ui auto --security auto --infra auto | sed -n 's/^Created run: //p')
python -m sdlc status "$RID"            # gates 1-25 initialized; local vs release state
python -m sdlc next "$RID"              # safest next action
python -m sdlc run "$RID"               # advance deterministic + advisory gates
python -m sdlc scan "$RID"              # gate 17 security scans
python -m sdlc agents plan "$RID" --parallel 6     # gate 9 agent plan/permissions
python -m sdlc agents plan "$RID" --agent-model architecture=claude --agent-model redteam=openai-codex-primary
python -m sdlc auto "build a request-specific demo" --execute-agents --policy host-oauth-tools --allow-network
python -m sdlc worker "$RID" codex --mode BUILD     # gate 14 (dry-run; add --execute to run)
python -m sdlc redteam "$RID"           # gate 20 (deterministic; --execute for workers)
python -m sdlc finding list "$RID"      # gate 21 finding lifecycle
python -m sdlc gate complete "$RID" <gate> --verdict GO --evidence ...   # manual gate evidence
python -m sdlc git provenance "$RID"    # gate 23 commit/branch/PR/CI provenance
python -m sdlc attest manifest "$RID"   # gate 22 attestations
python -m sdlc deploy plan "$RID" --env production    # gate 24 (locked)
python -m sdlc report "$RID" --print    # gate 25 final report
python -m sdlc validate --run-id "$RID" --release     # deterministic release verdict
```

## Per-gate reference

| # | Gate | Command(s) that exercise it | Evidence location |
|---|------|------------------------------|-------------------|
| 1 | intake_scope | `sdlc plan` / `sdlc brief` | `artifacts/intake_scope.md` |
| 2 | stakeholders_raci | `sdlc run` (advisory) | `artifacts/stakeholders_raci.md` |
| 3 | mission_non_goals | `sdlc run` (advisory) | `artifacts/mission_non_goals.md` |
| 4 | repo_context_env_branch | `sdlc run` (git deterministic) | `artifacts/repo_context_env_branch.md` |
| 5 | risk_blast_radius | `sdlc plan` (classifier) | `plan.json` classification |
| 6 | data_privacy_secrets | `sdlc run` + `sdlc scan` | `artifacts/data_privacy_secrets.md` |
| 7 | baseline_freeze | `sdlc run` (git snapshot) | `artifacts/baseline_freeze.md` |
| 8 | supply_chain_sbom | `sdlc run` (lockfiles) + `scripts/gen_sbom.py` + release SBOM | `artifacts/supply_chain_sbom.md`, `artifacts/sbom.cdx.json` |
| 9 | agent_plan_permissions | `sdlc agents plan/execute/status/doctor` | `artifacts/agents/**` |
| 10 | architecture_contracts | `sdlc run` (advisory) / worker | `artifacts/architecture_contracts.md` |
| 11 | ui_architecture_accessibility | `sdlc run` (only if `has_ui`) | `artifacts/ui_architecture_accessibility.md` |
| 12 | threat_model_abuse_cases | `sdlc run` (advisory) / worker | `artifacts/threat_model_abuse_cases.md` |
| 13 | implementation_plan_changeset | `sdlc run` (advisory) / worker | `artifacts/implementation_plan_changeset.md` |
| 14 | implementation | `sdlc worker <run> codex --mode BUILD --execute` | `worker-results/**` |
| 15 | deterministic_quality | `sdlc run` (detected test commands) | `artifacts/deterministic_quality.md` |
| 16 | qa_tests_integration_smoke | `sdlc worker --mode TEST` / local tests | `worker-results/**` |
| 17 | security_scans | `sdlc scan <run>` (bandit/detect-secrets/pip-audit/checkov) | `artifacts/{bandit,detect-secrets,...}.json` |
| 18 | observability_runbooks | `sdlc run` (advisory) | `artifacts/observability_runbooks.md` |
| 19 | implementer_self_review | `sdlc gate complete` / worker | gate evidence |
| 20 | independent_redteam_cross_model | `sdlc redteam <run> --execute --rounds 2` (cross-model) | `artifacts/redteam/**` |
| 21 | critical_high_fix_loop | `sdlc finding list/open/close/accept/defer` | `findings.json` |
| 22 | evidence_traceability_attestations | `sdlc attest manifest/sign/verify` | `artifacts/attestations/**` |
| 23 | commit_branch_pr_ci | `sdlc git branch/commit/pr/provenance` | `artifacts/git_*`, ledger |
| 24 | deploy_rollout_postdeploy | `sdlc deploy plan/approve/execute/verify/rollback` | `artifacts/deploy/**` |
| 25 | final_report_reaudit | `sdlc report <run> --print` | `final-report.md` |

## Cross-cutting features (this session) and what they touch

| Feature | Command | What it does / gates touched | Docs |
|---------|---------|------------------------------|------|
| Status & next | `sdlc status`, `sdlc next` | release-readiness overlay across all 25 gates | README |
| Interactive TUI | `sdlc tui <run>` (`--no-tui` fallback) | dashboard over gates/findings/blockers; 10 benchmark tasks | `docs/SCREENCAST.md` |
| Benchmark | `sdlc bench run/compare/report` | measured 12-dimension quality across runs | `docs/EVIDENCE.md`, `artifacts/bench/report.md` |
| Quality diff | `sdlc diff quality <old> <new>` | 12 structural fields between two runs | this file |
| Self-improvement | `sdlc learn record/suggest/apply` | lessons from gate blockers; human-approved only | `sdlc/learn.py` |
| Providers | `agents.role_worker_preferences`, `--agent-model-config`, `--agent-model role=worker` | Claude/Codex/Gemini/Kimi/custom workers by role | `artifacts/agents/task-plan.json` |
| Ledger integrity | `sdlc ledger seal-legacy` | tamper-evident event chain | — |
| Memory (consent) | `sdlc memory init/status/search/export/delete/disable` | local episodic memory | `privacy.md` |
| Release validation | `sdlc validate [--run-id <r> --release]` | deterministic GO/NO_GO verdict | `docs/RELEASE_PROCESS.md` |
| Signed release | `.github/workflows/release.yml` (tag `v*`) | build → SBOM → Sigstore-sign → GitHub Release | `docs/RELEASE_PROCESS.md`, `KEYS.md` |

## Other reference docs
- `README.md` — quick start, the 25-gate list, worker-adapter safety.
- `AGENTS.md` — agent roles, write-ownership, required commands.
- `docs/PIPELINE.md` — gate definitions detail.
- `docs/HANDS_ON_ADVISORY_USAGE.md` — advisory-mode walkthrough.
- `docs/WHY_THIS_TOOL.md` — comparison vs coding agents + LLM integration.
- `docs/EVIDENCE.md` — measured benchmark + dogfooding verdict.
- `docs/DEMO.md` / `scripts/demo.sh` — captured full-feature walkthrough.
