# Demo Walkthrough (captured output)

Reproduce live for a screencast:
```
asciinema rec -c 'bash scripts/demo.sh' sdlc-demo.cast   # or screen-record: bash scripts/demo.sh
```

Interactive TUI (curses) is best shown live: `python -m sdlc tui product-self-run`

```text

== 1. The control plane governs AI workers — it does not replace them ==
$ python -m sdlc --help | sed -n '1,8p'
usage: sdlc [-h] [--repo REPO]
            {init,plan,start,brief,status,next,run,worker,prompt,redteam,isolation,scan,deploy,attest,agents,ledger,memory,finding,gate,git,tui,release,report,validate,bench} ...

Terminal-native Secure SDLC control plane for AI software delivery

positional arguments:
  {init,plan,start,brief,status,next,run,worker,prompt,redteam,isolation,scan,deploy,attest,agents,ledger,memory,finding,gate,git,tui,release,report,validate,bench}
    init                Initialize .sdlc structure

== 2. Plan a gated, risk-classified run from a plain request ==
$ python -m sdlc plan 'add OAuth login with audit logging' --risk auto --security auto | head -6
Created run: add-oauth-login-with-audit-logging-20260615-101952
Risk: EXTREME
Prompt: /Users/rmallarapu/dev/sdlc/.sdlc/runs/add-oauth-login-with-audit-logging-20260615-101952/prompts/execution_prompt.md
Plan: /Users/rmallarapu/dev/sdlc/.sdlc/runs/add-oauth-login-with-audit-logging-20260615-101952/plan.json

== 3. Status: 25 gates, local vs RELEASE state, blockers — in one command ==
$ python -m sdlc status product-self-run | sed -n '1,12p'
Run: product-self-run
Feature: Advance SDLC Control Plane into terminal-native Secure SDLC orchestrator with finding lifecycle, worker adapters, TUI, git PR integration, scanner hooks, and artifact provenance
Risk: EXTREME | Policy: default | Branch: unknown
Release readiness: NO_GO | blockers=31
Authority mode: ADVISORY | production authority=DISABLED
Use this run as advisory PR evidence only; it is not production deployment clearance.

Gates:
  01. intake_scope                         local=GO/GO  release=BLOCKED  owner=agent_1_pm_coordinator
  02. stakeholders_raci                    local=GO/GO  release=BLOCKED  owner=agent_1_pm_coordinator
  03. mission_non_goals                    local=GO/GO  release=BLOCKED  owner=agent_1_pm_coordinator
  04. repo_context_env_branch              local=GO/GO  release=BLOCKED  owner=agent_1_pm_coordinator

== 4. The interactive TUI (plain fallback shown; run 'sdlc tui product-self-run' live for curses) ==
$ python -m sdlc tui product-self-run --no-tui | sed -n '1,20p'
================================================================================
SDLC CONTROL PLANE — DASHBOARD
================================================================================
Run: product-self-run
Feature: Advance SDLC Control Plane into terminal-native Secure SDLC orchestrato
Risk: EXTREME | Policy: default | Branch: unknown
Release: NO_GO | blockers=31 | authority=ADVISORY
Next blocking gate: intake_scope

Gates:  (* = blocking;  cols: NN id  local/verdict  release)
*01 intake_scope                   GO/GO  BLOCKED
*02 stakeholders_raci              GO/GO  BLOCKED
*03 mission_non_goals              GO/GO  BLOCKED
*04 repo_context_env_branch        GO/GO  BLOCKED
*05 risk_blast_radius              GO/GO  BLOCKED
*06 data_privacy_secrets           GO/GO  BLOCKED
*07 baseline_freeze                GO/GO  BLOCKED
*08 supply_chain_sbom              GO/GO  BLOCKED
*09 agent_plan_permissions         GO/GO  BLOCKED
*10 architecture_contracts         GO/GO  BLOCKED

== 5. Measured benchmark — 12 dimensions, evidence not claims ==
$ python -m sdlc bench run | sed -n '1,14p'
Benchmark: 12/12 dimensions measured across 25 runs; overall score=88.0
  1_setup_friction                 100.0
  2_blocker_visibility             100.0
  3_evidence_completeness          85.4
  4_hallucination_count            100.0
  5_redteam_independence           100.0
  6_resume_recovery                100.0
  7_failed_tool_visibility         44.4
  8_release_readiness_accuracy     100.0
  9_tui_task_completion            80.0
  10_provider_flexibility          100.0
  11_cost_token_visibility         100.0
  12_github_pr_provenance          46.2

== 6. The honest comparative factor (NOT 100x) and category capabilities ==
$ sed -n '/Measured factor/,/present.absent/p' artifacts/bench/comparison_matrix.md
## Measured factor: identifying release blockers

Task: find the release blockers and their reasons for a run. Metric: artifacts inspected to identify release blockers + reasons (manual baseline) vs 1 tool command.

- Tool: **1 command**.
- Manual baseline (conservative): **4x** more inspection units (median across 25 runs; range 3x–47x).
- **100x proven on this metric: NO.** The honest factor is the median above, not 100x.

_Conservative steps proxy; under-counts manual effort (excludes re-deriving validation rules). Not wall-clock; not a measurement of any other product._

## Capability differences (category, not a ratio)

A raw-artifact baseline or generic coding agent cannot produce these at all,
so they are reported as present/absent, never as a finite multiple:

== 7. The tool gates its OWN work — and reports the real numbers ==
$ sed -n '1,12p' docs/EVIDENCE.md
# Evidence Report — Secure SDLC Control Plane

Generated from measured runs of the tool on this repository. This is the capstone
artifact for the "world-class" goal: it reports **what was measured**, not what was
claimed. Regenerate the numbers with `sdlc bench run` (writes
`artifacts/bench/after.json`, `report.md`, `comparison_matrix.md`).

## Scope of claim

World-class **for Secure SDLC orchestration** — enforced gate evidence, cross-model
red-team independence, release-readiness discipline, and claim discipline. This is a
different category from a general coding agent (e.g. Claude Code), whose strengths

== Demo complete. Everything shown is measured and committed (PR #1). ==
```
