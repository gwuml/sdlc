# Benchmark Report

Runs evaluated: 23
Measured dimensions: 10/12
Overall score (mean of measured): 87.6

## Claim discipline

100x superiority was not proven. Dimensions without measurement are marked
UNAVAILABLE, not scored.

## Dimensions

| # | Dimension | Status | Value | Score | Detail |
|---|-----------|--------|-------|-------|--------|
| 1 | setup_friction | MEASURED | 0.15 | 100.0 | Cold `init` + first `plan` completed in 0.15s (target <300s). |
| 2 | blocker_visibility | MEASURED | 0.0014 | 100.0 | Computed readiness and located first blocking gate (intake_scope) for run 'audit-container-hard-isolation-20260525'. |
| 3 | evidence_completeness | MEASURED | 85.4 | 85.4 | 258/302 executed gates across 23 runs carry evidence. |
| 4 | hallucination_count | MEASURED | 0 | 100.0 | Scanned 18 reports; 0 unsupported claim candidates. |
| 5 | redteam_independence | MEASURED | 100.0 | 100.0 | 17/17 HIGH/EXTREME runs assign a red-team worker distinct from the implementer. |
| 6 | resume_recovery | MEASURED | 100.0 | 100.0 | 15/15 completed gates preserved across a resume re-run. |
| 7 | failed_tool_visibility | MEASURED | 44.4 | 44.4 | 4/9 scan summaries surface tool status explicitly. |
| 8 | release_readiness_accuracy | MEASURED | 100.0 | 100.0 | 23/23 runs: release verdict is consistent with blocker presence. |
| 9 | tui_task_completion | UNAVAILABLE | — | — | TUI built; addresses 10/10 tasks programmatically. Official score pending independent-reviewer evaluation (spec requires no-docs human review). |
| 10 | provider_flexibility | MEASURED | 4 | 100.0 | Worker CLIs on PATH: ['codex', 'claude', 'gemini', 'ollama'] (target >= 3). |
| 11 | cost_token_visibility | UNAVAILABLE | — | — | Cost/token usage is not tracked by the engine. |
| 12 | github_pr_provenance | MEASURED | 46.2 | 46.2 | 6/13 git-active runs have ledger-backed provenance. |
