# Benchmark Report

Runs evaluated: 23
Measured dimensions: 12/12
Overall score (mean of measured): 88.0

## Claim discipline

100x superiority was not proven. Dimensions without measurement are marked
UNAVAILABLE, not scored.

## Dimensions

| # | Dimension | Status | Value | Score | Detail |
|---|-----------|--------|-------|-------|--------|
| 1 | setup_friction | MEASURED | 0.196 | 100.0 | Cold `init` + first `plan` completed in 0.20s (target <300s). |
| 2 | blocker_visibility | MEASURED | 0.0018 | 100.0 | Computed readiness and located first blocking gate (intake_scope) for run 'audit-container-hard-isolation-20260525'. |
| 3 | evidence_completeness | MEASURED | 85.4 | 85.4 | 258/302 executed gates across 23 runs carry evidence. |
| 4 | hallucination_count | MEASURED | 0 | 100.0 | Scanned 19 reports; 0 unsupported claim candidates. |
| 5 | redteam_independence | MEASURED | 100.0 | 100.0 | 17/17 HIGH/EXTREME runs assign a red-team worker distinct from the implementer. |
| 6 | resume_recovery | MEASURED | 100.0 | 100.0 | 15/15 completed gates preserved across a resume re-run. |
| 7 | failed_tool_visibility | MEASURED | 44.4 | 44.4 | 4/9 scan summaries surface tool status explicitly. |
| 8 | release_readiness_accuracy | MEASURED | 100.0 | 100.0 | 23/23 runs: release verdict is consistent with blocker presence. |
| 9 | tui_task_completion | MEASURED | 80.0 | 80.0 | Independent reviewer (not the builder) attested APPROVED ('TUI looks great; proceed'); holistic sign-off credited at the 8/10 spec threshold (per-task rubric would refine this). |
| 10 | provider_flexibility | MEASURED | 4 | 100.0 | Worker CLIs on PATH: ['codex', 'claude', 'gemini', 'ollama'] (target >= 3). |
| 11 | cost_token_visibility | MEASURED | 100.0 | 100.0 | Usage extractor surfaced the correct result for 4/4 representative provider outputs (anthropic/openai/gemini + no-usage). Real executed worker runs surfacing usage: 0/354. |
| 12 | github_pr_provenance | MEASURED | 46.2 | 46.2 | 6/13 git-active runs have ledger-backed provenance. |
