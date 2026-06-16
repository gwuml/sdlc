# Benchmark Report

Runs evaluated: 28
Measured dimensions: 12/12
**Headline score (CORPUS dimensions only): 75.2** — corpus-relative, not an absolute tool-quality constant.
Headline dimensions: 2_blocker_visibility, 3_evidence_completeness, 4_hallucination_count, 7_failed_tool_visibility, 12_github_pr_provenance

## Claim discipline

100x superiority was not proven. The headline averages only CORPUS dimensions
(observed over the real run corpus). CAPABILITY / CONFIG / CONSISTENCY /
ENVIRONMENT / ATTESTATION dimensions are reported but EXCLUDED from the headline
because they are near-constant, environment-specific, definitional, or
self-attested and would inflate it. Unmeasured dimensions are UNAVAILABLE.

## Dimensions

| # | Dimension | Status | Kind | Value | Score | In headline? | Detail |
|---|-----------|--------|------|-------|-------|--------------|--------|
| 1 | setup_friction | MEASURED | CAPABILITY | 0.199 | 100.0 | no | Cold `init` + first `plan` completed in 0.20s (target <300s). |
| 2 | blocker_visibility | MEASURED | CORPUS | 0.0019 | 100.0 | yes | Computed readiness and located first blocking gate (intake_scope) for run 'add-oauth-login-with-audit-logging-20260615-101934'. |
| 3 | evidence_completeness | MEASURED | CORPUS | 85.4 | 85.4 | yes | 258/302 executed gates across 28 runs carry evidence. |
| 4 | hallucination_count | MEASURED | CORPUS | 0 | 100.0 | yes | Scanned 19 reports; 0 unsupported claim candidates. |
| 5 | redteam_independence | MEASURED | CONFIG | 100.0 | 100.0 | no | 22/22 HIGH/EXTREME runs assign a red-team worker distinct from the implementer. |
| 6 | resume_recovery | MEASURED | CAPABILITY | 100.0 | 100.0 | no | 15/15 completed gates preserved across a resume re-run. |
| 7 | failed_tool_visibility | MEASURED | CORPUS | 44.4 | 44.4 | yes | 4/9 scan summaries surface tool status explicitly. |
| 8 | release_readiness_accuracy | MEASURED | CONSISTENCY | 100.0 | 100.0 | no | 28/28 runs: release verdict is consistent with blocker presence. |
| 9 | tui_task_completion | MEASURED | ATTESTATION | 80.0 | 80.0 | no | Independent reviewer (not the builder) attested APPROVED ('TUI looks great; proceed'); holistic sign-off credited at the 8/10 spec threshold (per-task rubric would refine this). |
| 10 | provider_flexibility | MEASURED | ENVIRONMENT | 4 | 100.0 | no | Worker CLIs on PATH: ['codex', 'claude', 'gemini', 'ollama'] (target >= 3). |
| 11 | cost_token_visibility | MEASURED | CAPABILITY | 100.0 | 100.0 | no | Usage extractor surfaced the correct result for 4/4 representative provider outputs (anthropic/openai/gemini + no-usage). Real executed worker runs surfacing usage: 0/354. |
| 12 | github_pr_provenance | MEASURED | CORPUS | 46.2 | 46.2 | yes | 6/13 git-active runs have ledger-backed provenance. |
