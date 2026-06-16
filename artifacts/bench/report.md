# Benchmark Report

Runs evaluated: 4
Measured dimensions: 8/12
**Headline score (CORPUS dimensions only): 87.5** — corpus-relative, not an absolute tool-quality constant.
Headline dimensions: 2_blocker_visibility, 3_evidence_completeness, 7_failed_tool_visibility, 12_github_pr_provenance

## Claim discipline

100x superiority was not proven. The headline averages only CORPUS dimensions
(observed over the real run corpus). CAPABILITY / CONFIG / CONSISTENCY /
ENVIRONMENT / ATTESTATION dimensions are reported but EXCLUDED from the headline
because they are near-constant, environment-specific, definitional, or
self-attested and would inflate it. Unmeasured dimensions are UNAVAILABLE.

## Dimensions

| # | Dimension | Status | Kind | Value | Score | In headline? | Detail |
|---|-----------|--------|------|-------|-------|--------------|--------|
| 1 | setup_friction | UNAVAILABLE | UNAVAILABLE | — | — | no | init/plan failed (init rc=1, plan rc=1). |
| 2 | blocker_visibility | MEASURED | CORPUS | 0.0468 | 100.0 | yes | Computed readiness and located first blocking gate (intake_scope) for run 'fac10-accepted-critical'. |
| 3 | evidence_completeness | MEASURED | CORPUS | 100.0 | 100.0 | yes | 95/95 executed gates across 4 runs carry evidence. |
| 4 | hallucination_count | UNAVAILABLE | UNAVAILABLE | — | — | no | No final reports present to scan. |
| 5 | redteam_independence | MEASURED | CONFIG | 100.0 | 100.0 | no | 3/3 HIGH/EXTREME runs assign a red-team worker distinct from the implementer. |
| 6 | resume_recovery | UNAVAILABLE | UNAVAILABLE | — | — | no | init failed during resume measurement. |
| 7 | failed_tool_visibility | MEASURED | CORPUS | 100.0 | 100.0 | yes | 4/4 scan summaries surface tool status explicitly. |
| 8 | release_readiness_accuracy | MEASURED | CONSISTENCY | 100.0 | 100.0 | no | 4/4 runs: release verdict is consistent with blocker presence. |
| 9 | tui_task_completion | UNAVAILABLE | UNAVAILABLE | — | — | no | TUI task completion is not auto-scored: independent-reviewer verification is not implemented, so it cannot be trusted as a measured score. No reviewer attestation on file. |
| 10 | provider_flexibility | MEASURED | ENVIRONMENT | 4 | 100.0 | no | Worker CLIs on PATH: ['codex', 'claude', 'gemini', 'ollama'] (target >= 3). |
| 11 | cost_token_visibility | MEASURED | CAPABILITY | 100.0 | 100.0 | no | Usage extractor surfaced the correct result for 4/4 representative provider outputs (anthropic/openai/gemini + no-usage). No executed worker runs in corpus — this scores the extractor mechanism, not real coverage. |
| 12 | github_pr_provenance | MEASURED | CORPUS | 50.0 | 50.0 | yes | 2/4 git-active runs have ledger-backed provenance. |
