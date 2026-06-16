# Comparison Matrix (evidence-backed only)

Scope: Secure SDLC orchestration. This is NOT a general-coding-agent comparison.
Claude Code's strengths (terminal-native edits, IDE integration, checkpoints) are
not denied; they are a different category. We only fill cells we actually measured.

| Dimension | This tool | Generic coding agent | Evidence / note |
|-----------|-----------|----------------------|-----------------|
| Setup friction (s) | 0.199 (score 100.0) | NOT MEASURED | architecture: local-first, single CLI |
| Blocker visibility (s) | 0.0019 (score 100.0) | NOT MEASURED | generic agents have no gate model |
| Evidence completeness (%) | 85.4 (score 85.4) | NOT MEASURED | no gate-evidence ledger in generic agents |
| Unsupported claims in report | 0 (score 100.0) | NOT MEASURED | no claim-discipline gate in generic agents |
| Red-team independence (%) | 100.0 (score 100.0) | NOT MEASURED | no enforced cross-model red-team |
| Release-readiness accuracy (%) | 100.0 (score 100.0) | NOT MEASURED | no release-verdict engine |
| Provider flexibility (families) | 4 (score 100.0) | NOT MEASURED | varies by agent |

## Measured factor: identifying release blockers

Task: find the release blockers and their reasons for a run. Metric: artifacts inspected to identify release blockers + reasons (manual baseline) vs 1 tool command.

- Tool: **1 command**.
- Manual baseline (conservative): **4.0x** more inspection units (median across 28 runs; range 3x–47x).
- **100x proven on this metric: NO.** The honest factor is the median above, not 100x.

_Conservative steps proxy; under-counts manual effort (excludes re-deriving validation rules). Not wall-clock; not a measurement of any other product._

## Capability differences (category, not a ratio)

A raw-artifact baseline or generic coding agent cannot produce these at all,
so they are reported as present/absent, never as a finite multiple:

- Deterministic release-readiness verdict (GO/NO_GO) computed from evidence
- Tamper-evident gate-evidence ledger with chained digests
- Enforced cross-model red-team independence on HIGH/EXTREME runs
- Claim-discipline gate blocking unsupported release claims
- Per-gate release-blocking reasons without manual rule re-derivation

## Honest position

- We do not claim '100x better than Claude Code'. 100x superiority was not proven.
- The measured advantage on release-blocker identification is the factor above
  (a conservative same-task steps proxy), plus capabilities a generic agent lacks
  entirely.
- The generic-agent column stays NOT MEASURED until we run an equivalent benchmark
  against one; asserting 'better' without that would violate claim discipline.
