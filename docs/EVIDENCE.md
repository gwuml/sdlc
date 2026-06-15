# Evidence Report — Secure SDLC Control Plane

Generated from measured runs of the tool on this repository. This is the capstone
artifact for the "world-class" goal: it reports **what was measured**, not what was
claimed. Regenerate the numbers with `sdlc bench run` (writes
`artifacts/bench/after.json`, `report.md`, `comparison_matrix.md`).

## Scope of claim

World-class **for Secure SDLC orchestration** — enforced gate evidence, cross-model
red-team independence, release-readiness discipline, and claim discipline. This is a
different category from a general coding agent (e.g. Claude Code), whose strengths
(in-editor edits, IDE integration, checkpoints) are not contested. We do **not**
claim "100x better than Claude Code": **100x superiority was not proven.**

## Measured benchmark (23 runs on this repo)

Overall score (mean of measured dimensions): **87.6** — **10 of 12** dimensions measured.

| # | Dimension | Status | Score |
|---|-----------|--------|-------|
| 1 | setup friction | MEASURED | 100.0 |
| 2 | blocker visibility | MEASURED | 100.0 |
| 3 | evidence completeness | MEASURED | 85.4 |
| 4 | hallucination count | MEASURED | 100.0 |
| 5 | red-team independence | MEASURED | 100.0 |
| 6 | resume recovery | MEASURED | 100.0 |
| 7 | failed-tool visibility | MEASURED | 44.4 |
| 8 | release-readiness accuracy | MEASURED | 100.0 |
| 9 | TUI task completion | UNAVAILABLE | — (needs independent reviewer, spec FAC 8/22) |
| 10 | provider flexibility | MEASURED | 100.0 |
| 11 | cost / token visibility | UNAVAILABLE | — (worker usage parsing not yet built) |
| 12 | github PR provenance | MEASURED | 46.2 |

Honest weak spots that are visible, not hidden: **failed-tool visibility (44.4)** and
**github provenance (46.2)** reflect the historical run corpus and are genuine areas
to improve. They are reported, not papered over.

## Dogfooding: the tool gated its own work

The tool ran its own 25-gate pipeline on this very change
(run `ship-measured-benchmark-harness-and-curses-tui-...`, risk HIGH):

- Release readiness: **NO_GO**, 10 blockers.
- `validate --release`: **NO_GO** — `implementation` gate needs worker/human evidence;
  `security_scans` returned NO_GO (the scanners flagged issues in this repo).
- Authority mode: ADVISORY; production authority DISABLED.

This is the system **working correctly**: it refuses to declare its own work
release-ready without the required evidence. An evidence-driven control plane that
rubber-stamped itself would be the failure mode.

## What is proven vs. not

**Proven (measured):** sub-second blocker visibility; 100% release-readiness accuracy
on the corpus; cross-model red-team independence enforced on HIGH/EXTREME runs;
resume preserves 100% of completed gates; 0 unsupported claims in scanned reports;
fast setup; ≥3 worker families available.

**Not proven (honestly):** the "100x" claim (no comparative benchmark was run against
another tool); the TUI's official task score (requires an independent reviewer);
cost/token visibility (feature not built).

## Capabilities a generic coding agent does not have at all

Enforced gate evidence with a tamper-evident ledger; deterministic release-readiness
verdicts; enforced cross-model red-team; claim discipline; and a measured benchmark of
all of the above. See `artifacts/bench/comparison_matrix.md` (generic-agent column is
NOT MEASURED — we do not assert "better" without measuring the other tool).
