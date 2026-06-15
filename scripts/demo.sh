#!/usr/bin/env bash
# Screencast demo for the SDLC control plane.
#
#   Record with asciinema:  asciinema rec -c "bash scripts/demo.sh" sdlc-demo.cast
#   Or just run it and screen-record your terminal:  bash scripts/demo.sh
#
# Each section pauses (set PAUSE=0 to disable) so a narrator can speak.
set -euo pipefail
cd "$(dirname "$0")/.."
PAUSE="${PAUSE:-2}"
RUN="${RUN:-product-self-run}"

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; sleep "$PAUSE"; }
run() { printf '\033[2m$ %s\033[0m\n' "$*"; eval "$*"; sleep "$PAUSE"; }

say "1. The control plane governs AI workers — it does not replace them"
run "python -m sdlc --help | sed -n '1,8p'"

say "2. Plan a gated, risk-classified run from a plain request"
run "python -m sdlc plan 'add OAuth login with audit logging' --risk auto --security auto | head -6"

say "3. Status: 25 gates, local vs RELEASE state, blockers — in one command"
run "python -m sdlc status $RUN | sed -n '1,12p'"

say "4. The interactive TUI (plain fallback shown; run 'sdlc tui $RUN' live for curses)"
run "python -m sdlc tui $RUN --no-tui | sed -n '1,20p'"

say "5. Measured benchmark — 12 dimensions, evidence not claims"
run "python -m sdlc bench run | sed -n '1,14p'"

say "6. The honest comparative factor (NOT 100x) and category capabilities"
run "sed -n '/Measured factor/,/present.absent/p' artifacts/bench/comparison_matrix.md"

say "7. The tool gates its OWN work — and reports the real numbers"
run "sed -n '1,12p' docs/EVIDENCE.md"

say "Demo complete. Everything shown is measured and committed (PR #1)."
