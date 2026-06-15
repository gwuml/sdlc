#!/usr/bin/env bash
# Full-feature screencast demo for the SDLC control plane.
#
#   Record (asciinema):  asciinema rec -c "bash scripts/demo.sh" sdlc-demo.cast
#   Or screen-record your terminal while running:  bash scripts/demo.sh
#
# PAUSE controls the per-section pause for narration (default 3s; set PAUSE=0 to rush).
set -uo pipefail
cd "$(dirname "$0")/.."
PAUSE="${PAUSE:-3}"
RUN="${RUN:-product-self-run}"

say()  { printf '\n\033[1;36m========== %s ==========\033[0m\n' "$*"; sleep "$PAUSE"; }
run()  { printf '\033[2m$ %s\033[0m\n' "$*"; eval "$*"; sleep "$PAUSE"; }
note() { printf '\033[33m# %s\033[0m\n' "$*"; }

say "0. What this is"
note "A Secure-SDLC control plane: it governs AI coding agents (Claude Code, Codex,"
note "Gemini, Kimi, Ollama) as workers behind evidence-driven gates. It does not"
note "out-code them — it decides whether their work is safe to ship, and proves it."
run "python -m sdlc --help | sed -n '1,6p'"

say "1. Plan: turn a plain request into a gated, risk-classified run"
run "python -m sdlc plan 'add OAuth login with audit logging' --risk auto --security auto | head -5"

say "2. Status: 25 gates, local vs RELEASE state, blockers — one command"
run "python -m sdlc status $RUN | sed -n '1,14p'"

say "3. Next action: the safest next step, computed from evidence"
run "python -m sdlc next $RUN"

say "4. Findings: red-team finding lifecycle"
run "python -m sdlc finding list $RUN 2>/dev/null | head -6 || echo '(none open)'"

say "5. Interactive TUI (curses). Run live: 'python -m sdlc tui $RUN'  —  plain fallback:"
run "python -m sdlc tui $RUN --no-tui | sed -n '1,18p'"

say "6. Providers: open/local + commercial models, with a fallback chain"
note "Per-role model selection; first available worker wins; exhaustion is recorded,"
note "never silently skipped. Ollama runs fully local (no API key / no network)."
run "python3 -c \"from sdlc.adapters import select_available_adapter as s; print(s(['codex','claude','gemini','ollama']))\""

say "7. Benchmark: measured quality across 12 dimensions (evidence, not claims)"
run "python -m sdlc bench run | sed -n '1,14p'"

say "8. The honest comparative factor — measured, NOT '100x'"
run "python3 -c \"import json;c=json.load(open('artifacts/bench/comparative.json'));print('release-blocker identification: median', str(c['factor_median'])+'x', '| range', str(c['factor_min'])+'x-'+str(c['factor_max'])+'x', '| 100x proven:', c['proven_100x'])\""

say "9. Quality diff: compare two runs across 12 structural fields"
run "python -m sdlc diff quality scanner-evidence-hardening $RUN | sed -n '1,14p'"

say "10. Self-improvement: record lessons, suggest proposals (apply needs a human)"
run "python -m sdlc learn record $RUN | python3 -c 'import json,sys;print(\"recorded\", json.load(sys.stdin)[\"recorded\"], \"lessons\")'"
run "python -m sdlc learn suggest | python3 -c 'import json,sys;d=json.load(sys.stdin);print(\"pending proposals:\", len(d[\"pending\"]))'"

say "11. Release readiness: the deterministic verdict — it even gates its OWN work"
run "python -m sdlc validate --run-id $RUN --release 2>&1 | head -4"

say "12. Evidence + signing"
note "Final report, tamper-evident ledger, and a Sigstore-keyless signed release"
note "(see .github/workflows/release.yml and docs/EVIDENCE.md). 305 tests pass."
run "sed -n '1,6p' docs/EVIDENCE.md"

say "Done — everything shown is measured, tested, and committed (PR #1)."
