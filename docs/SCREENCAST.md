# Screencast Guide

A ~4-minute scene-by-scene script to record a demo of every feature. Pairs with
`scripts/demo.sh` (which prints each command) and `docs/DEMO.md` (captured output).

## Setup

```bash
# Option A — terminal cast (shareable, tiny):
asciinema rec -c "bash scripts/demo.sh" sdlc-demo.cast
# play/share:  asciinema play sdlc-demo.cast   |   asciinema upload sdlc-demo.cast

# Option B — video: start your screen recorder, then:
PAUSE=4 bash scripts/demo.sh        # 4s pauses give you time to narrate

# Show the interactive TUI live (curses) separately — it can't be captured by the script:
python -m sdlc tui product-self-run     # Tab=panels, ↑/↓=scroll, g=next blocker, q=quit
```

Use an 80×24+ terminal, a light-on-dark theme, and a large font.

## Scenes (what to show / what to say)

| # | On screen | Say (≈) | ~sec |
|---|-----------|---------|------|
| 0 | `sdlc --help` | "This is a Secure-SDLC control plane. It governs AI coding agents — Claude Code, Codex, Gemini, Kimi, local Ollama — as workers behind evidence-driven gates. It doesn't out-code them; it decides whether their work is safe to ship, and proves it." | 25 |
| 1 | `sdlc plan '…' --risk auto` | "Any plain request becomes a risk-classified run with a 25-gate pipeline. High-risk work activates security and red-team roles automatically." | 20 |
| 2 | `sdlc status` | "One command shows all 25 gates, each with its local state and its *release* state, plus the blocker count. Local-GO does not mean release-ready — the tool keeps them distinct." | 25 |
| 3 | `sdlc next` | "It computes the single safest next action from evidence — no guessing." | 15 |
| 4 | `sdlc finding list` | "Red-team findings have a real lifecycle; CRITICAL/HIGH can't be closed by the implementer or accepted away — they must be fixed." | 15 |
| 5 | `sdlc tui …` (LIVE) | "The interactive dashboard: Tab between panels, arrow-scroll gates, press g to jump to the next blocking gate. Tasks it can't do — resume, GitHub, cost — show explicit UNAVAILABLE banners, never blank." | 30 |
| 6 | provider `select_available_adapter` | "Per-role model selection with a fallback chain. First available worker wins; if none are available it records WORKER_UNAVAILABLE — never a silent skip. Ollama runs fully local, no API key." | 25 |
| 7 | `sdlc bench run` | "Measured quality across 12 dimensions — evidence, not adjectives. Overall 88. The two low scores are real, visible weak spots, reported honestly." | 25 |
| 8 | comparative factor | "And the honest headline: on finding release blockers it's a measured ~4–47x fewer steps — not '100x'. The tool refuses to claim 100x because it isn't proven." | 20 |
| 9 | `sdlc diff quality` | "Compare any two runs across 12 structural fields — gate changes, blockers added/removed, findings, verdict. Regression detection for governance." | 20 |
| 10 | `sdlc learn record / suggest` | "It learns from runs — recurring blockers become suggestions. But it never approves its own proposals or changes policy; a human applies them." | 20 |
| 11 | `sdlc validate --release` | "The deterministic release verdict. It even gates its *own* work NO_GO until evidence exists — an evidence engine that rubber-stamped itself would be the failure mode." | 25 |
| 12 | `docs/EVIDENCE.md` + `release.yml` | "Everything is backed by a tamper-evident ledger and shipped through a Sigstore-keyless signed release. 305 tests pass." | 20 |

**Closing line:** "Claude Code and Codex make changes. This tool decides whether those changes are safe to ship — and proves it with measured evidence."

## One honesty note for the narration
Don't say "100x better than Claude Code." Say "categorically does things a coding agent
doesn't — gates, evidence ledger, release verdicts — plus a measured multiple on
specific tasks." That's the claim the evidence supports.
