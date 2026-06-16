# Why this tool — and how it uses Claude Code, Codex, and open LLMs

This document states, with evidence discipline, where the SDLC control plane is
**better** than a general coding agent (Claude Code, Codex), and — more importantly —
how it **governs and combines** them rather than competing with them.

## The honest framing first

Claude Code and Codex are excellent *coding agents*: they edit files, run commands,
and integrate with your IDE. **This tool does not try to out-code them.** It is a
**control plane that sits above them** — it turns any of them (and open/local LLMs)
into governed *workers* inside an evidence-driven Secure SDLC pipeline.

So "better than Claude Code" is scoped precisely: better at **Secure SDLC
orchestration, evidence, and release discipline** — not at writing code. On a measured
same-task comparison (finding a run's release blockers) the advantage is **~5x typical,
up to 47x** (`artifacts/bench/comparative.json`); we do **not** claim "100x." The
sharper wins below are *categorical* — capabilities a coding agent does not have at all.

## 5 ways this tool is better (for Secure SDLC orchestration)

### 1. Enforced gates instead of vibes
A coding agent produces a diff and a confident summary. This tool runs a **25-gate
pipeline** where each gate has an owner, required artifacts, and a verdict computed
from evidence — not prose. A change cannot be called "done" until the gates say so.
*Coding agents have no gate model; the baseline score for this capability is zero.*

### 2. A tamper-evident evidence ledger
Every decision is appended to `events.jsonl` with **chained SHA-256 digests** and
optional HMAC origin signatures, so provenance is verifiable and tampering is
detectable. A coding agent's chat log is not provenance. *Category difference.*

### 3. Enforced cross-model red-team independence
For HIGH/EXTREME-risk work the tool **requires the red-team reviewer to be a different
model than the implementer** — measured at 100% on HIGH/EXTREME runs
(`sdlc bench`, dimension 5). A single agent reviewing its own output repeats its own
blind spots; this tool structurally prevents that.

### 4. Deterministic release-readiness verdicts
The tool computes **GO / NO_GO / GO_WITH_ACCEPTED_RESIDUAL_RISKS** from evidence, and
it even refuses to pass its own work without it (it gated this very project NO_GO — see
`docs/EVIDENCE.md`). A coding agent has no concept of release readiness. It also closes
a real loophole: a CRITICAL/HIGH finding can **never** be accepted into a positive
verdict — it must be fixed (FAC-10 hardening).

### 5. Claim discipline (no unsupported claims ship)
Reports may not assert "production-ready / secure / compliant / 100x" without linked
evidence; the benchmark even greps for unsupported "100x" claims. This is why this very
project reports its real ~5x factor instead of a slogan. *A coding agent will happily
write "production-ready" with nothing behind it.*

## How it integrates Claude Code, Codex, and open LLMs

The tool treats every model as a **worker family** assigned to an SDLC **role**. You
pick which model does which job, and the orchestrator enforces permissions, isolation,
and independence.

```
policy.agents.role_worker_preferences:
  pm:           ["claude", "gemini"]      # Claude Code as planner
  architect:    ["codex", "claude"]
  implementer:  ["codex"]                 # Codex writes code
  red_team:     ["claude", "gemini"]      # MUST differ from implementer (HIGH/EXTREME)
  qa:           ["codex", "gemini"]
  sre:          ["claude", "kimi"]
```

Supported worker families:

| Family | CLI | Use |
|--------|-----|-----|
| Claude Code | `claude` | planning, architecture, red-team |
| Codex | `codex` | implementation, QA |
| Gemini | `gemini` | review, red-team independence |
| Kimi | `kimi` | additional cross-model diversity |
| **Open / local LLMs** | `ollama run <model>` | air-gapped/offline workers, zero API cost |
| **Custom** | any CLI (policy-approved, hashed, `execv` no-shell) | bring-your-own model |

What the integration adds on top of the raw agents:

- **Per-role model selection** — best model per job, not one model for everything.
- **Cross-model red-team** — Codex implements, Claude/Gemini attacks. Diversity catches
  what monoculture misses.
- **Fallback chains** — if a provider is unavailable, the next is tried; exhaustion is
  recorded as `WORKER_UNAVAILABLE`, never silently skipped.
- **Cost/token visibility** — usage is extracted from each worker's output
  (Anthropic/OpenAI/Gemini formats) and surfaced, or marked UNAVAILABLE (`sdlc/usage.py`).
- **Open-LLM and offline support** — Ollama workers run fully local; dry-run gates,
  status, benchmark, and the TUI all work with no network.
- **Isolation** — workers run with an env allowlist, output redaction, and (optionally)
  hard sandbox/container isolation; they cannot mutate the control-plane ledger.

### The one-line pitch
**Claude Code and Codex make changes. This tool decides whether those changes are safe
to ship — and proves it.** It doesn't replace your coding agent; it puts a measured,
auditable, multi-model governance layer around it, including open/local models.

## Evidence behind every claim here
- Benchmark: `artifacts/bench/after.json` (headline 75.2 — mean of CORPUS dimensions
  only, corpus-relative; per-kind breakdown in `docs/EVIDENCE.md`)
- Comparative factor: `artifacts/bench/comparative.json` (~5x median, 3–47x)
- Comparison matrix: `artifacts/bench/comparison_matrix.md`
- Dogfooding verdict: `docs/EVIDENCE.md`
- We do not assert a head-to-head "better at coding" — that column is NOT MEASURED.
