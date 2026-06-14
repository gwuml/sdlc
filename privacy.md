# privacy.md — Data Handling & Consent

This document states exactly what data the SDLC Control Plane handles, what (if
anything) leaves your machine, how consent is recorded and revoked, and what the
local memory store retains. It satisfies Final Approval Condition 16 and the
Consent & Privacy rules of the goal specification.

## (a) Data that leaves the machine by default

**None.** The control plane is local-first. By default it does not transmit prompts,
repository contents, run artifacts, findings, or telemetry to any network service.

The only outbound calls that can occur are those the operator explicitly configures:

- **Worker CLI invocations.** When you run a worker with `--execute` (e.g. the Codex,
  Claude, Gemini, Kimi, or Ollama CLI), the prompt is handed to that CLI, which is
  the operator's own installed tool. What that CLI transmits is governed by the
  operator's relationship with that provider — it is outside this tool's boundary.
  Local providers (Ollama, custom CLI) transmit nothing off-machine.
- **Security scanners.** `pip-audit` and `checkov` may contact their advisory
  databases when run. If the network is unavailable they are recorded as
  `UNAVAILABLE`, never silently skipped.
- **Auto-update.** `sdlc update check/apply` contacts GitHub Releases only
  (`github.com` / `objects.githubusercontent.com`), and only when you invoke it.

## (b) Data that leaves the machine only with explicit consent

- Standards-reference refresh from official sources (NIST/OWASP/SLSA) — disabled
  unless both policy and an explicit CLI flag allow network access.
- Any future telemetry — there is none today, and none may be added without an
  explicit opt-in recorded as a ledger event and documented in this file.

Repository contents are never uploaded to any cloud service by default.

## (c) How consent is recorded and revoked

- Local episodic memory is **opt-in or clearly disclosed at first use** with an
  explicit prompt.
- Each consent decision (enable memory, allow network standards refresh, enable any
  future telemetry) is recorded as a ledger event with actor and timestamp.
- Revocation: `sdlc memory disable` stops further writes; `sdlc memory delete --all`
  erases the store. Network/telemetry consents are revoked by flipping the
  corresponding policy flag, which is itself ledgered.

## (d) What the local memory store retains

The memory store (`.sdlc/memory.sqlite`) is for preference and audit support, not
surveillance. It retains **summaries and hashes, never raw prompt text, secrets, or
credentials**. Specifically:

- recurring gate blockers (pattern + count)
- repeated setup failures (step + error + count)
- model/provider performance (latency, success rate, per role)
- red-team finding patterns (area + severity)
- user-approved lessons (with timestamp and run reference)

Security properties (enforced and tested — FAC 12):

- File mode `600` (user-readable only).
- Excluded from version control via `.gitignore`; a warning is printed if staged.
- Scanned in CI by a secrets scanner on every build; a secret in the store fails
  the build.
- Records that reference a finding-ID or run-ID retain only metadata (ID, date,
  severity) — never the artifact contents.

The memory store never changes policy, bypasses gates, weakens safety rules, or
approves its own proposals.
