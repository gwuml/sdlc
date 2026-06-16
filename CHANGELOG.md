# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [0.2.0] — 2026-06-16

Audit-remediated release. An independent brutal red-team returned **GO** (zero findings)
on a clean clone after this work.

### Added
- `sdlc bench run/compare/report` — measured 12-dimension benchmark; headline averages
  only CORPUS dimensions and is corpus-relative (with a committed reference-corpus
  fallback for clean-clone reproducibility).
- `sdlc diff quality <old> <new>` — structural quality diff across 12 fields.
- `sdlc learn record/suggest/apply` — conservative self-improvement loop (no
  self-approval, no policy mutation).
- Provider abstraction: Ollama (open/local) adapter + worker fallback chain that records
  `WORKER_UNAVAILABLE` instead of silently skipping.
- Cost/token usage extraction (Anthropic/OpenAI/Gemini) surfaced on worker results.
- Interactive curses TUI (`sdlc tui`) with `--no-tui` plain fallback.
- Signed release pipeline: CycloneDX SBOM + Sigstore-keyless signature; CI test gate.
- Docs: `USAGE.md`, `FEATURE_GATE_MAP.md`, `WHY_THIS_TOOL.md`, `EVIDENCE.md`,
  `SESSION_AUDIT_PROMPT.md`, `LICENSE`, `CONTRIBUTING.md`, `SECURITY.md`.
- Rust foundation (library): models + 25-gate pipeline + `final_verdict` at parity.

### Changed / Fixed
- **FAC-10 enforced in the Python runtime** (not just Rust): an ACCEPTED/DEFERRED
  CRITICAL/HIGH finding now yields NO_GO; only MEDIUM and lower may be accepted as
  residual risk.
- Ledger canonical hash-chain integrity is checked in **every** `validate` mode
  (default and `--structural-only`), not only `--release`.
- `redact_secrets` hardened for PEM/PuTTY `.ppk`/SSH2/JWK private-key material.
- Removed an orphaned `audit session` subcommand whose module was never committed.
- Benchmark headline reframed from an inflated "88.0/12-of-12" to an honest,
  kind-classified, corpus-relative score.

## [0.1.0]

- Initial Secure-SDLC control plane: 25-gate pipeline, risk classifier, finding
  lifecycle, worker adapters, deterministic gates, release validation, attestations,
  locked deployment, final report.
