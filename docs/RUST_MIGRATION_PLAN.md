# Rust Migration & Benchmark Target — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **This is a master plan.** Phase 0 is fully bite-sized and executable now. Phases 1–6 are each a self-contained sub-project: their file structure, interfaces, task breakdown, and acceptance criteria are concrete here, but each phase MUST be expanded into bite-sized TDD steps in its own plan document (`docs/superpowers/plans/`) at the start of that phase, because later-phase design depends on decisions locked in earlier phases. Writing speculative line-by-line steps for code five phases out would be guesswork.

**Goal:** Migrate the Python `sdlc` Secure SDLC control plane (16,385 LOC, 22 modules, 24 CLI subcommands) to a single self-contained Rust binary with field-identical gate behavior, plus six new subsystems (benchmark, quality-diff, self-improvement, provider abstraction, TUI, signed release pipeline), proven by benchmarks and an independent red-team.

**Architecture:** The Python implementation stays as the executable reference and parity oracle until every fixture passes. The Rust binary is built command-by-command behind a golden-output parity harness that diffs Rust output against `python -m sdlc` on all 23 `.sdlc/runs/` fixtures. Nothing is deleted until parity + rollback are proven. Governance artifacts (keys, privacy, CI, baseline) precede all code per the spec's mandatory ordering.

**Tech Stack:** Rust (edition 2021, pinned toolchain), `clap` (CLI), `serde`/`serde_json` (artifact parity), `ratatui` (TUI), `cargo-cyclonedx` (SBOM), GitHub Actions (release), GPG/Sigstore (signing), `insta` or custom golden-file harness (parity tests).

---

## Spec Coverage Map

Every Final Approval Condition (FAC 1–23) and Mandatory First Action (MFA 1–8) maps to a phase. No condition is unowned.

| Spec item | Phase |
|---|---|
| MFA 1–3 (read docs, run validate, run tests) | Phase 0 |
| MFA 4 KEYS.md / FAC 15 | Phase 0 |
| MFA 5 privacy.md / FAC 16 | Phase 0 |
| MFA 6 release.yml + RELEASE_PROCESS.md / FAC 17 | Phase 0 (stub) → Phase 6 (full) |
| MFA 7 baseline.json + ledger event / FAC 21 | Phase 0 |
| FAC 1 binary runs without Python, 4 platforms | Phase 1, Phase 6 |
| FAC 2 fixture parity (incl. attestation/deploy/hard-isolation) | Phase 2, Phase 3 |
| FAC 3 setup friction < 300s | Phase 4 (bench), Phase 6 |
| FAC 4 provider/model per role, ≥3 families | Phase 5 |
| FAC 5 `sdlc bench run` 12 dimensions | Phase 4 |
| FAC 6 `sdlc diff quality` + `sdlc bench compare` distinct | Phase 4 |
| FAC 7 hallucination controls, zero unsupported claims | Phase 3 (report parity), Phase 4 |
| FAC 8 TUI 8/10 independent | Phase 5 |
| FAC 9 CI-only assets, SBOM content-equality, reproducible, pinned toolchain | Phase 6 |
| FAC 10 GO_WITH_ACCEPTED_RESIDUAL_RISKS code-enforced | Phase 2 |
| FAC 11 25-gate pipeline before/after | Phase 2 |
| FAC 12 `sdlc learn record`, memory store 600/.gitignore/scan | Phase 4 |
| FAC 13 offline mode + atomic worker calls | Phase 3, Phase 5 |
| FAC 14 rollback plan + smoke artifact | Phase 1 (doc), Phase 6 (smoke) |
| FAC 18 rust-toolchain.toml pinned | Phase 0 |
| FAC 19 custom CLI execv + policy.json hash | Phase 5 |
| FAC 20 100x grep CI gate | Phase 6 |
| FAC 22 TUI tasks 9/10 both states | Phase 5 |
| FAC 23 diff-quality 12-field test | Phase 4 |

---

## File Structure (target Rust crate)

Files that change together live together. Split by responsibility, mirroring the Python module boundaries so parity is reviewable module-against-module.

```
Cargo.toml                  crate manifest, pinned deps
rust-toolchain.toml         pinned toolchain version (FAC 18)
src/
  main.rs                   clap entry, dispatch to command modules
  models.rs                 RunPlan, GateState, Finding, verdict enums  ⟵ sdlc/models.py
  ledger.rs                 events.jsonl, canonical digests, chain verify ⟵ sdlc/ledger.py
  pipeline.rs               25 gate definitions                         ⟵ sdlc/pipeline.py
  engine.rs                 gate state machine, final_verdict           ⟵ sdlc/engine.py
  policies.rs               policy profiles, thresholds                 ⟵ sdlc/policies.py
  classifier.rs             risk classification                         ⟵ sdlc/classifier.py
  release.rs                release readiness + preflight                ⟵ sdlc/release.py
  scanners.rs               scanner orchestration + normalization       ⟵ sdlc/scanners.py
  attestations.rs           manifest, HMAC sign/verify                  ⟵ sdlc/attestations.py
  deploy.rs                 locked deploy lifecycle                     ⟵ sdlc/deploy.py
  agents.rs                 role agents, parallel scheduler             ⟵ sdlc/agents.py
  adapters/                 worker adapters (one file per family)       ⟵ sdlc/adapters.py
    mod.rs                  WorkerAdapter trait, dispatch, fallback
    codex.rs claude.rs gemini.rs kimi.rs ollama.rs custom.rs
  prompts.rs                prompt rendering + SHA binding              ⟵ sdlc/prompts.py
  reporting.rs              final report generation                     ⟵ sdlc/reporting.py
  evidence.rs               validation-command detection                ⟵ sdlc/evidence.py
  briefing.rs               intake brief, standards mapping             ⟵ sdlc/briefing.py
  memory.rs                 episodic memory (mode 600)                  ⟵ sdlc/memory.py
  validation.rs             JSON-schema validation                     ⟵ sdlc/validation.py
  audit_runtime.rs          isolation preflight                         ⟵ sdlc/audit_runtime.py
  util.rs                   git, json io, redaction, hashing            ⟵ sdlc/util.py
  bench.rs                  NEW: 12-dimension benchmark harness
  diff.rs                   NEW: quality-diff (structural)
  learn.rs                  NEW: self-improvement loop
  tui.rs                    NEW: ratatui dashboard + --no-tui fallback
  update.rs                 NEW: signed auto-update
  cli/                      command handlers (one file per subcommand group) ⟵ sdlc/cli.py
    mod.rs init.rs plan.rs run.rs worker.rs redteam.rs scan.rs deploy.rs
    attest.rs agents.rs ledger.rs memory.rs finding.rs gate.rs git.rs
    tui.rs release.rs report.rs validate.rs bench.rs diff.rs learn.rs update.rs
tests/
  parity/                   golden-output harness vs python -m sdlc
  fixtures/                 symlink or copy of .sdlc/runs/
```

---

## Phase 0 — Prerequisites (executable now, no Rust source)

**Goal:** Satisfy MFA 4–8 and FAC 15, 16, 18, 21. These are governance/CI artifacts the spec requires *before* any Rust file.

**Files:**
- Create: `KEYS.md`
- Create: `privacy.md`
- Modify: `README.md` (link privacy.md)
- Create: `.github/workflows/release.yml`
- Create: `docs/RELEASE_PROCESS.md`
- Create: `rust-toolchain.toml`
- Create: `docs/ROLLBACK.md`
- Create: `artifacts/bench/baseline.json`
- Modify: `.gitignore` (memory store path)

### Task 0.1: Run the test suite to record true baseline

- [ ] **Step 1:** Run `python -m unittest discover -s tests 2>&1 | tail -20`
- [ ] **Step 2:** Record pass/fail count and any failures into `artifacts/bench/baseline.json` under `test_suite`. Expected: this is the reference test state; do not fix failures in Phase 0.

> NOTE: The user declined this run earlier. Confirm before running, or record `test_suite: "NOT RUN — declined"` honestly rather than fabricating a result. The spec forbids fabricated evidence.

### Task 0.2: KEYS.md

- [ ] **Step 1:** Create `KEYS.md` with: a placeholder key-holder identity table (name, role, GPG fingerprint or Sigstore identity — marked `<TO BE FILLED BY OPERATOR>`), key rotation procedure, key-compromise procedure. Mark clearly that the file is a template requiring a real fingerprint before any release asset is signed (FAC 15).
- [ ] **Step 2:** Commit `docs: add KEYS.md signing-key registry (template)`.

### Task 0.3: privacy.md + README link

- [ ] **Step 1:** Create `privacy.md` covering the four required points: (a) data that leaves the machine by default = none except operator-configured worker CLI calls; (b) data that leaves with consent; (c) consent record/revoke mechanism; (d) memory store retention (summaries + hashes, never raw prompts/secrets).
- [ ] **Step 2:** Add a `## Privacy` section to `README.md` linking `privacy.md` (FAC 16).
- [ ] **Step 3:** Commit `docs: add privacy.md and link from README`.

### Task 0.4: rust-toolchain.toml

- [ ] **Step 1:** Create `rust-toolchain.toml` with a specific version string, NOT `stable`:
```toml
[toolchain]
channel = "1.83.0"
components = ["rustfmt", "clippy"]
targets = ["aarch64-apple-darwin", "x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
```
- [ ] **Step 2:** Commit `build: pin Rust toolchain to 1.83.0` (FAC 18).

### Task 0.5: release.yml (stub) + RELEASE_PROCESS.md

- [ ] **Step 1:** Create `.github/workflows/release.yml` triggered only on `push` to `main` and tags `v*`; uses pinned runners `ubuntu-22.04` and `macos-14`; a `verify-toolchain` step that fails if active `rustc --version` ≠ `rust-toolchain.toml`; a guard step that fails the job if invoked from any ref other than `main`/`v*`. Build/sign steps are stubbed with `echo "implemented in Phase 6"` and `exit 1` so the workflow cannot produce a real asset yet.
- [ ] **Step 2:** Create `docs/RELEASE_PROCESS.md` documenting: release branch = `main`; branch-protection requiring one approving review from a non-author; the authorized-actor model; that `release.yml` is the only authorized build path (FAC 17).
- [ ] **Step 3:** Commit `ci: add release workflow skeleton and release process doc`.

### Task 0.6: ROLLBACK.md

- [ ] **Step 1:** Create `docs/ROLLBACK.md` with the four required parts: exact revert commands (reinstall Python pkg, repoint `sdlc` shim), backward-compat statement (`artifact_schema_version` gate — Python reads Rust artifacts iff version matches), <10-min smoke procedure, artifact-preservation check. Mark the smoke-test-evidence requirement (CI log / recording / non-implementer attestation, ledger-anchored) as a Phase 6 gate (FAC 14).
- [ ] **Step 2:** Commit `docs: add rollback plan`.

### Task 0.7: baseline.json + ledger event + .gitignore

- [ ] **Step 1:** Create `artifacts/bench/baseline.json` recording the *current measurable* state of the 12 benchmark dimensions. Dimensions with no tooling yet are recorded as `"UNAVAILABLE — no baseline tooling pre-migration"`, NOT fabricated scores. Include the current git commit hash.
- [ ] **Step 2:** Append ledger event `bench.baseline_recorded` with the commit hash, via the existing Python ledger (`python -m sdlc ledger ...` or direct append to the control-plane ledger used for self-runs). The event timestamp must precede the first Rust commit (FAC 21).
- [ ] **Step 3:** Add the memory store path (e.g. `.sdlc/memory.sqlite`) to `.gitignore`.
- [ ] **Step 4:** Commit `chore: record pre-migration benchmark baseline (ledger-anchored)`.

**Phase 0 acceptance:** KEYS.md, privacy.md (linked), rust-toolchain.toml, release.yml (guarded stub), RELEASE_PROCESS.md, ROLLBACK.md, baseline.json all exist and are committed; `bench.baseline_recorded` ledger event exists with a timestamp before any `*.rs` file. **Gate: no Rust source may be committed before this phase is complete (MFA 8).**

---

## Phase 1 — Cargo project + core models + parity harness skeleton

**Goal:** A compiling Rust binary that prints `--version`, plus serde types for `RunPlan`/`GateState`/`Finding` that round-trip every fixture's `plan.json`/`findings.json` byte-for-byte (modulo declared non-deterministic fields), plus the golden-output parity harness scaffolding. Satisfies the foundation of FAC 1, FAC 2.

**Files:** `Cargo.toml`, `rust-toolchain.toml` (exists), `src/main.rs`, `src/models.rs`, `src/util.rs`, `tests/parity/mod.rs`, `tests/parity/harness.rs`.

**Task-level breakdown (expand to bite-sized TDD at phase start):**
1. `cargo init --bin`; `Cargo.toml` with pinned `clap`, `serde`, `serde_json`, `sha2`, `hmac`.
2. `models.rs`: define enums (`Verdict`, `Severity`, `FindingStatus`) and structs matching `sdlc/models.py` exactly; `#[serde(rename_all=...)]` to match Python JSON casing. TDD: a test deserializing each fixture's `plan.json` and re-serializing must equal input (ignoring `non_deterministic`-tagged fields).
3. Parity harness: helper that runs `python -m sdlc <cmd>` and Rust equivalent, normalizes non-deterministic fields (timestamps, UUIDs, `elapsed_ms`), and asserts equality of the required parity fields from the spec.
4. `main.rs`: clap skeleton with all 24 subcommand names registered as no-ops returning "not yet implemented" so the surface matches Python.

**Phase 1 acceptance:** `cargo build` succeeds with pinned toolchain; `models.rs` round-trips all 23 fixtures' `plan.json` and `findings.json`; parity harness can invoke both binaries and diff normalized output.

---

## Phase 2 — Gate engine + pipeline + parity oracle

**Goal:** Port `pipeline.py` (25 gate defs), `engine.py` (state machine, deterministic gate checks, `final_verdict`), `policies.py`, `classifier.py` with field-identical verdicts on every fixture. Code-enforce FAC 10 (GO_WITH_ACCEPTED_RESIDUAL_RISKS never with open/accepted CRITICAL/HIGH). Satisfies FAC 2, 10, 11.

**Files:** `src/pipeline.rs`, `src/engine.rs`, `src/policies.rs`, `src/classifier.rs`, `tests/parity/engine_parity.rs`.

**Task-level breakdown:**
1. `pipeline.rs`: the 25 gates with id, owner, required artifacts, conditional logic. TDD against `pipeline.py` output.
2. `policies.rs` + `classifier.rs`: port profiles and risk classification; parity test feeds the same feature requests and asserts identical risk/flags/specialists.
3. `engine.rs` deterministic gate checks (repo context, baseline, supply chain, quality, scans, evidence traceability) — parity per fixture.
4. `engine.rs` `final_verdict`: implement and add a dedicated test asserting `GO_WITH_ACCEPTED_RESIDUAL_RISKS` is returned ONLY when no CRITICAL/HIGH finding has status other than RESOLVED — covering the `--human-override` attack from the spec (FAC 10).
5. Full-fixture parity sweep: for all 23 fixtures, Rust gate verdicts == Python, including attestation/deploy/hard-isolation fixtures (FAC 2).

**Phase 2 acceptance:** all 23 fixtures pass gate-verdict parity; `final_verdict` test proves the residual-risk rule at code level; 25-gate pipeline enumerates identically to Python.

---

## Phase 3 — CLI command parity (the 24 subcommands)

**Goal:** Port every subcommand handler with parity, including report generation with hallucination controls (EVIDENCE MISSING / UNAVAILABLE / UNVERIFIED markers), ledger integrity, release validation, attestations, deploy locks, and atomic worker calls. Satisfies FAC 2, 7, 13 (atomicity), and the bulk of `cli.py`.

**Files:** `src/cli/*.rs` (one per command group), `src/ledger.rs`, `src/release.rs`, `src/reporting.rs`, `src/attestations.rs`, `src/deploy.rs`, `src/scanners.rs`, `src/evidence.rs`, `src/briefing.rs`, `src/validation.rs`, `src/audit_runtime.rs`, `src/prompts.rs`, `tests/parity/cli_parity.rs`.

**Task-level breakdown (each command is its own bite-sized sub-plan):**
- Group A (read-only, easiest parity first): `validate`, `status`, `next`, `report`, `ledger`, `gate`, `finding`.
- Group B (evidence/provenance): `scan`, `attest`, `release`, `git`.
- Group C (execution, deferred to interplay with Phase 5 adapters): `worker`, `prompt`, `redteam`, `agents`, `isolation`, `deploy`.
- Group D (lifecycle): `init`, `plan`, `start`, `brief`, `memory`.
- Report parity must assert hallucination markers render exactly (FAC 7).
- Worker-call atomicity: a partial/interrupted worker response leaves the gate PENDING (FAC 13) — test with a simulated truncated response.

**Phase 3 acceptance:** every subcommand produces parity output on representative fixtures; report renders EVIDENCE MISSING / UNAVAILABLE / UNVERIFIED; release validation verdict matches Python on all fixtures; atomic-worker test passes.

---

## Phase 4 — Benchmark, quality-diff, self-improvement subsystems (NEW)

**Goal:** Build `sdlc bench run/compare/report` (12 scored dimensions), `sdlc diff quality` (12 structural fields), `sdlc learn record/suggest/apply` with secure memory store. Satisfies FAC 3, 5, 6, 12, 20, 21, 23.

**Files:** `src/bench.rs`, `src/diff.rs`, `src/learn.rs`, `src/cli/{bench,diff,learn}.rs`, `tests/bench_dimensions.rs`, `tests/diff_quality_fields.rs`, `tests/learn_memory_security.rs`.

**Task-level breakdown:**
1. `bench.rs`: implement all 12 dimensions as scorers (0–100), each emitting `UNAVAILABLE` honestly when unmeasurable. `bench run` writes `artifacts/bench/after.json`; `bench compare` diffs before/after; `bench report` emits json/md/html.
2. 100x rule: `bench report` must emit "100x superiority was not proven" unless a dimension shows measured ≥100x. (CI grep gate lands in Phase 6 — FAC 20.)
3. `diff.rs`: `sdlc diff quality <old> <new>` comparing all 12 structural fields. Add the FAC 23 test asserting all 12 named fields appear in output on a reference fixture pair. Keep distinct from `bench compare` (FAC 6).
4. `learn.rs` + `memory.rs`: record/suggest/apply; memory file mode 600; in `.gitignore`; store summaries+hashes only; strip artifact contents. Test: `detect-secrets` scan of the store passes; mode is 600 (FAC 12).

**Phase 4 acceptance:** `bench run` scores 12 dimensions; `diff quality` 12-field test passes; `bench compare` distinct and working; memory security test passes; 100x clause present unless proven.

---

## Phase 5 — TUI + provider abstraction (NEW)

**Goal:** `ratatui` TUI supporting the 10 benchmark tasks with `--no-tui` plain-text fallback and UNAVAILABLE banners; six worker families with per-role assignment, fallback chain, and secure custom-CLI invocation. Satisfies FAC 4, 8, 13 (offline), 19, 22.

**Files:** `src/tui.rs`, `src/cli/tui.rs`, `src/adapters/{mod,codex,claude,gemini,kimi,ollama,custom}.rs`, `tests/tui_tasks.rs`, `tests/provider_fallback.rs`, `tests/custom_cli_injection.rs`.

**Task-level breakdown:**
1. `adapters/mod.rs`: `WorkerAdapter` trait, dispatch, fallback chain, `WORKER_UNAVAILABLE` evidence on exhaustion (FAC 4). Per-role preferences from policy.
2. `adapters/custom.rs`: invoke via `execv` (no shell), prompt via stdin/temp file; require `policy.json` registration with SHA256 binary hash + `policy_approved`. Test: a prompt containing `$(...)`/backticks cannot execute (FAC 19).
3. `tui.rs`: implement all 10 tasks as navigable views; tasks 9 & 10 render a visible banner in both configured and UNAVAILABLE states (FAC 22); `--no-tui` fallback for all 10; works in 80-col; no-network degraded state.
4. Headless TUI test harness producing pass/fail output usable as independent-reviewer evidence (FAC 8).

**Phase 5 acceptance:** ≥3 worker families exercised in dry-run; custom-CLI injection test passes; TUI headless harness passes ≥8/10 with tasks 9/10 banner-tested in both states; `--no-tui` covers all 10.

---

## Phase 6 — Signed release pipeline + final self-run (NEW)

**Goal:** Make `release.yml` actually build, sign, SBOM, and reproducibly verify cross-platform binaries; wire `sdlc update apply` secure flow; run the tool's own 25-gate pipeline + benchmark + red-team on the migration; produce the comparison matrix. Satisfies FAC 1, 3, 9, 14, 17, 20, and the "tool runs its own pipeline" requirement.

**Files:** `.github/workflows/release.yml` (full), `src/update.rs`, `src/cli/update.rs`, `artifacts/bench/{after,diff,report.md,report.html,comparison_matrix.md}`, `tests/update_security.rs`.

**Task-level breakdown:**
1. Cross-compile 4 targets; code-sign + notarize macOS; emit SHA256SUMS + SHA256SUMS.sig + `sbom.cdx.json`.
2. SBOM content-equality check: every `Cargo.lock` package name+version appears in SBOM; CI fails otherwise (FAC 9).
3. Reproducible build: run build twice on same commit, `diff` SHA256SUMS; CI fails on mismatch (FAC 9).
4. `update.rs`: the 8-step secure auto-update (signature → checksum → temp → health → atomic rename → rollback on failure); domain-locked to github.com (FAC 13 distribution). Test in `update_security.rs`.
5. 100x CI grep gate over the final report (FAC 20).
6. Rollback smoke test on a clean machine producing a ledger-anchored artifact (FAC 14).
7. Self-run: `sdlc plan "ship sdlc binary v<next>" --risk high` → run → bench → agents → redteam → diff quality → bench compare → validate --release → report. Produce `comparison_matrix.md` with NOT MEASURED where unmeasured.
8. Independent red-team pass: GO or GO_WITH_ACCEPTED_RESIDUAL_RISKS with structured findings; no CRITICAL/HIGH closed by implementer.

**Phase 6 acceptance:** all 20 FAC + 23 sub-conditions green; reproducible build demonstrated; update security test passes; self-run produces a release-validated report; red-team verdict positive with evidence.

---

## Execution Notes

- **Parity-first discipline:** no command is "done" until its parity test is green against `python -m sdlc`. The Python tree is the oracle and is not deleted until Phase 6 acceptance + rollback smoke pass.
- **Commit cadence:** commit per task; feature branch + PR (never direct to `main` per AGENTS.md).
- **Each phase opens with its own bite-sized plan** in `docs/superpowers/plans/` before code, expanding the task-level breakdown above into TDD steps with exact code and commands.
- **Red-team between phases:** run the independent red-team agent at each phase boundary, not only at the end.
