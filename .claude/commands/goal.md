# /goal — Secure SDLC Control Plane: Rust Migration & Benchmark Target

## What This Is

This is a specification for what must be built — not a description of what currently
exists. The implementation starts from scratch. The absence of implementation is
expected; the absence of these requirements being met blocks release.

A goal is not a claim. This document defines measurable targets, approval conditions,
and anti-patterns for the Rust migration of the Secure SDLC Control Plane.

"World-class" is not a prompt adjective. It is an evidence target.

The tool is world-class for Secure SDLC orchestration — not generic coding chat —
only when benchmarks prove it, not when prompts say so.

---

## Mandatory First Actions

These must be completed and ledgered before any Rust source file is created.

1. Read `AGENTS.md`, `README.md`, `docs/WORLD_CLASS_CONTROL_PLANE_PROMPT.md`.
2. Run `python -m sdlc validate --run-id production-grade-release-blockers --release`.
3. Run `python -m unittest discover -s tests`.
4. Create `KEYS.md` with at least one pre-registered key fingerprint (GPG or Sigstore)
   and the key holder's identity. Document key rotation and compromise procedures.
   This file must exist before any release asset is signed.
5. Create `privacy.md` documenting: (a) what data leaves the machine by default;
   (b) what data leaves the machine with user consent; (c) how consent is recorded
   and revoked; (d) what the memory store retains. Reference it from `README.md`.
6. Commit a GitHub Actions release workflow (`release.yml`) that:
   - Triggers only on pushes to the `main` branch or tags matching `v*` from `main`.
   - Uses pinned runner versions (`ubuntu-22.04` and `macos-14`), not floating labels
     (`ubuntu-latest`, `macos-latest`). Floating labels violate the byte-identical
     reproducibility requirement if the runner OS changes between builds.
   - Fails if any build step is skipped or the toolchain version does not match
     `rust-toolchain.toml`.
   - Is the only authorized path to producing release assets. No release asset may
     be built on a developer laptop.
   - Documents the release branch name (`main`) and protection configuration in
     `docs/RELEASE_PROCESS.md`.
7. Record current baseline scores in `artifacts/bench/baseline.json`. Append a ledger
   event `bench.baseline_recorded` with the current Git commit hash. The ledger event
   timestamp must predate the first Rust commit in Git history — this is verified at
   release time.
8. Do not implement any Rust code until steps 1-7 are complete and ledgered.

---

## Authorized Actor Definition

"Authorized actor" means a human or CI identity that is:

- Not the author of the commit, finding, or implementation being reviewed.
- Named in `CODEOWNERS` with `@reviewer` on the relevant path, OR
- A GitHub branch protection required reviewer on the release branch, OR
- A named human in `KEYS.md` with a Sigstore or GPG-attested identity.

Enforcement mechanism: the release branch must have GitHub branch protection requiring
at least one approved review from an account that did not author the commit. This must
be documented in `docs/RELEASE_PROCESS.md` and verified by the red-team as part of
the distribution approval condition.

Actor identity is verified by HMAC-signed actor proof. The
`actor_proof_required_for_finding_closure` policy flag is ON by default. Disabling
it requires a policy override recorded in the ledger with an authorized actor signature.
An actor string passed via `--closed-by` without a corresponding HMAC proof is
rejected. This prevents string-impersonation: no caller can pass
`--closed-by human_release_manager` without possessing the HMAC key.

An implementer cannot close their own CRITICAL/HIGH findings. CI cannot close findings
unless it is configured as a separate named authorized identity in `CODEOWNERS` with
explicit policy allowance. Granting CI that allowance requires approval from a named
human in `KEYS.md` who is not the implementer, recorded as a ledger event before the
allowance takes effect. A CI identity may not self-grant closing authority for
findings where the implementer who created them controls the CI configuration.

---

## Target: Rust Binary

Migrate from `python -m sdlc` to a single compiled Rust binary `sdlc`.

The binary must:

- Run without Python, pip, venv, or any Python dependency present.
- Ship as a self-contained release asset (macOS arm64, macOS x86_64, Linux x86_64,
  Linux aarch64).
- Be code-signed and notarized on macOS.
- Include SHA256 checksums, a GPG or Sigstore signature over SHA256SUMS, and a
  machine-readable SBOM in every GitHub Release.
- Support auto-update with explicit user consent: `sdlc update check`, `sdlc update apply`.
- Work offline: all 25 gates must be inspectable; dry-run gates must execute; scanners
  that are unavailable must be marked unavailable, not silent.
- Produce field-identical gate output to the Python reference implementation on all
  test fixtures (parity test suite required — see Parity Test Specification below).
- Be installable by an intern in under 5 minutes from a fresh macOS or Linux machine
  without prior knowledge of the tool (setup friction benchmark required).

### Parity Test Specification

The Rust binary must produce identical values for the following fields compared to the
Python reference on every `.sdlc/runs/` fixture:

Required matches (exact equality):
- `gate.gate_id`
- `gate.verdict` (PASS / NO_GO / PENDING / SKIPPED)
- `gate.blocker` (null or blocker reason string)
- `finding.id`
- `finding.severity`
- `finding.status`
- `finding.evidence.artifact_path`
- `ledger.event_count` (total events per gate)

Exempt from exact match (non-deterministic fields):
- `gate.elapsed_ms`
- `finding.created_at` / `finding.updated_at`
- `ledger.event_id` (UUID)
- Any field explicitly tagged `non_deterministic: true` in the fixture manifest

PENDING gates in fixtures: a gate that was PENDING in the Python fixture must also
be PENDING in the Rust output. It is not acceptable for the Rust binary to compute
a verdict for a gate that was unexecuted in the reference run.

### Rollback Plan (Required Before Release)

A testable rollback plan must be documented at `docs/ROLLBACK.md` before the first
Rust binary is evaluated. It must include:

1. Exact shell commands to revert from Rust binary to Python in-place.
2. A statement on backward compatibility: can the Python implementation read
   artifacts produced by the Rust binary? If not, which artifact formats diverge
   and what migration command converts them?
3. A smoke test procedure that an on-call engineer can run in under 10 minutes to
   confirm the rollback was successful.
4. Verification that existing `.sdlc/runs/` artifacts are preserved and readable
   after rollback.

The rollback plan must be smoke-tested on a clean machine before Final Approval
Condition 14 can be satisfied. The smoke test must produce a verifiable artifact:
a CI log, a screen recording with timestamps, or a signed attestation from an
authorized actor who is not the implementer. This artifact must be ledger-anchored
(`rollback.smoke_test_completed` event) before condition 14 is checked. Self-attestation
by the implementer does not satisfy this requirement.

### Migration Risk Controls

- The Python implementation is the reference. It must not be deleted or deprecated
  until parity is proven on all test fixtures and the rollback plan is smoke-tested.
- A fixture compatibility test must run the Rust binary against every existing
  `.sdlc/runs/` fixture and compare the required parity fields above.
- A data-format version field (`artifact_schema_version`) must be present in all
  run artifacts so the Rust binary can detect and reject or migrate artifacts from
  incompatible Python versions.

---

## Benchmark Layer (Required Before Release)

Implement three benchmark commands:

```
sdlc bench run [--suite <name>]
sdlc bench compare --before <artifact> --after <artifact>
sdlc bench report [--format json|md|html]
```

`sdlc bench compare` operates on **scored benchmark dimension artifacts** (the 12
dimensions below). It is distinct from `sdlc diff quality`, which operates on
structural run fields. Both are required. Neither substitutes for the other.

### Benchmark Dimensions (all required, all scored 0–100)

1. **Setup friction** — time from clean machine to first successful `sdlc start`,
   measured in seconds; target under 300s; record actual time or UNAVAILABLE.
   The target may be revised upward to at most 600s if evidence shows the 300s target
   is unachievable, with a written rationale approved by a named reviewer (not the
   implementer).
2. **Blocker visibility** — seconds to identify next blocking gate from `sdlc status`;
   target under 5s; record actual time or UNAVAILABLE.
3. **Evidence completeness (executed gates)** — percentage of executed (non-PENDING)
   gates with substantive, typed, ledger-backed evidence; target 100% for dry-run gates,
   ≥ 80% for executed gates with at least one worker run.
4. **Hallucination count** — number of unsupported claims in the final report (claims
   with no linked evidence artifact, ledger event, or human acceptance); target 0.
5. **Red-team independence** — percentage of HIGH/EXTREME risk runs with cross-model
   review enforced; target 100%.
6. **Resume recovery** — percentage of interrupted runs that resume correctly from the
   last completed gate without data loss; target 100%.
7. **Failed tool visibility** — percentage of failed scanners/workers/models that appear
   visibly in status and report (not silently skipped); target 100%.
8. **Release-readiness accuracy** — percentage of `release validate` verdicts that match
   the ground-truth state of the run (gate blockers present = NO_GO); target 100%.
9. **TUI task completion** — percentage of 10 benchmark TUI tasks completable without
   docs by an independent reviewer who did not implement the TUI; target 80% unaided,
   100% with docs.
10. **Provider flexibility** — number of worker families (Codex, Claude, Gemini, Kimi,
    local Ollama, custom CLI) successfully used in a role-assigned dry-run; target ≥ 3.
11. **Cost/token visibility** — percentage of executed worker runs with cost or token
    estimate shown, or UNAVAILABLE stated explicitly; target 100%.
12. **GitHub PR provenance** — percentage of PR/commit/CI evidence records with ledger
    event chain and Git hash; target 100% when GitHub is used.

### Benchmark Artifacts (all required)

```
artifacts/bench/baseline.json       — pre-change scores (ledger-anchored)
artifacts/bench/after.json          — post-change scores
artifacts/bench/diff.json           — delta per dimension
artifacts/bench/report.md           — human-readable comparison
artifacts/bench/report.html         — static HTML, no external deps
artifacts/bench/comparison_matrix.md — evidence-backed comparison vs generic agents
```

100x superiority rule: the final report must say "100x superiority was not proven"
unless a specific dimension shows at least 100x improvement with a measured before
and after value. Do not claim 100x improvement without a benchmark showing it.

---

## Quality Diff Tool (Required)

Implement:

```
sdlc diff quality <old-run-id> <new-run-id>
```

This tool compares **structural run fields** between two runs. It is not the same as
`sdlc bench compare`, which scores benchmark dimensions. Both are required.

`sdlc diff quality` must compare:

- gate states (per gate: old verdict → new verdict)
- evidence coverage (per gate: evidence artifact count and type)
- finding lifecycle (opened, closed, accepted, deferred — counts and IDs)
- release blockers (removed, added, unchanged)
- unsupported-claim count (delta)
- scanner coverage (which scanners ran vs were unavailable)
- red-team findings (count, severity, new vs resolved)
- prompt overrides (if any custom prompts were used)
- provider/model choices (per role agent)
- cost/token usage (if available, or UNAVAILABLE)
- elapsed time per gate
- final verdict (old → new)

Output formats: `--format json|md` required; `--format html` optional.

---

## Hallucination Controls (Non-Negotiable)

These rules apply to all model outputs, reports, and status views:

- Model outputs are proposals. The orchestrator is the authority. Gate verdicts are
  computed from evidence, not from model prose.
- Every factual claim in a final report must link to: an evidence artifact path,
  a ledger event ID, a scanner result hash, or an explicit human acceptance record
  with actor and timestamp.
- Missing evidence must be shown as "EVIDENCE MISSING" — not omitted, not inferred.
- Failed tools must appear as "SCANNER UNAVAILABLE" or "WORKER FAILED" — not silently
  skipped.
- Unavailable cost/token data must appear as "COST UNAVAILABLE" — not omitted.
- Provider and model claims (e.g. "reviewed by claude-3-opus") must be verified by
  setup doctor or adapter response metadata. Unverified claims appear as "UNVERIFIED".
- Release-readiness is computed deterministically from gate evidence. It is not
  summarized by a model.
- Prompt customization via `.sdlc/prompts/` overrides cannot remove mandatory safety
  text (red-team requirements, evidence requirements, claim-discipline rules).
- Red-team findings must be parsed into structured Finding records. Prose summaries
  without structured findings do not satisfy the red-team gate.
- CRITICAL/HIGH findings block approval until independently validated and closed by
  an authorized actor other than the implementer (see Authorized Actor Definition above).

---

## Self-Improvement Loop (Required)

Implement:

```
sdlc learn record <run-id>
sdlc learn suggest
sdlc learn apply --proposal <id> --execute
```

What learning may record:

- recurring gate blockers (pattern + count)
- repeated setup failures (step + error + count)
- model/provider performance (latency, success rate, per-role)
- red-team finding patterns (recurring attack area + severity)
- flaky check results (scanner + expected vs actual)
- user-approved lessons (explicit accept, with timestamp and run reference)

What learning must not do:

- store secrets, credentials, raw prompts, or API keys
- silently change policy thresholds
- bypass gates or weaken evidence requirements
- approve its own proposals (human or authorized CI must approve)
- weaken safety rules or red-team independence
- transmit data externally without explicit policy and user consent

### Memory Store Security

Memory store files must:

- Be stored with filesystem mode `600` (user-readable only).
- Be excluded from version control in `.gitignore` with a warning printed if staged.
- Be validated in CI by a secrets scanner (e.g., `trufflehog`, `detect-secrets`) on
  every build. A secret found in the memory store fails the build.
- Store summaries and hashes, not raw prompt text.
- Strip any field referencing a finding-ID or run-ID of artifact file contents before
  storage — only metadata (ID, date, severity) is retained.

Every memory-influenced decision must log which prior episode or preference affected it.

---

## Provider Abstraction (Required)

All worker adapters must support:

- Codex CLI (OpenAI)
- Claude CLI (Anthropic)
- Gemini CLI (Google)
- Kimi CLI (Moonshot)
- Local Ollama (any model, via `ollama run`)
- Custom CLI (arbitrary command, policy-approved — see Custom CLI Security below)

Per-role provider assignment:

```
policy.agents.role_worker_preferences:
  pm: ["claude", "gemini"]
  architect: ["codex", "claude"]
  implementer: ["codex"]
  red_team: ["claude", "gemini"]   # must differ from implementer for HIGH/EXTREME
  qa: ["codex", "gemini"]
  sre: ["claude", "kimi"]
```

Fallback chain: if primary provider is unavailable, try next in list. If all
unavailable, record as WORKER_UNAVAILABLE evidence — do not silently skip and
do not claim the role was executed.

API keys vs subscriptions vs local models must all work. No provider requires
mandatory API key if a CLI equivalent is available and configured.

### Custom CLI Security

Custom CLI providers must be invoked via `execv` (no shell) with prompt text passed
via stdin or a temporary file argument — never via shell string interpolation. This
prevents command injection from prompt text containing backticks, `$()`, or quotes.

Custom CLI output is parsed as structured text only. It is never eval'd or executed.

A custom CLI command must be registered in `policy.json` with:
- the full command path
- a SHA256 hash of the command binary
- an explicit `policy_approved: true` flag set by an authorized actor

Using an unregistered or hash-mismatched custom CLI fails with a policy violation
recorded in the ledger.

---

## Offline Mode (Required)

The following must work without internet, GitHub, PyPI, or paid LLM access:

- `sdlc start <run-id>`
- `sdlc plan "<request>"`
- `sdlc run <run-id>` (dry-run gates)
- `sdlc status <run-id>`
- `sdlc diff quality <old> <new>`
- `sdlc bench run --suite offline`
- `sdlc validate`
- `sdlc memory status`
- `sdlc report <run-id> --print`

Offline limitations must be shown, not hidden:

- network scanners: UNAVAILABLE
- cloud workers: UNAVAILABLE
- standards refresh: OFFLINE BASELINE (version date shown)
- GitHub PR status: UNAVAILABLE
- auto-update check: UNAVAILABLE

The tool must never silently degrade. Every offline limitation is evidence.

### Network Loss Mid-Execution

If a worker call starts online and the network drops before the response is received:

- The worker call is treated as atomic. Partial responses are discarded.
- The gate remains PENDING. It is never marked as completed from a partial response.
- `sdlc status` shows "WORKER RESPONSE INCOMPLETE" for the affected gate.
- The run can be resumed from the last fully completed gate.

---

## Distribution & Supply-Chain Security (Required)

Release assets for every version:

```
sdlc-<version>-macos-arm64.tar.gz
sdlc-<version>-macos-x86_64.tar.gz
sdlc-<version>-linux-x86_64.tar.gz
sdlc-<version>-linux-aarch64.tar.gz
SHA256SUMS
SHA256SUMS.sig          (GPG-signed with key in KEYS.md, or Sigstore)
sbom.cdx.json           (CycloneDX, generated by cargo-cyclonedx from Cargo.lock)
```

Requirements:

- Assets are built exclusively in CI (GitHub Actions), not on a developer laptop.
  The release workflow is the only authorized build path.
- GitHub Releases are the only authorized distribution point. Auto-update must not
  resolve downloads from any domain other than `github.com` or
  `objects.githubusercontent.com`.
- macOS binaries are code-signed and notarized before release.
- SHA256SUMS is signed by a key registered in `KEYS.md` or Sigstore transparency log.
  Checksum-only verification is insufficient — signature must also be verified.
- SBOM is generated by `cargo-cyclonedx` directly from `Cargo.lock`. CI fails if
  the SBOM package count does not match the `Cargo.lock` package count.
- Reproducible builds: the same Git commit and pinned Rust toolchain (from
  `rust-toolchain.toml`) must produce byte-identical binaries on two independent CI
  runs. This is demonstrated before release by running the build workflow twice on
  the same commit and comparing SHA256SUMS with `diff`.
- `rust-toolchain.toml` must contain a specific version string (e.g.,
  `channel = "1.79.0"`), not a floating channel label (`channel = "stable"`).
  The CI workflow must verify the active toolchain version matches the pinned
  version before building and fail if it does not.
  Nightly toolchains require written justification and a fallback plan.

### Auto-Update Security

`sdlc update apply` must:

1. Download the new binary and SHA256SUMS and SHA256SUMS.sig from GitHub Releases.
2. Verify the signature on SHA256SUMS against a key in `KEYS.md` or Sigstore.
   If signature verification fails, abort and do not proceed.
3. Verify the SHA256 checksum of the downloaded binary against SHA256SUMS.
   If checksum fails, abort and delete the downloaded file.
4. Write the new binary to a temporary path, not the active binary path.
5. Run a health check (`sdlc --version`) on the temporary binary.
   If the health check fails, delete the temporary binary and abort.
6. Only after all verifications pass: atomically rename the temporary binary to
   the active binary path (`rename(2)` or equivalent atomic operation).
7. If the rename fails, leave the existing binary intact and report the failure.
8. Auto-update requires explicit user confirmation before any step that modifies
   the binary on disk.

---

## TUI Benchmark (Required)

The TUI must be benchmarked against these 10 tasks. Each task is scored PASS/FAIL.

**Independence requirement:** The 10 tasks must be evaluated by a reviewer who did not
implement the TUI. Acceptable evidence: screen recording with timestamps, automated
headless test output with pass/fail results, or a signed attestation from the reviewer.
Self-scored benchmarks are invalid.

Tasks:

1. Find the next blocking gate.
2. Find why release validation is NO_GO.
3. Find all open CRITICAL/HIGH findings.
4. Find which scanners or workers are unavailable.
5. Change the provider for the red-team adversary role.
6. Resume an interrupted run from the last completed gate.
7. Open an evidence artifact for a specific gate.
8. Compare before/after quality diff between two runs.
9. View GitHub PR or check status (or see UNAVAILABLE if not configured).
10. View current budget burn or cost estimate (or see UNAVAILABLE if not tracked).

Success criteria:

- Task completed without docs by independent reviewer: PASS
- Works in 80-column terminal: required
- Works without network: required (degraded state shown, not crashed)
- No ambiguous GO state: gate GO must not imply release-ready GO unless validated
- Plain-text fallback (`--no-tui`) works for all 10 tasks
- Tasks 9 and 10 must be evaluated in both the configured state (when GitHub and
  cost tracking are active) and the UNAVAILABLE state. In the UNAVAILABLE state,
  the TUI must display a visible banner (e.g., "GITHUB STATUS: UNAVAILABLE") — a
  blank or absent field does not count as PASS.

---

## Comparison Matrix (Required, Evidence-Backed Only)

Produce `artifacts/bench/comparison_matrix.md` comparing this tool against
generic coding agents (e.g. Claude Code, Copilot) on dimensions where evidence exists.

Compare only where evidence can be cited. Do not compare where no benchmark was run.

Required dimensions:

| Dimension | This tool | Generic coding agent | Evidence |
|-----------|-----------|----------------------|----------|
| Setup friction (seconds) | measured | N/A or measured | benchmark run ID |
| Provider flexibility | measured | N/A | provider test run |
| SDLC gate visibility | measured | N/A | benchmark task score |
| Evidence ledger | present/absent | absent | architecture |
| Red-team enforcement | measured | N/A | policy test |
| Release-readiness distinction | measured | N/A | accuracy benchmark |
| Resume support | PASS/FAIL | PASS/FAIL | test result |
| TUI task completion (no docs) | measured | N/A | TUI benchmark |
| Auditability | present/absent | absent | architecture |
| Offline/local model support | PASS/FAIL | PASS/FAIL | offline benchmark |

The matrix must say "NOT MEASURED" where no benchmark was run. It must not say
"better" without a measured before/after comparison. Claude Code's strengths
(terminal-native, file editing, IDE integration, checkpoints) are not denied —
this tool's superiority claims are scoped to Secure SDLC orchestration only.

---

## The Tool Must Run Its Own Pipeline

Before and after every major release, run the tool against itself:

```bash
sdlc plan "ship new release of sdlc binary v<next>" --risk high
sdlc run <run-id>
sdlc bench run
sdlc agents execute <run-id> --parallel 6 --execute
sdlc redteam <run-id> --execute --rounds 2
sdlc diff quality <prev-run-id> <run-id>
sdlc bench compare --before artifacts/bench/baseline.json --after artifacts/bench/after.json
sdlc validate --run-id <run-id> --release
sdlc report <run-id> --print
```

This is not optional. A tool that claims to enforce evidence-driven SDLC gates
must use them on itself.

---

## Consent & Privacy Rules

- Memory is opt-in or clearly disclosed at first use with an explicit prompt.
- No telemetry without explicit consent, documented in `privacy.md` and referenced
  from `README.md`.
- Prompt contents are not transmitted to any external service except the configured
  worker CLI. The worker CLI is the operator's responsibility.
- Repo contents are not uploaded to any cloud service by default.
- Cost/token data from provider APIs may include prompt metadata — show what is
  logged and where, or mark as UNAVAILABLE.
- Auto-update downloads come only from GitHub Releases. Signature is verified before
  the binary is replaced. Checksum alone is insufficient.

---

## Final Approval Conditions

The Rust binary release is approved only when ALL of the following are true:

1. Rust binary runs without Python on macOS arm64, macOS x86_64, Linux x86_64,
   and Linux aarch64.
2. Fixture parity test passes: Rust binary produces identical values for all required
   parity fields (see Parity Test Specification) on all `.sdlc/runs/` fixtures,
   including attestation, deploy, and hard-isolation gate fixtures.
3. Setup friction benchmark: intern-reproducible in under 5 minutes (300s) on a clean
   machine. If the actual time exceeds 300s, the target may be revised to at most 600s
   with written rationale approved by a named reviewer who is not the implementer.
   Above 600s is a NO_GO.
4. Provider/model assignment works per role; at least 3 worker families tested.
5. `sdlc bench run` produces scored output for all 12 benchmark dimensions.
6. `sdlc diff quality` compares two runs across all 12 structural run fields.
   `sdlc bench compare` produces scored deltas across all 12 benchmark dimensions.
   Both are required and distinct.
7. Hallucination controls tested: final report with zero unsupported claims on
   reference run.
8. TUI benchmark: 8/10 tasks pass without docs, evaluated by an independent reviewer
   who did not implement the TUI. Evidence: screen recording, automated test output,
   or signed reviewer attestation.
9. Release assets produced in CI only (pinned runners `ubuntu-22.04` / `macos-14`,
   not floating labels): binary, SHA256SUMS, SHA256SUMS.sig, SBOM.
   SBOM generated by `cargo-cyclonedx` from `Cargo.lock`; every package name and
   version in `Cargo.lock` appears in the SBOM (content equality, not count equality).
   Reproducible build demonstrated by two independent CI runs on the same commit
   producing byte-identical SHA256SUMS, verified by `diff`.
   `rust-toolchain.toml` uses a specific version string (e.g., `channel = "1.79.0"`),
   not `channel = "stable"`. CI verifies active toolchain matches before building.
10. Red-team run produces GO or GO_WITH_ACCEPTED_RESIDUAL_RISKS with structured
    findings and evidence; no CRITICAL/HIGH finding closed by the implementer.
    `GO_WITH_ACCEPTED_RESIDUAL_RISKS` requires ALL of:
    - Every CRITICAL/HIGH finding is RESOLVED (closed with evidence by an authorized
      actor who is not the implementer). CRITICAL/HIGH findings may never be ACCEPTED
      or DEFERRED — not even with `--human-override`. They must be fixed.
    - Only MEDIUM or lower findings remain as residual risks.
    - Each residual MEDIUM/LOW is explicitly accepted by an authorized actor who is
      not the implementer, with HMAC-signed actor proof recorded in the ledger.
    - The implementation enforces this at the code level: the `final_verdict` function
      must return GO_WITH_ACCEPTED_RESIDUAL_RISKS only when no finding with severity
      CRITICAL or HIGH has status other than RESOLVED.
11. 25-gate pipeline runs before and after the change.
12. `sdlc learn record` works; memory store passes `detect-secrets` scan; filesystem
    mode is 600; memory store path is in `.gitignore`.
13. Offline mode: all required commands run without internet (degraded state shown,
    not silent); network loss mid-execution leaves gate PENDING, not falsely completed.
14. Rollback plan exists at `docs/ROLLBACK.md` with exact commands and backward-compat
    statement; smoke-tested on a clean machine with a verifiable artifact (CI log,
    screen recording, or authorized-actor attestation) ledger-anchored before release.
15. `KEYS.md` exists with at least one registered key fingerprint and rotation
    procedure. All release assets signed with a key from `KEYS.md` or Sigstore.
16. `privacy.md` exists and is referenced from `README.md`.
17. Authorized-actor enforcement documented in `docs/RELEASE_PROCESS.md`; branch
    protection rule requiring an independent reviewer is active on `main`.
    Release workflow triggers only from `main` or tags from `main`.
18. `rust-toolchain.toml` exists with a specific version string (not `channel = "stable"`).
19. Custom CLI invocation uses `execv` (no shell); prompt text via stdin or file.
    Custom CLI registered in `policy.json` with SHA256 hash.
20. "100x superiority" is not claimed unless one benchmark dimension proves it with
    measured before/after values. The final report is grepped by a CI gate for
    unsupported "100x" claims; the gate fails if any are found without benchmark evidence.
21. Baseline artifact (`artifacts/bench/baseline.json`) has a `bench.baseline_recorded`
    ledger event whose timestamp predates the first Rust commit in Git history.
    Verified at release time by comparing ledger event timestamp with
    `git log --diff-filter=A --name-only --format="%aI" -- "*.rs" | head -1`.
22. TUI benchmark tasks 9 and 10 are tested in both the configured state and the
    UNAVAILABLE state. UNAVAILABLE must display a visible banner (not a blank field)
    for the task to count as PASS.
23. An automated test asserts `sdlc diff quality` output contains all 12 named
    structural fields (gate states, evidence coverage, finding lifecycle, release
    blockers, unsupported-claim count, scanner coverage, red-team findings, prompt
    overrides, provider/model choices, cost/token usage, elapsed time, final verdict)
    on a reference fixture pair.

---

## What The Red-Team Will Attack

- Binary ships without signature verification in auto-update path (checksum alone).
- Parity test omits edge-case gates (attestation, deploy, hard isolation).
- TUI benchmark tasks are scored by the implementer, not an independent reviewer.
- "100x better" is asserted in the report without a measured benchmark.
- Memory system stores prompt text or API keys despite the privacy rule.
- Memory store has mode 644 (world-readable) or is not in `.gitignore`.
- Offline mode silently degrades instead of showing UNAVAILABLE.
- Network loss mid-run marks a gate complete from a partial response.
- Comparison matrix compares against Claude Code without measuring Claude Code.
- Release assets signed with a key not in `KEYS.md`.
- SBOM has correct package count but wrong package names/versions (count-only check).
  Attack is blocked only by content-equality check (every name+version in Cargo.lock
  appears in SBOM).
- Reproducible build not demonstrated — two CI runs produce different checksums.
- Runners pinned to `ubuntu-latest` / `macos-latest` (floating labels break reproducibility).
- `rust-toolchain.toml` uses `channel = "stable"` instead of a pinned version string.
- The tool does not run its own 25-gate pipeline before shipping.
- Cost/token data is omitted rather than shown as UNAVAILABLE.
- Red-team findings are summarized in prose, not parsed into structured Finding records.
- Custom CLI invoked via shell string interpolation; prompt text in argv.
- `sdlc diff quality` and `sdlc bench compare` conflated; one missing.
- Baseline artifact created after first Rust commit; pre-change state not captured.
- CRITICAL/HIGH finding closed by the implementer without an independent reviewer.
- CI granted authority to close findings by the same implementer whose findings it closes.
- `privacy.md` absent or not linked from `README.md`.
- Rollback smoke test self-attested; no verifiable artifact produced.
- Release cut from a branch other than `main`, bypassing branch protection.
- `GO_WITH_ACCEPTED_RESIDUAL_RISKS` issued with an open CRITICAL or HIGH finding.
- TUI tasks 9 or 10 scored PASS with blank/absent UNAVAILABLE display (not a visible banner).
- `sdlc diff quality` output missing one or more of the 12 named structural fields.
- "100x better" slip in report text not caught by CI gate grep.
- CRITICAL or HIGH finding accepted/deferred via `--human-override` instead of fixed,
  then `GO_WITH_ACCEPTED_RESIDUAL_RISKS` issued. This must be blocked at code level.
- `--closed-by human_release_manager` passed without HMAC proof; policy flag disabled
  or defaulting to OFF, allowing string impersonation of authorized actors.

If the red-team raises any of the above: CRITICAL or HIGH finding. Do not close
without evidence.
