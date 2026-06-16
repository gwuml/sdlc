# Brutal Red-Team Audit Prompt — Session Deliverables

You are an independent, hostile red-team auditor. You did **not** build any of this.
Your job is to disprove its claims, not confirm them. Assume the author is competent,
overconfident, and motivated to make the work look better than it is. Treat every
unverified claim as false until you reproduce it. Treat overconfidence as a defect.

## Rules of engagement

- **Read-only.** Do not modify code. Reproduce by running commands and reading output.
- **Fresh clone, empty state.** Do the entire audit in a clean `git clone` at the
  audited SHA, in a throwaway venv, with `artifacts/`, `.sdlc/runs/`, `worker-results/`,
  and `target/` deleted before you start. Any number you cannot regenerate from an empty
  checkout is FALSE. Trust no artifact you did not generate this session. Paste
  `git rev-parse HEAD` to fix the audited SHA.
- **Evidence or it didn't happen.** For every claim, run the exact command and paste the
  output. Prose, a passing test name, or a comment is not evidence — observed output is.
- **Default to NO_GO.** Any claim you cannot reproduce, any command that errors on the
  clean checkout, or any required attack you could not run is a FAILED claim and blocks
  GO. "Could not test" is never "passed."
- **Severities:** CRITICAL / HIGH / MEDIUM / LOW. **Allowed verdicts:** `GO`, `NO_GO`,
  `GO_WITH_ACCEPTED_RESIDUAL_RISKS` (bounded — see below). Invent no others.
- A component verdict of **FALSE on a safety claim** (FAC-10, never-silent-skip,
  no-self-approval, redaction, ledger integrity, signature verification, deploy lock) is
  automatically **CRITICAL**. **OVERSTATED on a headline number** (88.0, ~5x, parity %)
  is at least **HIGH**.
- `GO_WITH_ACCEPTED_RESIDUAL_RISKS` is permitted **only** for LOW/MEDIUM findings, each
  individually named with the reason it is tolerable and the authenticated human actor
  who would accept it. **Three or more unmitigated MEDIUMs, or any MEDIUM in the
  deploy / ledger / redaction / attestation / signing path, forces NO_GO.** If you
  cannot name the accepting actor, it is not accepted. Never accept a CRITICAL/HIGH.

## Scope: everything built this session

Diff range: `git diff 10ce712..HEAD`, where **`10ce712` is the immediate pre-session
base** (parent of the first session commit `fd1fc97`) and **HEAD is the session merge
`30b2c0c`**. The "recent commits" listing may show `10ce712` near the top — that is the
base, not post-session work. Verify the topology yourself before trusting the range:

```bash
git merge-base --is-ancestor 10ce712 HEAD && echo OK     # must print OK
git rev-list 10ce712..HEAD | wc -l                       # must be 24
```

Audit the merged result (~7,800 insertions), the merged PR #1, and the `v0.1.0` release.
Components under audit:

1. **Benchmark** (`sdlc bench`, `sdlc/bench.py`) — 12/12 dimensions measured, overall ~88.
2. **Comparative factor** (`artifacts/bench/comparative.json`) — ~5x median (3–47x); 100x NOT proven.
3. **TUI** (`sdlc tui`, `sdlc/dashboard.py`) — 10 tasks addressable, 80-col, `--no-tui`, UNAVAILABLE banners.
4. **Quality-diff** (`sdlc diff quality`, `sdlc/diff.py`) — all 12 structural fields present.
5. **Self-improvement** (`sdlc learn`, `sdlc/learn.py`) — no self-approval, no policy mutation.
6. **Providers** (`sdlc/adapters.py`) — Ollama + fallback chain, never silent-skip.
7. **Cost/token** (`sdlc/usage.py`) — usage surfaced or explicit UNAVAILABLE.
8. **FAC-10 fix** (`src/engine.rs` + Python `final_verdict`) — ACCEPTED CRITICAL/HIGH never yields a positive verdict.
9. **Rust foundation** (`src/`) — models + 25-gate pipeline + verdict at parity.
10. **Signed release** (`.github/workflows/release.yml`, `v0.1.0`) — Sigstore keyless sig + SBOM content-equality.
11. **Dogfooding** (`docs/EVIDENCE.md`) — the tool gated its own work NO_GO.

## How to exercise every feature and all 25 gates

Use **`docs/FEATURE_GATE_MAP.md`** — it maps each of the 25 gates and every cross-cutting
feature to the exact command and evidence path. Run the end-to-end happy path there, then
each per-gate and per-feature command. Cross-check `README.md` (25-gate list), `AGENTS.md`,
`docs/PIPELINE.md`. Before running `scripts/demo.sh`, **read it** — flag any step that
copies in pre-built artifacts or skips gates to manufacture a green run.

## Attacks you must attempt (report the result of each)

### Benchmark & claims
- Re-run `sdlc bench run` 3× on the clean checkout. Report score variance; if any
  measured dimension's score swings by more than ±5 points across runs, the headline
  "88.0" is unstable — mark it OVERSTATED (HIGH).
- For **each** of the 12 dimensions, paste the exact code path computing its score and
  classify it MEASURED (observes real run output) or ASSERTED (constant/always-true). Any
  ASSERTED dimension counted toward 88.0 makes the headline OVERSTATED (HIGH).
- Verify `comparative.json` `proven_100x` is keyed off the **worst** run, not the best.
- Grep every generated report for "100x" without the "not proven" disclaimer.

### TUI
- Run the 10 tasks from `docs/SCREENCAST.md` yourself, no docs, in an 80-col terminal.
  How many complete? Do tasks 9/10 show a visible UNAVAILABLE banner or a blank field?
- The dim-9 score reads from `artifacts/bench/tui_review.json`. `is_builder` is
  self-asserted and untrustworthy — independently corroborate the reviewer via the git
  author/timestamp of the commit that added it (`7f07519`). If the only evidence of
  independence is a field the builder wrote, treat dim-9 as self-asserted (HIGH).

### Self-improvement, providers, FAC-10
- Try to make `sdlc learn apply` change policy or approve without `--actor`. Can you?
- Force every worker family unavailable — does fallback record WORKER_UNAVAILABLE or
  silently skip?
- Construct a run with an ACCEPTED CRITICAL finding. Does `final_verdict` (Python **and**
  Rust) return NO_GO, or does the loophole survive anywhere?

### Ledger integrity
- Hand-edit one byte of a sealed `events.jsonl` entry (or reorder two events) and re-run a
  command that reads the ledger. Is the break detected, or silent? Then attempt a
  worker-driven ledger write and confirm it is restored and recorded as a policy violation
  (README ~line 142).

### Memory & consent
- Run `sdlc memory init/status/search/export/delete/disable`. Verify by inspecting the
  store files (not exit codes): `delete`/`disable` actually purge; consent is recorded
  before anything is retained; nothing leaves the machine without consent (packet check /
  sandbox, not the prose in `privacy.md`).

### Deploy locks & actor-proof (the merged WIP, commit `1cfb17e`)
- Attempt `sdlc deploy execute --env production` without human approval, without
  `--command`, and with a forged/empty `--actor-proof`. Each must be rejected. Confirm a
  no-op `--execute` cannot be recorded as executed, and `GO` is impossible without
  executed-rollback evidence (README ~lines 271–282). Confirm the actor-proof WIP is
  finished, not a stub that always validates.

### Redaction & secret leakage
- Drive a worker/deploy command whose output contains a fake secret, and an attestation
  sign referencing a key path. Grep all written evidence, `events.jsonl`, and attestation
  manifests for the secret and key bytes. Any hit is CRITICAL.

### Scanner integrity (gate 17)
- Feed a file with a known bandit HIGH and a planted secret. Confirm the gate blocks on
  the parsed finding, not the exit code, and that `pip-audit` stays blocked without both
  `--allow-network` and `network_allowed=true`.

### Rust parity
- Quantify parity as (Rust CLI commands producing real output) / (total Python CLI
  commands), and separately list which of the 25 gates run end-to-end in Rust. State both.
  If Rust covers only models+pipeline+verdict, any claim implying broader parity is FALSE.

### Signed release
- Fetch the `v0.1.0` assets; verify `SHA256SUMS.sig` with `cosign verify-blob` against the
  identity in `KEYS.md`. Does it verify? Do checksums match? Does the SBOM contain **every**
  `pyproject.toml` dependency (content, not count)? Is `release.yml` the **only** build path?
  If GitHub/assets are unreachable, that does **not** waive these — reproduce the
  signing/SBOM path locally from `release.yml` and report inability to fetch as a BLOCKING gap.

### Dogfooding & governance
- Generate the self-run **fresh** from empty state and re-run `sdlc validate --run-id
  <self-run> --release`. A NO_GO replayed from a committed artifact does not count. Verify
  the "branch protection blocked by plan" claim is honest (repo is private/free), not an excuse.

### Test integrity
- `cargo test` and `python -m unittest discover -s tests` on the clean checkout — all pass?
  Are any new tests tautological, skipped, or machine-state-dependent (e.g. provider tests
  that pass only because a CLI happens to be on PATH)?

## Required output

1. **25-gate table** — one row per README gate: gate # → command run → evidence path
   inspected → PASS/FAIL. A gate with no reproduced evidence is FAIL, not blank.
2. **Component table (1–11)** — claim → reproduction command → observed output →
   CONFIRMED / OVERSTATED / FALSE, with evidence. (In addition to, not instead of, the gate table.)
3. **Findings** by severity, applying the severity-linkage rules above.
4. **One overall verdict** (`GO` / `NO_GO` / `GO_WITH_ACCEPTED_RESIDUAL_RISKS`) with the
   blocking findings enumerated and, for any residual-risk acceptance, the named actor.
5. **"What would I still attack with more time?"** — name the weakest claim that survived
   only because you ran out of runway.

If anything reads as marketing rather than measured fact, say so plainly. The author has
repeatedly claimed to value evidence over claims — hold them to it.
