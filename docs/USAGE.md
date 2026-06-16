# USAGE — install from the release page + 25 use cases

This guide shows how to **install and verify a signed release**, then walks **25
concrete use cases** with exact commands. Commands use `python -m sdlc`; after a wheel
install you can use the `sdlc` entrypoint interchangeably.

---

## Install from the GitHub release page (verified)

Each release (e.g. `v0.2.0`) attaches a wheel, an sdist, a CycloneDX SBOM, and a
Sigstore-signed checksum set: `SHA256SUMS`, `SHA256SUMS.sig`, `SHA256SUMS.pem`.

### Option A — download + verify + install (recommended)

```bash
# 1. Download the assets (CLI) ...
gh release download v0.2.0 --repo gwuml/sdlc
#    ... or from the browser: https://github.com/gwuml/sdlc/releases/tag/v0.2.0

# 2. Verify the signature is from this repo's release workflow (Sigstore keyless).
cosign verify-blob \
  --certificate-identity-regexp '^https://github.com/gwuml/sdlc/\.github/workflows/release\.yml@refs/(heads/main|tags/v.*)$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --signature SHA256SUMS.sig --certificate SHA256SUMS.pem \
  SHA256SUMS
#    -> "Verified OK"   (install cosign: https://docs.sigstore.dev/cosign/installation/)

# 3. Verify the artifact checksums match what was signed.
sha256sum -c SHA256SUMS            # macOS: shasum -a 256 -c SHA256SUMS

# 4. Install the verified wheel into a virtualenv.
python3 -m venv .venv && . .venv/bin/activate
python -m pip install ./sdlc_control_plane-0.2.0-py3-none-any.whl

# 5. Confirm.
sdlc --help
sdlc --version 2>/dev/null || python -m sdlc --help
```

Why verify: the **signature** (not the checksum alone) is the tamper-evident control —
a tampered `SHA256SUMS` would still match a tampered artifact. Trust only assets whose
signature verifies against the identity registered in `KEYS.md`.

### Option B — from source (development)

```bash
git clone git@github.com:gwuml/sdlc.git && cd sdlc
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -e .
python -m sdlc --help
```

### Inspect the SBOM
```bash
python -m json.tool sbom.cdx.json | head -40   # CycloneDX dependency inventory
```

### Offline note
Once installed, planning, status, dry-run gates, the TUI, benchmark, quality-diff, and
validation all work with **no network**. Network-only tools (cloud workers, `pip-audit`)
report `UNAVAILABLE` rather than failing silently.

---

## 25 use cases

Each is a real task with the exact command(s). Set `RID` to your run id where shown.

### Getting started
1. **Initialize the control plane in a repo**
   `python -m sdlc init`
2. **Plan a gated run from a plain request** (risk auto-classified, 25 gates created)
   `python -m sdlc plan "add OAuth login with audit logging" --risk auto --ui auto --security auto --infra auto`
3. **Autopilot a vague request** (plan + brief + prework + agents + next action)
   `python -m sdlc start "build a small fibonacci API"`
4. **See the single safest next action**
   `python -m sdlc next "$RID"`

### Visibility
5. **Inspect all 25 gates** — local state vs release state, owner, blockers
   `python -m sdlc status "$RID"`
6. **Find out why release is NO_GO** (deterministic verdict + blocker list)
   `python -m sdlc validate --run-id "$RID" --release`
7. **Open the interactive TUI dashboard** (Tab=panels, ↑/↓=scroll, g=next blocker, q=quit)
   `python -m sdlc tui "$RID"` · plain/CI: `python -m sdlc tui "$RID" --no-tui`

### Advancing the pipeline
8. **Advance deterministic + advisory gates**
   `python -m sdlc run "$RID"`
9. **Capture security-scan evidence** (Bandit SAST, detect-secrets, pip-audit, Checkov)
   `python -m sdlc scan "$RID"`
10. **Preview an AI worker's bounded prompt (dry-run, no execution)**
    `python -m sdlc worker "$RID" codex --mode BUILD`
11. **Execute an AI worker for real** (implementation; opt-in, isolated)
    `python -m sdlc worker "$RID" codex --mode BUILD --execute`
12. **Run an independent cross-model red-team** (different model than the implementer)
    `python -m sdlc redteam "$RID" --execute --rounds 2`

### Findings & gates
13. **List red-team findings and their lifecycle**
    `python -m sdlc finding list "$RID"`
14. **Close a CRITICAL/HIGH finding with evidence** (the only way to clear it — FAC-10)
    `python -m sdlc finding close "$RID" HIGH-001 --closed-by human_security_owner --evidence path/to/fix.md`
15. **Accept a MEDIUM as residual risk** (CRITICAL/HIGH can NEVER be accepted)
    `python -m sdlc finding accept "$RID" MEDIUM-003 --closed-by human_release_manager --reason "tracked; low impact" --evidence path/to/rationale.md`
16. **Manually complete a gate with typed evidence**
    `python -m sdlc gate complete "$RID" observability_runbooks --verdict GO --evidence path/to/runbook.md`

### Multi-agent & providers
17. **Plan and run six role-agents in parallel**
    `python -m sdlc agents plan "$RID" --parallel 6` then `python -m sdlc agents execute "$RID" --parallel 6 --execute`
18. **Use a local open LLM (Ollama) as a worker** — fully offline, no API key
    `SDLC_OLLAMA_MODEL=llama3 python -m sdlc worker "$RID" ollama --mode PLAN --execute`
19. **Check which worker families are available + diagnose**
    `python -m sdlc agents doctor`

### Provenance, attestation, deployment
20. **Record ledger-backed Git provenance** (branch/commit/PR/CI)
    `python -m sdlc git provenance "$RID"`
21. **Generate, sign, and verify artifact attestations**
    `python -m sdlc attest manifest "$RID"` → `attest sign "$RID" --key ~/.sdlc/att.key --execute` → `attest verify "$RID"`
22. **Plan a locked deployment with human approval + rollback** (production stays locked by default)
    `python -m sdlc deploy plan "$RID" --env production --rollback-command "..."` then `deploy approve ... --actor human_release_manager`

### Quality, learning, integrity
23. **Benchmark the tool** (12 dimensions; corpus-relative headline; `corpus_source` recorded)
    `python -m sdlc bench run` · render: `python -m sdlc bench report`
24. **Quality-diff two runs** (regression detection across 12 structural fields)
    `python -m sdlc diff quality <old-run-id> <new-run-id>`
25. **Detect ledger tampering / verify run integrity**
    `python -m sdlc validate --run-id "$RID"`  (a broken canonical hash-chain fails, in every mode)

### Bonus
- **Self-improvement loop:** `sdlc learn record "$RID"` → `sdlc learn suggest` → `sdlc learn apply --proposal <id> --actor you --execute`
- **Consent-based memory:** `sdlc memory init|status|search "<topic>"|export|delete --all|disable`
- **Final report:** `python -m sdlc report "$RID" --print`

---

## What to expect

A fresh run is **advisory and NO_GO by default** — that is correct, not a bug. Gates
turn GO only when real evidence (worker output, tests, scans, human sign-off) closes
them. The tool deliberately refuses to declare your work release-ready without proof;
`sdlc next` always tells you the next step toward GO. See `docs/FEATURE_GATE_MAP.md` for
the gate-by-gate reference and `docs/WHY_THIS_TOOL.md` for how it governs Claude Code /
Codex / Gemini / Kimi / Ollama as workers.
