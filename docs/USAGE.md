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
16. **Manually complete a gate with typed evidence** (`--actor` required; the gate is
    guarded — you cannot mark it GO while prerequisite gates are unresolved)
    `python -m sdlc gate complete "$RID" observability_runbooks --verdict GO --actor agent_9_sre_sysadmin --evidence path/to/runbook.md`

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

---

## Appendix — worked transcripts (real captured output)

Generated by `scripts/capture_usage.sh` against **sdlc 0.2.0** in a throwaway git repo. Worker / red-team / deploy use safe dry/plan modes (no live LLM calls, no real deploys); the signed-release check runs against the real `v0.2.0` release. Temp paths are shown as `<repo>`. A fresh run is advisory and NO_GO by design — the tool refusing to declare work release-ready without evidence, not an error.

```text


========== 1. init ==========
$ sdlc init
Initialized Secure SDLC control plane at <repo>/.sdlc


========== 2. plan (risk auto-classified) ==========
$ sdlc plan 'add OAuth login with audit logging' --risk auto --security auto
Created run: add-oauth-login-with-audit-logging-20260617-002528
Risk: EXTREME
Prompt: <repo>/.sdlc/runs/add-oauth-login-with-audit-logging-20260617-002528/prompts/execution_prompt.md
Plan: <repo>/.sdlc/runs/add-oauth-login-with-audit-logging-20260617-002528/plan.json
(run id: add-oauth-login-with-audit-logging-20260617-002528)


========== 3. status ==========
$ sdlc status add-oauth-login-with-audit-logging-20260617-002528
Run: add-oauth-login-with-audit-logging-20260617-002528
Feature: add OAuth login with audit logging
Risk: EXTREME | Policy: default | Branch: master
Release readiness: NO_GO | blockers=25
Authority mode: ADVISORY | production authority=DISABLED
Use this run as advisory PR evidence only; it is not production deployment clearance.

Gates:
  01. intake_scope                         local=PENDING  release=BLOCKED  owner=agent_1_pm_coordinator
  02. stakeholders_raci                    local=PENDING  release=BLOCKED  owner=agent_1_pm_coordinator
  03. mission_non_goals                    local=PENDING  release=BLOCKED  owner=agent_1_pm_coordinator
  04. repo_context_env_branch              local=PENDING  release=BLOCKED  owner=agent_1_pm_coordinator


========== 4. next ==========
$ sdlc next add-oauth-login-with-audit-logging-20260617-002528
Next action: Provide evidence for gate intake_scope
Command: python -m sdlc gate evidence add-oauth-login-with-audit-logging-20260617-002528 intake_scope --actor agent_1_pm_coordinator --artifact <key>=<path> --source <evidence>
Reason: Gate intake_scope is not release-satisfied.
Blockers: 25


========== 5. run (advance deterministic + advisory gates) ==========
$ sdlc run add-oauth-login-with-audit-logging-20260617-002528
  evidence_traceability_attestations: NO_GO
  commit_branch_pr_ci: NO_GO
  deploy_rollout_postdeploy: SKIPPED
  final_report_reaudit: NO_GO

Run advanced with a full advisory pass. Release-grade implementation/red-team gates still require worker execution or human evidence.


========== 6. scan (security evidence) ==========
$ sdlc scan add-oauth-login-with-audit-logging-20260617-002528
Security scans -> NO_GO
  bandit          PASS               artifacts/scans/bandit.txt
  detect-secrets  PASS               artifacts/scans/detect-secrets.txt
  pip-audit       NOT_APPLICABLE     artifacts/scans/pip-audit.txt
  checkov         NOT_APPLICABLE     artifacts/scans/checkov.txt
  policy          PASS               artifacts/scans/policy.txt


========== 7. validate --release (deterministic verdict) ==========
$ sdlc validate --run-id add-oauth-login-with-audit-logging-20260617-002528 --release
Validation failed:
- Release validation final verdict is NO_GO
- repo_context_env_branch rejects protected branch master without explicit policy
- baseline_freeze rejects protected branch master without explicit policy
- Gate implementation is not release-satisfied: FIX_REQUIRED/NO_GO
- Gate deterministic_quality is not release-satisfied: NO_GO/NO_GO
- Gate qa_tests_integration_smoke is not release-satisfied: NO_GO/NO_GO
- Gate security_scans is not release-satisfied: BLOCKED/NO_GO


========== 8. tui --no-tui (dashboard) ==========
$ sdlc tui add-oauth-login-with-audit-logging-20260617-002528 --no-tui
================================================================================
SDLC CONTROL PLANE — DASHBOARD
================================================================================
Run: add-oauth-login-with-audit-logging-20260617-002528
Feature: add OAuth login with audit logging
Risk: EXTREME | Policy: default | Branch: master
Release: NO_GO | blockers=15 | authority=ADVISORY
Next blocking gate: repo_context_env_branch

Gates:  (* = blocking;  cols: NN id  local/verdict  release)
 01 intake_scope                   GO/GO  SATISFIED
 02 stakeholders_raci              GO/GO  SATISFIED
 03 mission_non_goals              GO/GO  SATISFIED
*04 repo_context_env_branch        GO/GO  BLOCKED
 05 risk_blast_radius              GO/GO  SATISFIED
 06 data_privacy_secrets           GO/GO  SATISFIED


========== 9. worker (dry-run preview of the bounded prompt) ==========
$ sdlc worker add-oauth-login-with-audit-logging-20260617-002528 codex --mode BUILD
  "result_path": "worker-results/20260617-002533-codex-build/result.json",
  "stdout_path": "worker-results/20260617-002533-codex-build/stdout.txt",
  "stderr_path": "worker-results/20260617-002533-codex-build/stderr.txt",
  "usage": {
    "status": "UNAVAILABLE",
    "reason": "worker not executed (dry-run or unavailable)"
  }
}


========== 10. redteam (deterministic findings) ==========
$ sdlc redteam add-oauth-login-with-audit-logging-20260617-002528
Findings for add-oauth-login-with-audit-logging-20260617-002528:
  HIGH-001 HIGH     OPEN   Implementation gate has no accepted code-diff evidence
  HIGH-002 HIGH     OPEN   High-stakes run lacks completed security scan evidence


========== 11. finding list ==========
$ sdlc finding list add-oauth-login-with-audit-logging-20260617-002528
HIGH-001 HIGH     OPEN                   Implementation gate has no accepted code-diff evidence
HIGH-002 HIGH     OPEN                   High-stakes run lacks completed security scan evidence


========== 12. finding accept on a HIGH (FAC-10: blocked) ==========
$ sdlc finding accept add-oauth-login-with-audit-logging-20260617-002528 HIGH-001 --closed-by human_security_owner --reason x --evidence app.py
CRITICAL/HIGH findings cannot be accepted or deferred without --human-override


========== 13. gate complete (manual typed evidence) ==========
$ sdlc gate complete add-oauth-login-with-audit-logging-20260617-002528 observability_runbooks --verdict GO --actor agent_9_sre_sysadmin --evidence runbook.md
Cannot mark observability_runbooks GO; unresolved prerequisite gates: implementation, deterministic_quality, qa_tests_integration_smoke, security_scans


========== 14. agents plan --parallel 6 ==========
$ sdlc agents plan add-oauth-login-with-audit-logging-20260617-002528 --parallel 6
Agent plan: artifacts/agents/task-plan.json
Parallelism: 6
  agent_1_pm_coordinator                 codex      PLAN             queued
  agent_2_architecture_contracts         claude     PLAN             queued
  agent_3_implementation_owner           codex      BUILD            queued
  agent_4_evidence_reporting_owner       codex      PLAN             queued
  agent_5_qa_validation_owner            codex      TEST             queued
  agent_6_redteam_deploy_rollback        openai-codex-primary SECURITY_REVIEW  queued
  agent_8_cybersecurity_engineer         openai-codex-adversary SECURITY_REVIEW  queued
  agent_9_sre_sysadmin                   codex      PLAN             queued
  agent_10_it_enterprise_integration     codex      PLAN             queued
  agent_11_compliance_audit              codex      PLAN             queued


========== 15. agents doctor (worker availability) ==========
$ sdlc agents doctor
Worker families:
  claude       available   command=claude --print --output-format json --permission-mode plan
  codex        available   command=codex exec --cd . --sandbox read-only --skip-git-repo-check --json -
  gemini       available   command=gemini --prompt 'Read the complete task from stdin and return final JSON only.' --approval-mode plan --output-format json --skip-trust
  kimi         unavailable command=kimi --prompt -
  ollama       available   command=ollama run llama3
  openai-codex-adversary available   command=codex exec --cd . --sandbox read-only --skip-git-repo-check --json --model gpt-5.4-mini -
  openai-codex-primary available   command=codex exec --cd . --sandbox read-only --skip-git-repo-check --json --model gpt-5.5 -


========== 16. providers: fallback chain (never silent-skip) ==========
$ python -c 'from sdlc.adapters import select_available_adapter as s; print(s([...]))'
{'name': 'ollama', 'status': 'AVAILABLE', 'tried': [('definitely-not-real', 'unknown-adapter')]}


========== 17. git provenance (ledger-backed) ==========
$ sdlc git provenance add-oauth-login-with-audit-logging-20260617-002528
Git provenance: .sdlc/runs/add-oauth-login-with-audit-logging-20260617-002528/artifacts/git/provenance.json


========== 18. attest manifest ==========
$ sdlc attest manifest add-oauth-login-with-audit-logging-20260617-002528
Attest manifest -> MANIFEST_WRITTEN
Artifact: artifacts/attestations/manifest.json


========== 19. deploy plan (production stays locked) ==========
$ sdlc deploy plan add-oauth-login-with-audit-logging-20260617-002528 --env production --rollback-command 'echo rollback'
Deploy plan production -> PLANNED
Artifact: artifacts/deploy/production.json


========== 20. bench run (12 dimensions, corpus-relative headline) ==========
$ sdlc bench run
Headline (CORPUS only, corpus-relative): 100.0 from 4/12 dimensions across 1 runs.
Other dimensions are reported but excluded from the headline (see kind):
  1_setup_friction                 100.0  CAPABILITY
  2_blocker_visibility             100.0 *CORPUS
  3_evidence_completeness          100.0 *CORPUS
  4_hallucination_count            UNAVAILABLE
  5_redteam_independence           100.0  CONFIG
  6_resume_recovery                100.0  CAPABILITY
  7_failed_tool_visibility         100.0 *CORPUS
  8_release_readiness_accuracy     100.0  CONSISTENCY
  9_tui_task_completion            UNAVAILABLE
  10_provider_flexibility          100.0  ENVIRONMENT
  11_cost_token_visibility         100.0  CAPABILITY
  12_github_pr_provenance          100.0 *CORPUS


========== 21. diff quality (compare two runs) ==========
$ sdlc diff quality add-oauth-login-with-audit-logging-20260617-002528 second-run
# Quality Diff: add-oauth-login-with-audit-logging-20260617-002528 -> second-run

Final verdict: **NO_GO** -> **NO_GO**

## Gate state changes
- critical_high_fix_loop: FIX_REQUIRED/NO_GO -> GO/GO
- observability_runbooks: BLOCKED/NO_GO -> GO/GO
- security_scans: BLOCKED/NO_GO -> GO/GO

## Release blockers
- added: none
- removed: ['critical_high_fix_loop', 'observability_runbooks', 'security_scans']
- unchanged: 8



========== 22. learn record + suggest ==========
$ sdlc learn record add-oauth-login-with-audit-logging-20260617-002528
  ],
  "recorded": 12,
  "run_id": "add-oauth-login-with-audit-logging-20260617-002528"
}
$ sdlc learn suggest
pending proposals: 0


========== 23. ledger integrity: detect a tamper ==========
$ sdlc validate --run-id add-oauth-login-with-audit-logging-20260617-002528   # after tampering one event
Validation failed:
- Run ledger event 0 failed canonical hash-chain validation
- Run validation found blocked gates; use --structural-only for schema checks: implementation=FIX_REQUIRED/NO_GO, deterministic_quality=NO_GO/NO_GO, qa_tests_integration_smoke=NO_GO/NO_GO, security_scans=BLOCKED/NO_GO, observability_runbooks=BLOCKED/NO_GO, implementer_self_review=FIX_REQUIRED/NO_GO, independent_redteam_cross_model=NO_GO/NO_GO, critical_high_fix_loop=FIX_REQUIRED/NO_GO, evidence_traceability_attestations=FIX_REQUIRED/NO_GO, commit_branch_pr_ci=FIX_REQUIRED/NO_GO, final_report_reaudit=FIX_REQUIRED/NO_GO
- Run validation found open CRITICAL/HIGH findings


========== 24. memory (consent-based, local) ==========
$ sdlc memory init
{
  "path": "<repo>/.sdlc/memory.sqlite",
  "status": "enabled"
$ sdlc memory status
{
  "enabled": true,
  "episodes": 0,
  "initialized": true,


========== 25. report --print ==========
$ sdlc report second-run --print
# Secure SDLC Final Report

Run: `second-run`
Feature: second feature for diff
Risk: LOW
Verdict: **NO_GO**

## Claim discipline
This report only claims that recorded gates and evidence exist. It does **not** claim profitability, safety, security, compliance, or production readiness unless those claims are explicitly backed by gate evidence.

## Authority Mode
- Mode: ADVISORY


========== 26. verify a signed release (real v0.2.0) ==========
$ cosign verify-blob --certificate-identity-regexp ... SHA256SUMS
Verified OK


(captured against sdlc 0.2.0; demo repo: throwaway)
```
