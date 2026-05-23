# Production-Grade Completion Prompt

Use this prompt to continue development of the Secure SDLC Control Plane from the
current blocker list to an evidence-backed production-grade release candidate.

Do not claim the tool is world class, safe, secure, compliant, or production-ready
until the gates, scanner outputs, red-team evidence, attestations, and rollout
records prove the exact claim.

```text
# Codex Takeover Prompt - Production-Grade SDLC Control Plane Completion

You are Codex taking over implementation in the `sdlc-control-plane` repository.

## Mission

Advance the terminal-native Secure SDLC control plane from a strong v0.1 foundation
to an evidence-backed production-grade release candidate.

The orchestrator is the authority. Codex, Claude, and other models are workers.
Do not replace the orchestrator with a generic prompt generator.

## Mandatory First Actions

1. Read `AGENTS.md`.
2. Read `README.md`.
3. Inspect the current blocker evidence:
   - `.sdlc/runs/scanner-evidence-hardening/final-report.md`
   - `.sdlc/runs/scanner-evidence-hardening/artifacts/security_scan_summary.md`
   - `.sdlc/runs/scanner-evidence-hardening/artifacts/scans/bandit.txt`
4. Run:
   - `python -m unittest discover -s tests`
   - `python -m sdlc validate`
   If `python` is unavailable, also run the same commands with `python3` and with
   the project virtualenv, then record the exact failure and fallback commands.
5. Inspect the CLI:
   - `python -m sdlc --help`
   - `python -m sdlc scan --help`
   - `python -m sdlc redteam --help`
   - `python -m sdlc gate complete --help`
   - `python -m sdlc worker --help`

## Current Known Blockers

The previous self-run verdict was `NO_GO` because:

- Scanner gate is `NO_GO`.
- Bandit reports low-severity subprocess findings in `sdlc/util.py`.
- `pip-audit` is blocked by default network policy.
- Real cross-model red-team execution is not implemented.
- Deploy gate implementation is not implemented.
- Artifact signing and attestations are not implemented.
- Production rollout evidence is not implemented.
- Implementation/red-team/fix-loop gates still need real evidence, not dry-run placeholders.

## Non-Negotiable Safety Rules

- Preserve the 25-gate pipeline.
- Do not remove or weaken the red-team loop.
- Do not let implementers close their own findings.
- Do not enable direct `origin/main` push by default.
- Do not enable production deploy/restart by default.
- Do not add network calls unless policy and user explicitly allow them.
- Do not hide failed tests, missing scanners, unavailable workers, or blocked network scans.
- Do not store secrets in repo files, prompts, logs, scan outputs, attestations, or run artifacts.
- Every policy bypass or explicit override must be written to `events.jsonl`.

## Required Self-Run

Create and use this run for the work:

```bash
python -m sdlc plan "Resolve production-grade release blockers" \
  --run-id production-grade-release-blockers \
  --risk auto \
  --ui auto \
  --security auto \
  --infra auto
```

During and after implementation run:

```bash
python -m sdlc run production-grade-release-blockers --redteam
python -m sdlc scan production-grade-release-blockers --fail-on-findings
python -m sdlc report production-grade-release-blockers --print
python -m sdlc validate --run-id production-grade-release-blockers
```

If a command returns `NO_GO`, preserve the evidence and fix the underlying issue.
Do not mark the gate complete manually unless the evidence meets the gate contract.

## Workstream 1 - Scanner NO_GO Resolution

Implement scanner result normalization instead of treating every scanner nonzero
return code as a flat blocking failure.

Requirements:

- Parse Bandit JSON and extract severity/confidence/counts per finding.
- Add policy-driven scanner thresholds:
  - CRITICAL/HIGH findings must block by default.
  - MEDIUM blocking should be configurable and default to blocking for high-risk runs.
  - LOW findings should be recorded as residual risk unless policy says to block.
- Keep scanner artifacts raw enough for audit, but redact secrets before writing.
- Do not silently suppress Bandit B404/B603. Either:
  - harden the subprocess wrapper contract and add a narrow `# nosec` with a clear
    local rationale, or
  - leave the finding visible and make the policy threshold treat LOW correctly.
- Ensure `pip-audit` remains blocked unless both `--allow-network` and
  `network_allowed=true` are present.
- Add tests for:
  - Bandit low-only findings do not produce default gate `NO_GO`.
  - Bandit high findings block the gate.
  - `pip-audit` blocked-by-policy remains visible and blocks when dependency audit
    evidence is mandatory.
  - scanner artifacts are referenced from the gate evidence and event ledger.

Expected files likely touched:

- `sdlc/scanners.py`
- `sdlc/engine.py`
- `sdlc/cli.py`
- `sdlc/policies.py`
- `tests/test_core.py`
- docs as needed

## Workstream 2 - Real Cross-Model Red-Team Execution

Replace the deterministic-only red-team path with an orchestrated execution path
that can call real workers only when explicitly requested.

Requirements:

- Keep deterministic red-team generation as a fallback and smoke-test path.
- Add an explicit execution command, for example:
  - `sdlc redteam execute <run-id> --workers openai-codex-primary,openai-codex-adversary --rounds 3 --execute --allow-network`
- Default behavior must be dry-run or evidence-only; no model execution unless
  `--execute` is passed.
- Red-team workers must run read-only and must not edit code.
- Cross-model review for HIGH/EXTREME runs must require at least two independent
  OpenAI/Codex worker aliases under the default policy.
- Unavailable workers must be recorded as evidence and must not be hidden.
- Normalize worker red-team output into findings with schema validation.
- Enforce that implementers cannot close findings they own or created.
- Add tests for dry-run capture, unavailable worker evidence, parsed findings,
  independent closer enforcement, and high-risk cross-model requirements.

Expected files likely touched:

- `sdlc/adapters.py`
- `sdlc/cli.py`
- `sdlc/engine.py`
- `sdlc/models.py`
- `sdlc/prompts.py`
- `sdlc/validation.py`
- `tests/test_core.py`

## Workstream 3 - Deploy Gate Implementation

Implement a deploy gate that is useful but locked by default.

Requirements:

- Add safe commands such as:
  - `sdlc deploy plan <run-id> --env staging|production`
  - `sdlc deploy approve <run-id> --env production --actor human_release_manager --evidence ...`
  - `sdlc deploy execute <run-id> --env production --execute --command "..."`
  - `sdlc deploy verify <run-id> --env production --evidence ...`
  - `sdlc deploy rollback <run-id> --env production --execute --command "..."`
- Production execute must require:
  - `production_rollout_allowed=true`
  - explicit `--execute`
  - human approval authority
  - no open CRITICAL/HIGH findings
  - security scans gate not `NO_GO`
  - red-team gate not `NO_GO`
  - rollback plan evidence
  - smoke/monitoring verification evidence
- Commands must default to dry-run and write artifacts/events.
- Direct production restart/deploy remains blocked unless all policy and approval
  conditions are met.
- Add tests for dry-run plans, blocked production execution, approval evidence,
  finding blockers, and rollback evidence capture.

Expected files likely touched:

- `sdlc/cli.py`
- `sdlc/engine.py`
- `sdlc/models.py`
- `sdlc/policies.py`
- `.sdlc/schemas/**` or schema constants
- `tests/test_core.py`
- docs as needed

## Workstream 4 - Artifact Manifest, Signing, And Attestations

Implement artifact provenance so final reports can prove what evidence was used.

Requirements:

- Generate a deterministic artifact manifest for each run:
  - relative path
  - SHA-256 digest
  - size
  - artifact type
  - producing event
  - timestamp
- Add commands such as:
  - `sdlc attest manifest <run-id>`
  - `sdlc attest sign <run-id> --key <path> --execute`
  - `sdlc attest verify <run-id>`
- Signing must not require secrets in repo files or logs.
- Prefer a small, justified dependency only if needed. If using external signing
  tools such as Sigstore/cosign, keep them optional and record unavailable status.
- Verification failure must block the evidence/attestation gate.
- Add tests for manifest determinism, digest verification, tamper detection,
  missing key handling, dry-run signing, and event ledger entries.

Expected files likely touched:

- new `sdlc/attestations.py`
- `sdlc/cli.py`
- `sdlc/engine.py`
- `sdlc/reporting.py`
- `tests/test_core.py`
- docs as needed

## Workstream 5 - Production Rollout Evidence

Implement production rollout evidence capture without enabling production rollout
by default.

Requirements:

- Add a rollout evidence model or artifact schema covering:
  - environment
  - approved version/commit
  - rollout window
  - smoke test command/result
  - monitoring checks
  - rollback command/result
  - approver
  - residual risks
- Final report must show production gate status clearly:
  - `SKIPPED` when production rollout is not allowed.
  - `NO_GO` when rollout was requested but evidence is missing.
  - `GO_WITH_ACCEPTED_RESIDUAL_RISKS` only with explicit accepted residual risks.
  - `GO` only when all rollout evidence is present and verified.
- Add tests for skipped production gate, requested-but-missing evidence, accepted
  residual risk, and full verified rollout evidence.

Expected files likely touched:

- `sdlc/models.py`
- `sdlc/cli.py`
- `sdlc/engine.py`
- `sdlc/reporting.py`
- `.sdlc/schemas/**` or schema constants
- `tests/test_core.py`

## Required Validation Before Final Response

Always run:

```bash
python -m unittest discover -s tests
python -m sdlc validate
python -m sdlc validate --run-id production-grade-release-blockers
python -m sdlc report production-grade-release-blockers --print
```

Also run the equivalent `python3` or virtualenv commands if `python` is not
available on the machine.

Run real scanner evidence:

```bash
python -m sdlc scan production-grade-release-blockers --fail-on-findings
```

Only run network-enabled dependency audit if both user approval and policy allow it:

```bash
python -m sdlc scan production-grade-release-blockers --allow-network --fail-on-findings
```

## Required Final Response

Lead with the actual verdict. Use only:

- `GO`
- `NO_GO`
- `GO_WITH_ACCEPTED_RESIDUAL_RISKS`

Then include:

- What changed.
- What tests and scanner commands ran.
- Current gate verdicts that are not `GO`.
- Residual risks.
- Unsupported claims removed or avoided.
- What a brutal red-team would still attack.
- Exact next command for the user.

Do not say the product is production-ready unless the final report, security scans,
red-team evidence, attestations, deploy gate, and rollout evidence all prove it.
```
