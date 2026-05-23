# Red-Team GO Remediation Prompt

You are repairing the `production-grade-release-blockers` run after real cross-model red-team returned `NO_GO`.

Do not claim production readiness, security, compliance, or world-class maturity unless the final run evidence proves the exact claim. Do not weaken the 25-gate pipeline, direct-main protections, production deploy locks, worker dry-run defaults, or finding lifecycle separation.

## Current Findings To Resolve

- `RT-CRITICAL-001`: the release-blocker run is still `NO_GO` by its own evidence.
- `RT-CRITICAL-002`: no Git provenance or real implementation diff exists.
- `RT-HIGH-001`: placeholder artifacts are marked `GO`.
- `RT-HIGH-002`: production execution does not require rollback command evidence or all prior release gates.
- `RT-HIGH-003`: final report is stale or omits current findings.
- `RT-MEDIUM-001`: security scan failure is converted to `GO` without structured residual-risk treatment.
- `RT-MEDIUM-002`: attestations exclude core control-plane truth.

## Required Fixes

1. Ensure dry-run placeholder artifacts cannot mark non-deterministic gates `GO`.
2. Require production execution to have explicit rollout allowance, human approval, no open CRITICAL/HIGH findings, all prior release gates through commit/CI satisfied with evidence, security/red-team gates non-blocking, rollback command planning, and an explicit command.
3. Require `GO_WITH_ACCEPTED_RESIDUAL_RISKS` plus human security/product approval when a `NO_GO` scanner summary is accepted as residual risk; never convert that case to plain `GO`.
4. Include signed control snapshots for plan, findings, filtered event ledger, and final report in attestations while avoiding self-referential attestation recursion.
5. Regenerate the final report after findings/gates change and reject final-report gate completion when the report is stale or omits current findings.
6. Establish Git provenance on a feature branch and capture an implementation diff artifact.
7. Re-run unit tests, validation, attestations, report generation, and real cross-model red-team.

## Verification Commands

```bash
python3 -m unittest discover -s tests
python3 -m sdlc validate
python3 -m sdlc validate --run-id production-grade-release-blockers
python3 -m sdlc report production-grade-release-blockers --print
python3 -m sdlc attest manifest production-grade-release-blockers
python3 -m sdlc attest sign production-grade-release-blockers --key ~/.sdlc-control-plane/attestation.key --execute
python3 -m sdlc attest verify production-grade-release-blockers --key ~/.sdlc-control-plane/attestation.key
python3 -m sdlc redteam execute production-grade-release-blockers --workers openai-codex-primary,openai-codex-adversary --rounds 3 --execute --allow-network --timeout 600 --fail-on-findings
```

The literal `python -m ...` commands may still fail on systems where `python` is not installed; report that honestly and also run the same commands with `python3` or the project virtualenv.
