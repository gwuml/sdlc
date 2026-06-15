# Release Process

This document defines how a release of the `sdlc` binary is cut, who may approve it,
and how supply-chain integrity is enforced. It satisfies Final Approval Condition 17
and supports conditions 9, 15, and 20.

## Release branch and trigger

- The release branch is **`main`**.
- `.github/workflows/release.yml` triggers **only** on:
  - pushes to `main`, and
  - tags matching `v*` created from `main`.
- A guard step fails the workflow if it is invoked from any other ref. Releases may
  not be cut from a feature branch or an arbitrary tag, so branch protection cannot
  be bypassed.

## Branch protection (required)

`main` must have GitHub branch protection configured with:

- Require a pull request before merging.
- Require **at least one approving review from an account that is not the commit
  author** (the independent-reviewer rule).
- Require status checks to pass (build, tests, parity, SBOM-equality, reproducibility,
  100x-claim grep, secrets scan).
- Dismiss stale approvals on new commits.
- No direct pushes to `main`.

## Authorized actors

An **authorized actor** is a human or CI identity that is **not** the author of the
commit, finding, or implementation under review, and is one of:

- a `CODEOWNERS` reviewer on the relevant path,
- a branch-protection required reviewer on `main`, or
- a named human in `KEYS.md` with a GPG/Sigstore-attested identity.

Actor identity for finding closure is verified by HMAC-signed actor proof; the
`actor_proof_required_for_finding_closure` policy flag is ON by default. An actor
string passed without a matching HMAC proof is rejected, preventing string
impersonation.

CRITICAL/HIGH findings may not be closed by the implementer, and may never be
ACCEPTED or DEFERRED — only RESOLVED with evidence by an authorized actor.

Granting a CI identity authority to close findings requires approval by a named human
in `KEYS.md` who is not the implementer, recorded as a `keys.ci_authority_granted`
ledger event before the authority takes effect.

## The workflow is the only build path

Release assets are produced **exclusively** by `release.yml` on a pinned runner
(`ubuntu-22.04`). No release asset may be built on a developer laptop.

**Active path — Python distribution (the current shippable deliverable):**

1. Builds the sdist + wheel with `python -m build`.
2. Generates a CycloneDX SBOM (`sbom.cdx.json`) and fails if any dependency declared
   in `pyproject.toml` is missing from the SBOM (content equality, not count).
3. Produces `SHA256SUMS` over the distribution + SBOM.
4. Signs `SHA256SUMS` with **Sigstore keyless cosign** → `SHA256SUMS.sig` +
   `SHA256SUMS.pem`, logged to the public Rekor transparency log (no stored key).
5. Uploads assets to the GitHub Release on a `v*` tag (build artifacts otherwise).
6. A separate gate fails the run on unsupported "100x" claims in the benchmark report.

**Deferred path — Rust binary (Phase 6, disabled job `rust-binary`):** pinned runners
`ubuntu-22.04` / `macos-14`, `rust-toolchain.toml` verification, double-build for
byte-identical `SHA256SUMS`, and macOS codesign + notarization (needs an Apple
Developer cert via CI secrets). Enable when the Rust binary reaches command parity.

## Release checklist (maps to Final Approval Conditions)

Before tagging, all 23 Final Approval Conditions in `docs/RUST_MIGRATION_PLAN.md`
and the `/goal` spec must be green, including: fixture parity, benchmark scores,
TUI independent evaluation, rollback smoke test (ledger-anchored), and a positive
independent red-team verdict with no implementer-closed CRITICAL/HIGH findings.
