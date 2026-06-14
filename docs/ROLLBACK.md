# Rollback Plan — Rust binary → Python reference

This plan lets an operator revert from the Rust `sdlc` binary to the Python reference
implementation in place. It satisfies Final Approval Condition 14. The smoke test
below must be executed on a clean machine and produce a verifiable, ledger-anchored
artifact (CI log, screen recording, or attestation by an authorized actor who is not
the implementer) before condition 14 is satisfied. Self-attestation by the
implementer does not satisfy the requirement.

## 1. Exact revert commands

Assuming the Rust binary was installed as `sdlc` on `PATH` and the Python package is
present in the repo:

```bash
# 1. Remove the Rust binary from PATH (adjust prefix to your install location).
sudo rm -f /usr/local/bin/sdlc

# 2. Reinstall the Python reference into an isolated environment.
cd /path/to/sdlc
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .

# 3. Repoint the `sdlc` entry to Python (shim), or invoke directly.
printf '#!/bin/sh\nexec python -m sdlc "$@"\n' | sudo tee /usr/local/bin/sdlc >/dev/null
sudo chmod +x /usr/local/bin/sdlc

# 4. Verify.
sdlc --help
sdlc validate
```

## 2. Backward compatibility

Run artifacts carry an `artifact_schema_version` field. The Python reference reads
artifacts produced by the Rust binary **iff** the schema version is one Python
understands. If the Rust binary introduced a newer schema:

- Diverging formats: any artifact whose `artifact_schema_version` exceeds the Python
  reader's max supported version.
- Migration: `sdlc migrate-artifacts --to-python <run-id>` (provided by the Rust
  binary) downconverts a run's artifacts to the last Python-compatible schema before
  rollback. If the Rust binary is already removed, restore it from the prior release
  to run the migration, or restore artifacts from version control / backup.

If no schema bump occurred (the common case for an in-place revert), Python reads
Rust-produced artifacts directly with no migration.

## 3. Smoke test (< 10 minutes, on-call runnable)

```bash
# On a clean machine with only the Python reference installed:
sdlc --help                                   # entry resolves
sdlc validate                                 # repo structure validates
sdlc status product-self-run                  # an existing run loads
sdlc report product-self-run --print | head   # report renders
python -m unittest discover -s tests 2>&1 | tail -3   # suite runs
```

Expected: every command exits 0 (or the documented NO_GO for `validate --release`),
no stack traces, the existing run loads and reports.

## 4. Artifact preservation check

```bash
# Confirm existing run evidence is intact and readable after rollback.
ls .sdlc/runs/ | wc -l            # expect the same run count as before rollback
sdlc ledger seal-legacy --help    # ledger tooling responds
```

`.sdlc/runs/**` is never modified by the rollback. The revert only changes which
binary serves the `sdlc` command; run evidence, ledgers, and attestations are
untouched.

## 5. Evidence requirement (FAC 14)

Record the smoke-test run as a `rollback.smoke_test_completed` ledger event with a
link to the CI log / recording / attestation. The attesting actor must not be the
implementer.
