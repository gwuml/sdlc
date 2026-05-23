# Secure SDLC Pipeline

The canonical pipeline is defined in `sdlc/pipeline.py` and materialized in `.sdlc/pipeline.json` by `sdlc init`.

## Why 25 gates instead of 12?

The original 12-step pipeline was strong for execution prompts. A high-assurance control plane needs additional gates for RACI, privacy, supply chain, threat modeling, observability, provenance, and long-term maintenance.

## Gate verdicts

Allowed final gate verdicts:

- `GO`
- `NO_GO`
- `GO_WITH_ACCEPTED_RESIDUAL_RISKS`
- `SKIPPED` for conditional gates only

Invalid verdicts:

- looks good
- probably fine
- ship it
- no major issues

## Commit and deploy defaults

- Direct main push is blocked by default.
- Deployment is locked by default.
- Production rollout requires explicit policy and human approval.
- Gate 23 is release-satisfied only with ledger-backed Git provenance from the
  control plane, not mutable plan fields or prose evidence. Release validation
  checks the feature branch, current HEAD, commit message discipline, PR plan or
  PR evidence, and local CI/release-gate status. Protected branches remain
  rejected unless policy and an explicit flag allow them.
- Executed workers may edit only their allowed source/docs/test paths. Run
  ledgers, finding state, memory, and gate evidence are protected control-plane
  state; attempted mutations are restored and recorded as policy violations.

## CRITICAL/HIGH fix loop

CRITICAL and HIGH findings must be fixed and re-audited before GO.

Implementers cannot close their own findings.
