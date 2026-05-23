# What We Were Not Thinking Of

This document captures gaps that separate a useful AI coding workflow from a stronger Secure SDLC control plane with evidence-backed controls.

## 1. Enforcement, not prompts

A great prompt is not a control. The platform needs a state machine, policy engine, permission model, evidence ledger, and schema-validated gate outputs.

## 2. Supply-chain risk

AI agents often add dependencies casually. A stronger control plane must watch lockfiles, licenses, SBOM/provenance, package reputation, dependency confusion, typosquatting, and artifact signing.

## 3. Secrets and data exfiltration

Terminal agents can accidentally read, summarize, log, or transmit secrets. The system needs deny paths, redaction, network controls, prompt-injection handling, and a policy for external data.

## 4. Model monoculture and collusion

If the same model implements and audits, blind spots repeat. Use cross-model review plus deterministic scanners and tests.

## 5. Human approval authority

You need explicit RACI: who can approve residual risk, security exceptions, production deploys, data access, and direct main push.

## 6. UX can be a security and safety risk

Bad UI can create incorrect decisions, destructive actions, dark patterns, accessibility failures, and false confidence. UI architecture must be a gate, not an afterthought.

## 7. Observability and incident response

Shipping code without metrics, logs, alerts, rollback, and runbooks is not serious for production. The SDLC must include operational readiness.

## 8. Claim discipline

For trading, security, healthcare, infra, and payments, unsupported optimism is dangerous. The platform must remove unsupported claims from prompts and reports.

## 9. Reproducibility

Every run needs a baseline snapshot: git SHA, branch, diff, dependencies, tool versions, prompt hashes, model/worker choices, test commands, and evidence artifacts.

## 10. Artifact provenance and tamper evidence

The system should hash artifacts, record event streams, and eventually produce signed attestations.

## 11. CI and terminal parity

The same engine must work in interactive terminal, non-interactive CI, and later web UI. Do not build a pretty UI that cannot run headless.

## 12. Cost, rate limits, and failure handling

Worker adapters need budgets, retries, timeouts, cancellation, partial-output capture, and graceful degradation when Codex/Claude are unavailable.

## 13. Rollback is not optional

Deployment gates need rollback commands, smoke tests, monitoring windows, canary/feature-flag plans, and rollback decision points.

## 14. Long-term maintenance

A feature can become unsafe after dependency updates, model changes, infra changes, or new threats. Final reports need next-audit triggers.

## 15. Trustworthy final reports

The final report must distinguish between:

- evidence completed
- risks accepted
- tests unavailable
- deployment not performed
- claims not proven

The product should never hide those distinctions.
