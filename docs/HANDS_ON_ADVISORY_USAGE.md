# Hands-On Advisory Usage

This project is currently usable as an advisory Secure SDLC control plane. Treat outputs as evidence for pull requests, operator review, and release discussions. Do not treat a `GO` verdict as production deployment authority.

## Fresh Advisory Run

```bash
python -m sdlc start "Describe the feature or fix" --run-id hands-on-advisory
python -m sdlc run hands-on-advisory --redteam
python -m sdlc status hands-on-advisory --persist
python -m sdlc next hands-on-advisory --persist
python -m sdlc report hands-on-advisory --print
```

Use `status` and `next` to decide the next hands-on task. The orchestrator should show `Authority mode: ADVISORY` until blockers are gone. Even then, production authority remains disabled unless a human release owner explicitly approves deployment and records rollback evidence.

`sdlc run` performs a full no-worker advisory pass. It creates architecture,
implementation, QA, and red-team gate artifacts even when Codex/Claude workers
are not executed. Gates with real local evidence can become `GO`; gates that
need an implementation diff, executed independent red-team, provenance, or human
release evidence are marked `NO_GO`/`FIX_REQUIRED` with concrete next steps
rather than being left pending.

## Required Local Checks

Before presenting a run as complete:

```bash
python -m unittest discover -s tests
python -m sdlc validate
python -m sdlc scan <run-id> --allow-network
```

Do not hide missing tools, scanner failures, failed tests, unavailable workers, or skipped gates.

## External Red-Team Workers

For high-stakes runs, external model workers are blocked unless a qualifying container/VM audit runtime is available. The hard-isolation contract requires a read-only source mount, a live source-write probe, isolated `HOME`, ephemeral writable temp/cache paths, no host credential directory mounts, explicit policy-bound network mode, brokered/scoped/absent auth, process containment, cleanup evidence, and a ledger-backed attestation artifact.

Configure the runtime in `.sdlc/policies/<profile>.json`:

```json
{
  "redteam": {
    "audit_isolation": {
      "runtime": "container",
      "container_engine": "auto",
      "container_image": "your-audit-worker-image@sha256:<digest>",
      "network_mode": "none",
      "auth": {"mode": "brokered"},
      "auth_env": ["SDLC_AUDIT_BROKER_URL"]
    }
  }
}
```

Run the non-interactive preflight before executed external red-team work:

```bash
python -m sdlc isolation preflight <run-id> --workers openai-codex-primary,openai-codex-adversary --json
```

On macOS, `sandbox-exec` may still be used as advisory source-write protection, but it is not counted as hard audit isolation unless strict host-read and credential containment can be attested. An environment flag alone is not accepted. If container/VM hard isolation is unavailable, use the product for advisory workflow and keep the red-team gate `NO_GO`. Prompt compliance alone is not a security boundary.

## Safe Iteration Loop

```bash
python -m sdlc status <run-id>
python -m sdlc next <run-id>
# implement the next narrow fix
python -m unittest discover -s tests
python -m sdlc validate
python -m sdlc run <run-id> --redteam
python -m sdlc report <run-id> --print
```

Commit only evidence-backed changes. Keep production deploy/restart as an explicit human-approved action, not a default command.
