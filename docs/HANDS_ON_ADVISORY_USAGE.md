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

Before any HIGH/EXTREME executed prompt run or release-candidate push, run:

```bash
python -m sdlc release doctor <run-id> --json
```

The doctor fails fast on prerequisites that otherwise appear late: a dirty
worktree, protected branch, missing signing keys, scanner policy/network
mismatch, and missing local red-team sandbox/OAuth prerequisites.

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

For high-stakes runs, external model workers are blocked unless a qualifying hard audit runtime is available. The default path is local macOS `sandbox-exec` with host Codex/OpenAI OAuth copied only into an ephemeral sandbox home. The contract requires a source-write probe, isolated `HOME`, ephemeral writable temp/cache paths, no host credential directory mounts, explicit policy-bound network mode, scoped/host OAuth auth, process containment, cleanup evidence, and a ledger-backed attestation artifact.

Configure the runtime in `.sdlc/policies/<profile>.json`:

```json
{
  "redteam": {
    "audit_isolation": {
      "runtime": "macos_sandbox_exec",
      "network_mode": "host",
      "auth": {"mode": "host_oauth"},
      "auth_env": []
    }
  }
}
```

Run the non-interactive preflight before executed external red-team work:

```bash
python -m sdlc isolation preflight <run-id> --workers openai-codex-primary,openai-codex-adversary --json
```

This local mode does not require Docker. If `sandbox-exec` or host OAuth is unavailable, the red-team worker is rejected instead of falling back to an unisolated host run. Prompt compliance alone is not a security boundary.

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
