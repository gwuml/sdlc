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

## Required Local Checks

Before presenting a run as complete:

```bash
python -m unittest discover -s tests
python -m sdlc validate
python -m sdlc scan <run-id> --allow-network
```

Do not hide missing tools, scanner failures, failed tests, unavailable workers, or skipped gates.

## External Red-Team Workers

For high-stakes runs, external model workers are blocked unless hard read-only source isolation is available. Set the following only when an external sandbox, container, or mount enforces a non-mutable source view:

```bash
export SDLC_AUDIT_HARD_SOURCE_ISOLATION=1
```

This flag is an assertion by the operator. It is not a sandbox by itself. If hard isolation is unavailable, use the product for advisory workflow and keep the red-team gate `NO_GO`.

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
