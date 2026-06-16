<!-- Releases/merges to main require an approving review from a non-author. -->

## What changed

## Why

## Tests run
- [ ] `python -m unittest discover -s tests` passes
- [ ] `python -m sdlc validate` passes
- [ ] `cargo test && cargo fmt --check && cargo clippy -- -D warnings` (if `src/` touched)

## Safety checklist
- [ ] No unsupported "production-ready / secure / 100x" claims added without evidence
- [ ] Does not weaken the red-team loop, FAC-10, secret redaction, or ledger integrity
- [ ] No direct-`main` push / production-deploy defaults introduced

## Risks / follow-ups
