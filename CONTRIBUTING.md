# Contributing

Thanks for considering a contribution. This project is a Secure-SDLC control plane, so
the contribution process intentionally mirrors its own discipline: tests gate merges,
the red-team loop is not optional, and claims need evidence.

## Setup

```bash
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -e .
python -m sdlc --help
```

Rust foundation (optional, for `src/`): a `rustup`-managed toolchain pinned by
`rust-toolchain.toml`.

## Before you open a PR

Run the same gates CI runs (`.github/workflows/ci.yml`):

```bash
python -m unittest discover -s tests      # Python unit + parity tests
python -m sdlc validate                   # repo structure
cargo test && cargo fmt --check && cargo clippy -- -D warnings   # if you touched src/
```

- **Tests are the merge gate.** Add tests for new behavior; don't lower coverage.
- **No unsupported claims.** Don't add "production-ready / secure / 100x" language to
  docs or reports without measured evidence — the benchmark/report tooling enforces this.
- **Don't weaken the safety rules** (see `AGENTS.md`): the red-team loop, FAC-10
  (CRITICAL/HIGH can't be accepted into a positive verdict), no direct-`main` push by
  default, no production deploy by default, secret redaction, ledger integrity.
- **Small, focused PRs.** One concern per PR. Match the surrounding code style.

## Commit and PR conventions

- Commit subject: `verb: subject` (e.g. `fix: enforce FAC-10 in Python`).
- Branch from `main`; open a PR. `main` requires an approving review from a **code
  owner** (`.github/CODEOWNERS`) who is **not** the commit author, plus green
  `python` / `rust` / `secrets-scan` checks (see `docs/RELEASE_PROCESS.md`).
- Fill in the PR template (what changed, tests run, risks).
- Outside contributors work from a fork; a maintainer must approve the first workflow
  run before CI executes on your PR.

### Signed commits are required

`main` enforces **signed commits** for the PR path — your PR cannot merge cleanly with
unsigned commits (admins bypass this, but you should not rely on that). Configure signing
once (SSH signing reuses an existing key):

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

Then add the **same public key** to GitHub under *Settings → SSH and GPG keys → New SSH
key → Key type: "Signing Key"*. (GPG signing works too; see GitHub's docs.) Commits made
through the GitHub web UI/API are signed automatically.

## Reporting bugs / requesting features

Use the issue templates under `.github/ISSUE_TEMPLATE/`. For anything security-related,
follow `SECURITY.md` instead of opening a public issue.

## Docs that orient you

- `docs/USAGE.md` — install + 25 use cases.
- `docs/FEATURE_GATE_MAP.md` — every feature → gate → command → evidence path.
- `AGENTS.md` — roles, write-ownership, hard safety rules.
- `docs/PIPELINE.md` — the 25-gate definitions.
