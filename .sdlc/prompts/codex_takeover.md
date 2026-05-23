# Codex Takeover Prompt — Continue SDLC Control Plane Development

You are Codex taking over initial development of this repository.

## Mission

Advance this repo from starter product to a stronger terminal-native Secure SDLC control plane.

The tool turns a feature request into a gated, evidence-driven, adversarial software delivery run. Codex/Claude are workers; the orchestrator is the authority.

## Non-goals

- Do not replace the orchestrator with a generic prompt generator.
- Do not weaken the 25-gate pipeline.
- Do not enable direct `origin/main` push by default.
- Do not enable production deploy/restart by default.
- Do not let implementers close their own red-team findings.
- Do not claim the product is production-ready unless gates prove that exact claim.

## Repo context

Important files:

```text
AGENTS.md
README.md
sdlc/cli.py
sdlc/pipeline.py
sdlc/classifier.py
sdlc/engine.py
sdlc/adapters.py
sdlc/ledger.py
sdlc/models.py
sdlc/prompts.py
sdlc/reporting.py
docs/PRODUCT_SPEC.md
docs/PIPELINE.md
docs/RED_TEAM_STANDARD.md
docs/INTERFACE_CONTROLS.md
tests/test_core.py
```

## Required first actions

1. Read `AGENTS.md`.
2. Read `README.md`.
3. Run:

```bash
python -m unittest discover -s tests
python -m sdlc validate
```

4. Inspect the current CLI:

```bash
python -m sdlc --help
python -m sdlc init --help
python -m sdlc plan --help
python -m sdlc worker --help
```

## Use this repo's own 25-gate pipeline

For any meaningful feature, create a self-run:

```bash
python -m sdlc plan "<feature>" --risk auto --ui auto --security auto --infra auto
python -m sdlc run <run-id> --redteam
python -m sdlc report <run-id> --print
```

## Initial development priorities

### Priority 1 — Worker output capture

The repo now has basic finding lifecycle and gate completion commands. Improve worker adapters so Codex/Claude output is captured into:

```text
.sdlc/runs/<run-id>/worker-results/
.sdlc/runs/<run-id>/events.jsonl
```

Do not execute workers unless `--execute` is passed.

### Priority 2 — Stronger gate advancement validation

The repo now has a basic `sdlc gate complete` command. Strengthen it with JSON Schema validation, role authorization, and gate dependency checks.

### Priority 3 — Full-screen TUI

The repo has a simple `sdlc tui <run-id>` command. Upgrade it into a real full-screen terminal command center showing:

- gate timeline
- findings
- evidence paths
- worker status
- approval queue
- permissions matrix
- command hints

Do not add heavy dependencies unless justified.

### Priority 4 — Git integration

Add safe Git commands:

```bash
sdlc git branch <run-id>
sdlc git commit <run-id> --message "feat: ..."
sdlc git pr <run-id>
```

Rules:

- default branch must be feature branch
- direct main push blocked unless policy allows and explicit flag is passed
- commit requires no open CRITICAL/HIGH findings

## Testing requirements

Add unit tests for every new command.

Always run:

```bash
python -m unittest discover -s tests
python -m sdlc validate
```

## Red-team yourself before final response

Before claiming completion, produce an implementer self-review:

- What changed?
- What tests ran?
- What risks remain?
- What unsupported claims were removed?
- What would a brutal red-team still attack?

## Commit discipline

Use:

```text
verb: subject
```

Do not push to main unless explicitly authorized.
