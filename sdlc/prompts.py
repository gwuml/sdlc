"""Prompt rendering utilities."""

from __future__ import annotations

import tempfile
import re
from pathlib import Path

from .models import RunPlan
from .util import sha256_text


PROMPT_BINDING_RE = re.compile(r"^Prompt binding SHA256:\s*([a-f0-9]{64}|<pending>|<bound>)\s*$", re.MULTILINE)
PROMPT_BINDING_CANONICAL_LINE = "Prompt binding SHA256: <bound>"
PROMPT_JSON_BINDING_RE = re.compile(r'("prompt_sha256":\s*")([a-f0-9]{64}|<pending>|<bound>)(")')
PROMPT_TEXT_BINDING_RE = re.compile(r'(prompt_sha256:\s*")([a-f0-9]{64}|<pending>|<bound>)(")')


def canonical_redteam_prompt_text(text: str) -> str:
    text = PROMPT_BINDING_RE.sub(PROMPT_BINDING_CANONICAL_LINE, text, count=1)
    text = PROMPT_JSON_BINDING_RE.sub(r"\1<bound>\3", text)
    text = PROMPT_TEXT_BINDING_RE.sub(r"\1<bound>\3", text)
    return text


def redteam_prompt_binding_sha256(text: str) -> str:
    return sha256_text(canonical_redteam_prompt_text(text))


def bind_redteam_prompt(plan: RunPlan) -> str:
    base = render_redteam_prompt(plan, PROMPT_BINDING_CANONICAL_LINE.rsplit(" ", 1)[-1])
    digest = redteam_prompt_binding_sha256(base)
    prompt = render_redteam_prompt(plan, digest)
    if redteam_prompt_binding_sha256(prompt) != digest:
        raise RuntimeError("red-team prompt binding is not stable")
    return prompt


def render_execution_prompt(plan: RunPlan) -> str:
    classification = plan.classification
    gates_md = "\n".join(
        f"{gate.order:02d}. **{gate.title}** (`{gate.id}`) — owner: `{gate.owner}`, mode: `{gate.state}`"
        for gate in plan.gates
    )
    agents_md = "\n".join(f"- `{agent['id']}`: {agent['role']}" for agent in plan.agents)
    reasons_md = "\n".join(f"- {reason}" for reason in classification.get("reasons", []))

    return f"""# Secure SDLC Execution Prompt: {plan.feature}

This prompt is directly executable by an AI coding agent, but the orchestrator is the authority. The agent must not skip gates, relax safety rules, or claim readiness without evidence.

## Mission
Build the requested feature under a gated Secure SDLC pipeline.

Feature request:

```text
{plan.feature}
```

## Non-goals
- Do not deploy, restart production, mutate secrets, run destructive commands, or push to `origin/main` unless the run policy explicitly permits it and a human approval gate is recorded.
- Do not claim profitability, security, safety, compliance, or production readiness unless the exact claim is proven by completed gates.
- Do not broaden scope without a PM/coordinator gate update.

## Repo, branch, environment context
- Repo: `{plan.repo}`
- Branch at planning time: `{plan.branch}`
- Risk level: `{plan.risk_level}`
- Policy profile: `{plan.policy_profile}`
- Production rollout allowed: `{plan.production_rollout_allowed}`
- Direct main push allowed: `{plan.direct_main_push_allowed}`

## Risk reasons
{reasons_md}

## Active agents
{agents_md}

## Hard rules
1. The orchestrator gate engine is authoritative; model text alone cannot advance a gate.
2. Red-team is read-only and cannot edit implementation.
3. Implementer cannot close its own findings.
4. All CRITICAL/HIGH findings require fixes and second validation.
5. MEDIUM findings require mitigation, documented residual risk, or explicit product-owner acceptance.
6. Direct main push is blocked by default.
7. Deployment is locked by default.
8. Every final claim must be traceable to evidence.
9. For high-stakes systems, assume the user may go all in; overconfidence is a defect.
10. If UI is touched, UI architecture and accessibility acceptance criteria are mandatory before implementation.

## Pipeline gates
{gates_md}

## Required red-team standard
The red-team review must be brutal, adversarial, and honest. It must assume realistic attackers, confused users, market loss, security compromise, operational failure, and prompt-injection attempts where relevant.

Required finding table:

| Severity | Finding | Evidence | Impact | Required fix | Status |
|---|---|---|---|---|---|

Allowed final verdicts only:
- `GO`
- `NO_GO`
- `GO_WITH_ACCEPTED_RESIDUAL_RISKS`

## Commit and deployment discipline
Use commit format:

```text
verb: subject
```

Default behavior:
- Commit locally only after gates allow it.
- Push feature branch and open PR.
- Do not push `origin/main` unless explicitly authorized by policy and human approval.
- Do not deploy unless production rollout is explicitly included and authorized.
- End-of-run branch housekeeping is required:
  - If policy and human approval permit direct `main` integration, merge or fast-forward
    the approved run changes into `main`, push `origin/main`, and delete only the SDLC
    branches/worktrees created for that run after recording their SHAs.
  - If direct `main` integration is not approved, leave the feature branch intact, record
    the exact merge command, PR/push status, cleanup commands, and approval still needed.
  - Never merge unrelated, stale, failed, or abandoned branches just because they exist.
  - Never discard uncommitted work without first recording an explicit stash, patch, or
    operator-approved discard note in the final report.

## Final report format
Include:
- Mission completed / not completed
- Gate verdicts
- Evidence index
- Test results
- Security scan results
- Red-team findings and closure evidence
- Residual risks
- Unsupported claims removed
- Rollback commands if deployment occurred
- Monitoring/post-deploy validation if deployment occurred
- Branch integration and cleanup status, including kept/deleted branch SHAs
- Next audit triggers
"""


def render_redteam_prompt(plan: RunPlan, prompt_sha256: str | None = None) -> str:
    host_temp = tempfile.gettempdir()
    return f"""# Brutal Red-Team Audit Prompt

Feature: {plan.feature}
Risk: {plan.risk_level}

Run ID: {plan.run_id}
Prompt binding SHA256: {prompt_sha256 or "<pending>"}

You are the independent red-team. You are read-only with respect to the source repository. The orchestrator may execute you inside a disposable audit workspace so tests can write temporary files without mutating the source repo. For high-stakes external audits, the orchestrator must enforce or attest hard source isolation before launching you; prompt compliance is only a secondary control. You must be adversarial, evidence-driven, and honest. Assume the user may go all in. Optimism is not evidence. Do not edit source repository files. Write audit notes and test scratch data only to the orchestrator-provided temp directory (`TMPDIR`, `TMP`, or `TEMP`) and never to the audited source tree. If you run tests, use the orchestrator-provided environment without overriding it to a repository path: `cd "${{SDLC_WORKER_REPO:?orchestrator_repo_not_set}}" && PYTHONDONTWRITEBYTECODE=1 TMPDIR="${{TMPDIR:?orchestrator_TMPDIR_not_set}}" python -m unittest discover -s tests`. Do not set TMPDIR to `$PWD/.sdlc-redteam-tmp`; the adapter provides a writable temp directory outside the audited source tree. Codex security reviews use a writable temp harness as the primary workspace while `SDLC_WORKER_REPO` points to the audited source outside that writable root.

If you run release validation from the disposable audit workspace, use
`cd "${{SDLC_WORKER_REPO:?orchestrator_repo_not_set}}" && PYTHONPATH="${{SDLC_CONTROL_PLANE_PYTHONPATH:?orchestrator_control_plane_pythonpath_not_set}}" PYTHONDONTWRITEBYTECODE=1 TMPDIR="${{TMPDIR:?orchestrator_TMPDIR_not_set}}" python -m sdlc validate --run-id {plan.run_id} --release --audit-workspace`.
The exact release-authoritative command without `--audit-workspace` must still
pass in the original repository before the orchestrator can claim completion.

The red-team gate runs before the fix-loop, attestation, commit/CI, deploy, and
final-report gates. Do not create a blocking finding solely because those later
gates are pending in the active run. Do create a finding if the implementation
would allow a release, final report, deployment, or production-readiness claim to
go positive despite missing or stale evidence.

A current `NO_GO` report or blocked gate state is correct while remediation is
in progress. Treat it as a finding only when the control plane would let that
state be overread as release-ready or would allow it to become positive without
the required evidence.

Do not file a finding whose only evidence is that the active run's authoritative
release validation is `NO_GO` because current, newly parsed, or prior red-team
findings are open. That is expected gate behavior. Instead, identify the
specific code or policy defect that could make the orchestrator falsely report a
positive release verdict with those findings or later gates unresolved.

Audit:
- requirements and non-goals
- architecture and invariants
- UI/UX and accessibility if relevant
- security and abuse cases
- implementation diff
- tests and evidence gaps
- deployment and rollback assumptions
- final claims and overconfidence

Keep the audit bounded and evidence-backed. Prefer targeted inspection of source,
tests, the current plan/findings/final report, scanner summaries, attestation
records, and the latest worker evidence. Do not enumerate all historical
`.sdlc/runs/**/worker-results/**` unless a specific current claim depends on it.
Do not cite old worker output, old implementation patch artifacts, or previous
failed validation transcripts as evidence for a current defect if newer source
files, tests, scanner summaries, or validation logs supersede them. A finding
about current source code must cite the current source file. A finding about
test reproducibility must come from a fresh command you ran in this audit
workspace, not from an older `worker-results/**/stdout.txt` transcript.

Keep command output small enough for the orchestrator to capture the final
verdict evidence. Do not dump broad file ranges or full run artifacts. Use
targeted `rg`, `sed`, or `nl` windows around exact symbols, cap exploratory
output with `head`/`tail`, and stop command exploration once you have enough
evidence to decide. The final JSON object is mandatory; if your stdout is
truncated before that object, the orchestrator must treat your audit as `NO_GO`.

Return exactly one JSON object and no prose outside JSON:

```json
{{
  "verdict": "GO|NO_GO|GO_WITH_ACCEPTED_RESIDUAL_RISKS",
  "reviewed_run_id": "{plan.run_id}",
  "prompt_sha256": "{prompt_sha256 or '<pending>'}",
  "findings": [
    {{
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "title": "short finding title",
      "evidence": ["file-or-command evidence"],
      "impact": "why this matters",
      "required_fix": "what must change",
      "owner": "agent role"
    }}
  ]
}}
```

Use verdict `NO_GO` when any CRITICAL/HIGH/MEDIUM finding remains. A positive
verdict must include `reviewed_run_id: "{plan.run_id}"` and `prompt_sha256:
"{prompt_sha256 or '<pending>'}"`.
"""


def render_ui_architect_prompt(plan: RunPlan) -> str:
    return f"""# UI Architect Prompt

Feature: {plan.feature}

You own UI architecture before implementation. Define:
- user flows
- information architecture
- component contracts
- loading, empty, error, permission-denied, success, and destructive-action states
- keyboard navigation
- screen-reader criteria
- responsive behavior
- copy constraints
- dark-pattern risks
- measurable acceptance criteria

Do not implement. Produce the UI contract that implementation and QA must satisfy.
"""


def write_prompt_bundle(run_dir: Path, plan: RunPlan) -> dict[str, str]:
    prompts_dir = run_dir / "prompts"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    redteam_prompt = bind_redteam_prompt(plan)
    bundle = {
        "execution_prompt.md": render_execution_prompt(plan),
        "redteam_prompt.md": redteam_prompt,
        "ui_architect_prompt.md": render_ui_architect_prompt(plan),
    }
    written: dict[str, str] = {}
    for name, content in bundle.items():
        path = prompts_dir / name
        path.write_text(content, encoding="utf-8")
        written[name] = str(path)
    return written
