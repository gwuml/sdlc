# 12-Agent Parallel SDLC Runs

The SDLC control plane supports explicit 12-role agent planning for high-risk and
extreme-risk work. The default six baseline agents remain active for ordinary
runs. When an operator requests `--parallel 12`, the planner includes the six
conditional specialist roles in the same dependency-free batch:

- `agent_7_ui_architect`
- `agent_8_cybersecurity_engineer`
- `agent_9_sre_sysadmin`
- `agent_10_it_enterprise_integration`
- `agent_11_compliance_audit`
- `agent_12_domain_specialist`

The policy limit is `agents.max_parallel`. It defaults to `12`; requests above
that cap are reduced to the configured maximum. High and extreme risk work still
uses the normal SDLC gates, red-team requirements, permission checks, worker
availability capture, and evidence ledger. Enabling 12-way planning does not
relax any release gate.

Example:

```bash
python -m sdlc --repo /path/to/repo start \
  "Extreme UI/security migration" \
  --risk extreme \
  --ui yes \
  --security yes \
  --infra no \
  --parallel 12 \
  --run-id example-12-agent-run

python -m sdlc --repo /path/to/repo agents plan example-12-agent-run --parallel 12
python -m sdlc --repo /path/to/repo agents execute example-12-agent-run --parallel 12 --execute
```

Use disjoint ownership in the implementation prompt when the target repository
requires multiple code-writing workstreams. The SDLC role plan records each
agent's read/write/deny paths and blocks attempted workspace changes outside
that role's allowed write paths.
