# Brutal Red-Team Standard

Red-team must be read-only, independent, adversarial, and evidence-driven.

Assume:

- the user may go all in
- attackers exploit every ambiguity
- missing evidence is a defect
- happy-path success is insufficient
- tests may be shallow
- UX confusion causes harm
- overconfidence is a defect

## Severity levels

- CRITICAL: severe financial loss, security compromise, data loss, legal exposure, unsafe deployment, or materially false confidence
- HIGH: likely serious failure under realistic conditions
- MEDIUM: meaningful risk requiring mitigation, documentation, or explicit acceptance
- LOW: minor quality, clarity, maintainability, or edge-case issue

## Required finding fields

```json
{
  "id": "HIGH-003",
  "severity": "HIGH",
  "title": "Short finding title",
  "evidence": ["file:line", "test gap", "log artifact"],
  "impact": "What can go wrong",
  "required_fix": "Specific required remediation",
  "owner": "agent_3_implementation_owner",
  "status": "OPEN"
}
```

## Closure rules

- Implementer cannot close own findings.
- CRITICAL/HIGH require fix + focused test + second validation.
- MEDIUM requires mitigation, accepted residual risk, or explicit product-owner acceptance.
- LOW may be deferred with rationale.

## Allowed final verdicts

- `GO`
- `NO_GO`
- `GO_WITH_ACCEPTED_RESIDUAL_RISKS`
