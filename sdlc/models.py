"""Data models for the Secure SDLC control plane."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


VALID_GATE_STATES = {"PENDING", "READY", "RUNNING", "GO", "NO_GO", "FIX_REQUIRED", "SKIPPED", "WAIVED", "BLOCKED"}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
VALID_FINAL_VERDICTS = {"GO", "NO_GO", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"}


@dataclass
class GateState:
    id: str
    order: int
    title: str
    owner: str
    state: str = "PENDING"
    verdict: str | None = None
    evidence: list[str] = field(default_factory=list)
    notes: str = ""
    conditional_on: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GateState":
        return cls(**data)


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    evidence: list[str]
    impact: str
    required_fix: str
    owner: str
    status: str = "OPEN"
    closed_by: str | None = None
    closure_evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        return cls(**data)


@dataclass
class RunPlan:
    run_id: str
    created_at: str
    feature: str
    repo: str
    branch: str
    risk_level: str
    classification: dict[str, Any]
    production_rollout_allowed: bool
    direct_main_push_allowed: bool
    policy_profile: str
    gates: list[GateState]
    agents: list[dict[str, str]]
    worker_preferences: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["gates"] = [gate.to_dict() for gate in self.gates]
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RunPlan":
        data = dict(data)
        data["gates"] = [GateState.from_dict(gate) for gate in data["gates"]]
        return cls(**data)


def open_findings(findings: list[Finding], severities: set[str] | None = None) -> list[Finding]:
    if severities is None:
        severities = VALID_SEVERITIES
    terminal_statuses = {"CLOSED", "ACCEPTED"}
    return [
        finding
        for finding in findings
        if finding.severity in severities
        and finding.status not in terminal_statuses
        and not (finding.status == "DEFERRED" and finding.severity == "LOW")
    ]


def plan_condition_value(plan: RunPlan | None, condition: str | None) -> Any:
    """Resolve gate conditions from their canonical plan location."""

    if plan is None or not condition:
        return None
    if hasattr(plan, condition):
        return getattr(plan, condition)
    if condition in plan.classification:
        return plan.classification[condition]
    return None
