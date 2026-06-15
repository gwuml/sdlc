"""Tests for the dashboard view-model (sdlc/dashboard.py)."""

from __future__ import annotations

import unittest
from pathlib import Path

from sdlc import dashboard
from sdlc.models import Finding, GateState, RunPlan


def _plan() -> RunPlan:
    gates = [
        GateState(id="intake_scope", order=1, title="Intake", owner="agent_1", state="GO", verdict="GO",
                  evidence=["artifacts/intake_scope.md"]),
        GateState(id="implementation", order=14, title="Impl", owner="agent_3", state="FIX_REQUIRED",
                  verdict="NO_GO", evidence=[]),
        GateState(id="deploy_rollout_postdeploy", order=24, title="Deploy", owner="agent_6", state="SKIPPED",
                  verdict="SKIPPED", conditional_on="production_rollout_allowed"),
    ]
    return RunPlan(
        run_id="t", created_at="now", feature="Build a thing", repo=".", branch="main",
        risk_level="HIGH", classification={}, production_rollout_allowed=False,
        direct_main_push_allowed=False, policy_profile="default", gates=gates,
        agents=[], worker_preferences={"implementation": "codex", "redteam": "claude"},
    )


def _readiness() -> dict:
    return {
        "release_satisfied": False,
        "authority_mode": "ADVISORY",
        "blockers": ["Local final verdict is NO_GO; release gates are not satisfied."],
        "gate_readiness": [
            {"gate_id": "intake_scope", "release_state": "BLOCKED"},
            {"gate_id": "implementation", "release_state": "BLOCKED"},
            {"gate_id": "deploy_rollout_postdeploy", "release_state": "SKIPPED_VALID"},
        ],
    }


class DashboardModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = dashboard.build_dashboard_model(
            Path("."), _plan(),
            [Finding(id="HIGH-001", severity="HIGH", title="no diff evidence", evidence=[], impact="x",
                     required_fix="y", owner="agent_3", status="OPEN")],
            _readiness(), {"command": "sdlc next t"},
        )

    def test_next_blocking_gate_is_first_blocked(self) -> None:
        self.assertEqual(self.model["next_blocking_gate"], "intake_scope")

    def test_skipped_valid_gate_is_not_blocking(self) -> None:
        deploy = next(g for g in self.model["gates"] if g["id"] == "deploy_rollout_postdeploy")
        self.assertFalse(deploy["blocking"])

    def test_critical_high_findings_surfaced(self) -> None:
        self.assertEqual(len(self.model["critical_high_findings"]), 1)
        self.assertEqual(self.model["critical_high_findings"][0]["id"], "HIGH-001")

    def test_unavailable_tasks_have_explicit_banners_not_blank(self) -> None:
        # Tasks 6, 9, 10 must say UNAVAILABLE, never be empty (spec requirement).
        for key in ("resume_status", "github_status", "cost_status"):
            self.assertIn("UNAVAILABLE", self.model[key])

    def test_all_ten_tasks_present(self) -> None:
        answers = dashboard.task_answers(self.model)
        self.assertEqual(len(answers), 10)
        # Every task has a non-empty answer.
        for label, answer in answers:
            self.assertTrue(answer, f"task {label} has no answer")

    def test_render_plain_is_80col_safe_and_complete(self) -> None:
        text = dashboard.render_plain(self.model)
        self.assertIn("SDLC CONTROL PLANE", text)
        self.assertIn("Next blocking gate: intake_scope", text)
        self.assertIn("GITHUB:", text)
        self.assertIn("COST:", text)
        # Header/separator lines stay within 80 columns.
        for line in text.splitlines():
            self.assertLessEqual(len(line), 80, f"line exceeds 80 cols: {line!r}")


if __name__ == "__main__":
    unittest.main()
