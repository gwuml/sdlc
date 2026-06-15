"""Tests for the self-improvement loop (sdlc/learn.py) and its safety rules."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sdlc import learn
from sdlc.models import Finding, GateState, RunPlan


def _plan(run_id: str) -> RunPlan:
    gates = [
        GateState(id="implementation", order=14, title="Impl", owner="agent_3",
                  state="FIX_REQUIRED", verdict="NO_GO"),
        GateState(id="intake_scope", order=1, title="Intake", owner="agent_1",
                  state="GO", verdict="GO", evidence=["a.md"]),
    ]
    return RunPlan(run_id=run_id, created_at="now", feature="f", repo=".", branch="main",
                   risk_level="HIGH", classification={}, production_rollout_allowed=False,
                   direct_main_push_allowed=False, policy_profile="default", gates=gates,
                   agents=[], worker_preferences={"implementation": "codex", "redteam": "codex"})


class LearnTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        (self.repo / ".sdlc").mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_record_captures_blocker_and_monoculture(self) -> None:
        findings = [Finding(id="HIGH-1", severity="HIGH", title="t", evidence=[], impact="i",
                            required_fix="f", owner="agent_3", status="OPEN")]
        r = learn.record_lessons(self.repo, _plan("r1"), findings)
        kinds = {l["kind"] for l in r["lessons"]}
        self.assertIn("gate_blocker", kinds)
        self.assertIn("open_high_findings", kinds)
        self.assertIn("redteam_monoculture", kinds)

    def test_suggest_after_two_runs_creates_proposals(self) -> None:
        learn.record_lessons(self.repo, _plan("r1"), [])
        learn.record_lessons(self.repo, _plan("r2"), [])
        out = learn.suggest_proposals(self.repo, min_occurrences=2)
        self.assertTrue(out["pending"], "recurring lessons should yield proposals")

    def test_apply_requires_actor_and_never_changes_policy(self) -> None:
        learn.record_lessons(self.repo, _plan("r1"), [])
        learn.record_lessons(self.repo, _plan("r2"), [])
        pid = learn.suggest_proposals(self.repo)["pending"][0]["id"]
        # self-approval rejected
        self.assertEqual(learn.apply_proposal(self.repo, pid, actor="", execute=True)["status"], "REJECTED")
        # dry-run does not apply
        self.assertEqual(learn.apply_proposal(self.repo, pid, actor="ravi", execute=False)["status"], "DRY_RUN")
        # execute records approval only
        applied = learn.apply_proposal(self.repo, pid, actor="ravi", execute=True)
        self.assertEqual(applied["status"], "APPLIED")
        self.assertIn("no policy/gate/safety change", applied["effect"])


if __name__ == "__main__":
    unittest.main()
