"""Tests for the measured benchmark harness (sdlc/bench.py)."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from sdlc import bench

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "runs"
_SEEDED: "tempfile.TemporaryDirectory | None" = None


def setUpModule() -> None:
    # Seed a temp repo from committed fixtures so bench tests are deterministic and
    # pass on a clean clone (the working repo's .sdlc/runs is gitignored/empty there).
    global _SEEDED
    _SEEDED = tempfile.TemporaryDirectory()
    runs = Path(_SEEDED.name) / ".sdlc" / "runs"
    runs.mkdir(parents=True)
    for run in _FIXTURES.iterdir():
        if run.is_dir():
            shutil.copytree(run, runs / run.name)


def tearDownModule() -> None:
    if _SEEDED is not None:
        _SEEDED.cleanup()


class BenchHelperTests(unittest.TestCase):
    def test_measured_clamps_and_rounds_score(self) -> None:
        d = bench._measured(7, 142.5, "x", "detail")
        self.assertEqual(d["status"], "MEASURED")
        self.assertEqual(d["score"], 100.0)  # clamped to 100
        d2 = bench._measured(7, -5, "x", "detail")
        self.assertEqual(d2["score"], 0.0)  # clamped to 0

    def test_unavailable_has_no_score(self) -> None:
        d = bench._unavailable("no tooling")
        self.assertEqual(d["status"], "UNAVAILABLE")
        self.assertIsNone(d["score"])
        self.assertEqual(d["detail"], "no tooling")

    def test_compare_tolerates_freeform_baseline(self) -> None:
        before = {"overall_score": None, "dimensions": {"1_x": "UNAVAILABLE — old"}}
        after = {"overall_score": 80.0, "dimensions": {"1_x": bench._measured(1, 80, "u", "d")}}
        diff = bench.compare(before, after)
        self.assertEqual(diff["dimensions"]["1_x"]["before"], "UNAVAILABLE")
        self.assertEqual(diff["dimensions"]["1_x"]["after"], "MEASURED")
        self.assertEqual(diff["dimensions"]["1_x"]["after_score"], 80.0)

    def test_report_states_100x_not_proven(self) -> None:
        result = bench.measure(_repo(), _stub_readiness)
        md = bench.report_markdown(result)
        self.assertIn("100x superiority was not proven", md)

    def test_comparison_matrix_is_honest(self) -> None:
        result = bench.measure(_repo(), _stub_readiness)
        md = bench.comparison_matrix_markdown(result)
        # No 'better' claim without measuring the other tool.
        self.assertIn("NOT MEASURED", md)
        self.assertIn("100x superiority was not proven", md)

    def test_headline_counts_only_corpus_dimensions(self) -> None:
        # The headline must average ONLY CORPUS-kind dimensions; capability/config/
        # consistency/environment/attestation dims must be excluded (audit H1/H4).
        result = bench.measure(_repo(), _stub_readiness)
        self.assertEqual(result["headline_kind"], "CORPUS")
        for key in result["headline_dimensions"]:
            self.assertEqual(result["dimensions"][key]["kind"], "CORPUS")
        for key in ("8_release_readiness_accuracy", "10_provider_flexibility", "9_tui_task_completion"):
            self.assertNotIn(key, result["headline_dimensions"])

    def test_comparative_factor_is_measured_and_not_faked(self) -> None:
        c = bench.comparative_blocker_identification(_repo())
        self.assertEqual(c["status"], "MEASURED")
        self.assertEqual(c["tool_units"], 1)
        self.assertIsInstance(c["proven_100x"], bool)
        # proven_100x must reflect the WORST run, not be asserted optimistically.
        self.assertEqual(c["proven_100x"], c["factor_min"] >= 100)


class BenchMeasureTests(unittest.TestCase):
    def test_measure_returns_all_twelve_dimensions(self) -> None:
        result = bench.measure(_repo(), _stub_readiness)
        self.assertEqual(result["total_dimensions"], 12)
        self.assertEqual(len(result["dimensions"]), 12)
        for dim in result["dimensions"].values():
            self.assertIn(dim["status"], {"MEASURED", "UNAVAILABLE"})
            if dim["status"] == "MEASURED":
                self.assertIsInstance(dim["score"], float)
                self.assertGreaterEqual(dim["score"], 0.0)
                self.assertLessEqual(dim["score"], 100.0)

    def test_no_dimension_carries_a_faked_score(self) -> None:
        # The core honesty invariant: a dimension is either MEASURED with a real
        # 0-100 score, or UNAVAILABLE with NO score. Never an UNAVAILABLE-with-score.
        result = bench.measure(_repo(), _stub_readiness)
        for key, dim in result["dimensions"].items():
            if dim["status"] == "UNAVAILABLE":
                self.assertIsNone(dim["score"], f"{key} is UNAVAILABLE but carries a score")
            else:
                self.assertEqual(dim["status"], "MEASURED", f"{key} has an invalid status")
                self.assertIsInstance(dim["score"], float, f"{key} MEASURED without a numeric score")

    def test_tui_dimension_requires_independent_review(self) -> None:
        # Without a review file, dim 9 is UNAVAILABLE; a builder-authored review
        # does not count.
        import tempfile
        from pathlib import Path as _P
        with tempfile.TemporaryDirectory() as tmp:
            r = bench._dim_tui_completion(_P(tmp))
            self.assertEqual(r["status"], "UNAVAILABLE")


def _repo() -> Path:
    # The fixture-seeded temp repo (clean-clone safe), not the working tree.
    assert _SEEDED is not None
    return Path(_SEEDED.name)


def _stub_readiness(run_id: str) -> dict:
    # Deterministic readiness so the test does not depend on engine internals:
    # blockers present and not satisfied (consistent => accuracy dimension scores high).
    return {
        "release_satisfied": False,
        "blockers": ["stub blocker"],
        "gate_readiness": [{"gate_id": "intake_scope", "release_state": "BLOCKED"}],
    }


if __name__ == "__main__":
    unittest.main()
