"""Tests for the quality-diff tool (sdlc/diff.py)."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from sdlc import diff

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "runs"


class QualityDiffTests(unittest.TestCase):
    def setUp(self) -> None:
        # Seed a temp repo from committed fixtures so the test is self-contained and
        # passes on a clean clone (.sdlc/runs is gitignored and empty there).
        self._tmp = tempfile.TemporaryDirectory()
        repo = Path(self._tmp.name)
        runs = repo / ".sdlc" / "runs"
        runs.mkdir(parents=True)
        for name in ("scanner-evidence-hardening", "product-self-run"):
            shutil.copytree(FIXTURES / name, runs / name)
        self.result = diff.quality_diff(repo, "scanner-evidence-hardening", "product-self-run")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_all_twelve_structural_fields_present(self) -> None:
        # FAC 23: the output must contain all 12 named structural fields.
        self.assertEqual(len(diff.FIELDS), 12)
        for field in diff.FIELDS:
            self.assertIn(field, self.result["fields"], f"missing structural field: {field}")

    def test_final_verdict_field_compares_old_and_new(self) -> None:
        fv = self.result["fields"]["final_verdict"]
        self.assertIn("old", fv)
        self.assertIn("new", fv)

    def test_distinct_from_bench_compare(self) -> None:
        # diff schema is the structural diff, not the benchmark compare schema.
        self.assertEqual(self.result["schema"], "sdlc.diff.quality/v1")

    def test_markdown_renders_and_lists_fields(self) -> None:
        md = diff.render_markdown(self.result)
        self.assertIn("Quality Diff", md)
        self.assertIn("Final verdict", md)
        for field in diff.FIELDS:
            self.assertIn(field, md)


if __name__ == "__main__":
    unittest.main()
