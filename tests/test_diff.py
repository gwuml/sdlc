"""Tests for the quality-diff tool (sdlc/diff.py)."""

from __future__ import annotations

import unittest
from pathlib import Path

from sdlc import diff


def _repo() -> Path:
    return Path(__file__).resolve().parent.parent


class QualityDiffTests(unittest.TestCase):
    def setUp(self) -> None:
        # Two real fixtures that both have plan.json + findings.json.
        self.result = diff.quality_diff(_repo(), "scanner-evidence-hardening", "product-self-run")

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
