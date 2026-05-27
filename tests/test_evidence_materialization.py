from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sdlc.cli import _gate_artifact_content_error


class EvidenceMaterializationTests(unittest.TestCase):
    def test_machine_transcript_stdout_does_not_trip_keyword_stuffing_guard(self) -> None:
        terms = (
            "decision consequence json schema command contract invariant failure mode "
            "trust boundary threat model abuse cases misuse cases security acceptance "
            "metric log alert runbook incident response"
        )
        text = "\n".join([
            "# deterministic_quality.lint_result",
            "artifact_type: machine_command_transcript",
            "provenance: gate.required_artifact_recorded for deterministic_quality.lint_result",
            "scope: deterministic quality command transcript",
            "acceptance: release validation parses the command transcript and ledger binding.",
            "evidence_id: deterministic_quality.lint_result",
            "claim: lint_result is supported by a machine-captured transcript.",
            "method: execute configured command and capture stdout, stderr, cwd, timestamp, and returncode.",
            "result: command completed with returncode: 0.",
            "limitations: this transcript does not replace scanner, red-team, or finalization gates.",
            "supporting_artifacts: command:python -m unittest discover -s tests, .sdlc/runs/run-id/events.jsonl",
            "timestamp: 2026-05-26T00:00:00+00:00",
            "cwd: /tmp/repo",
            "command: python -m unittest discover -s tests",
            "returncode: 0",
            "stdout:",
            terms,
            "stderr:",
            "<empty>",
            "Concrete references: .sdlc/runs/run-id/events.jsonl, sdlc/evidence.py, gate.required_artifact_recorded, python -m unittest discover -s tests.",
            "",
        ])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lint_result.md"
            path.write_text(text, encoding="utf-8")
            self.assertIsNone(_gate_artifact_content_error("deterministic_quality", "lint_result", path, text))


if __name__ == "__main__":
    unittest.main()
