"""Tests for cost/token usage extraction (sdlc/usage.py)."""

from __future__ import annotations

import unittest

from sdlc import usage


class UsageExtractionTests(unittest.TestCase):
    def test_anthropic(self) -> None:
        u = usage.extract_usage('{"usage": {"input_tokens": 1200, "output_tokens": 350}}')
        self.assertEqual(u["status"], "MEASURED")
        self.assertEqual(u["source"], "anthropic")
        self.assertEqual(u["total_tokens"], 1550)

    def test_openai(self) -> None:
        u = usage.extract_usage('{"usage": {"prompt_tokens": 800, "completion_tokens": 200, "total_tokens": 1000}}')
        self.assertEqual(u["source"], "openai")
        self.assertEqual(u["total_tokens"], 1000)

    def test_gemini(self) -> None:
        u = usage.extract_usage('{"usageMetadata": {"promptTokenCount": 500, "candidatesTokenCount": 150, "totalTokenCount": 650}}')
        self.assertEqual(u["source"], "gemini")
        self.assertEqual(u["total_tokens"], 650)

    def test_nested_and_jsonl(self) -> None:
        # Usage buried in a streaming/wrapped envelope.
        text = 'event: start\n{"type": "result", "data": {"usage": {"input_tokens": 10, "output_tokens": 5}}}\n'
        u = usage.extract_usage(text)
        self.assertEqual(u["status"], "MEASURED")
        self.assertEqual(u["total_tokens"], 15)

    def test_no_usage_is_explicit_unavailable(self) -> None:
        u = usage.extract_usage("plain reply, no token accounting")
        self.assertEqual(u["status"], "UNAVAILABLE")
        self.assertIn("reason", u)

    def test_empty(self) -> None:
        self.assertEqual(usage.extract_usage("")["status"], "UNAVAILABLE")
        self.assertEqual(usage.extract_usage(None)["status"], "UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
