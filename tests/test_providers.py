"""Tests for provider abstraction: Ollama adapter + fallback chain."""

from __future__ import annotations

import unittest
from pathlib import Path

from sdlc import adapters


class OllamaAdapterTests(unittest.TestCase):
    def test_registered(self) -> None:
        self.assertIn("ollama", adapters.ADAPTERS)

    def test_command_is_local_and_stdin_based(self) -> None:
        a = adapters.OllamaAdapter(model="llama3")
        cmd = a.build_command(Path("p.md"), Path("."), "PLAN")
        self.assertEqual(cmd[:2], ["ollama", "run"])
        self.assertEqual(cmd[2], "llama3")
        # prompt must not be in argv (delivered via stdin)
        self.assertNotIn("p.md", cmd)

    def test_read_only_by_default(self) -> None:
        self.assertTrue(adapters.OllamaAdapter().security_review_write_protected())


class FallbackChainTests(unittest.TestCase):
    def test_unavailable_preferences_yield_explicit_worker_unavailable(self) -> None:
        result = adapters.select_available_adapter(["definitely-not-a-real-cli-xyz"])
        self.assertEqual(result["status"], "WORKER_UNAVAILABLE")
        self.assertIsNone(result["adapter"])
        # The tried list records what failed — never a silent skip.
        self.assertTrue(result["tried"])

    def test_first_available_is_selected(self) -> None:
        # 'python' as a stand-in CLI that exists on PATH via a custom family.
        import shutil
        existing = "claude" if shutil.which("claude") else None
        prefs = ["definitely-not-real", existing] if existing else ["definitely-not-real"]
        result = adapters.select_available_adapter([p for p in prefs if p])
        if existing:
            self.assertEqual(result["status"], "AVAILABLE")
            self.assertEqual(result["name"], existing)
            self.assertEqual(result["tried"][0][0], "definitely-not-real")
        else:
            self.assertEqual(result["status"], "WORKER_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
