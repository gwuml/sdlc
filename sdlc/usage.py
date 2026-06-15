"""Cost / token usage extraction from worker CLI output.

Worker CLIs report token usage in provider-specific shapes. This module extracts
a normalized usage record so the control plane can *surface* cost for every
executed worker run — or state UNAVAILABLE explicitly when a worker reports none.
Never silently omit cost (goal-spec hallucination/visibility discipline).

Supported shapes:
  - Anthropic:  {"usage": {"input_tokens", "output_tokens"}}
  - OpenAI:     {"usage": {"prompt_tokens", "completion_tokens", "total_tokens"}}
  - Gemini:     {"usageMetadata": {"promptTokenCount", "candidatesTokenCount", "totalTokenCount"}}
"""

from __future__ import annotations

import json
from typing import Any


def _measured(input_tokens: int, output_tokens: int, total: int, source: str) -> dict[str, Any]:
    return {
        "status": "MEASURED",
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total,
        "source": source,
    }


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "UNAVAILABLE", "reason": reason}


def _usage_from_obj(obj: Any) -> dict[str, Any] | None:
    """Recursively locate a recognized usage record inside a parsed JSON value."""
    if isinstance(obj, dict):
        u = obj.get("usage")
        if isinstance(u, dict):
            if "input_tokens" in u or "output_tokens" in u:  # Anthropic
                i = int(u.get("input_tokens", 0) or 0)
                o = int(u.get("output_tokens", 0) or 0)
                return _measured(i, o, i + o, "anthropic")
            if "prompt_tokens" in u or "completion_tokens" in u or "total_tokens" in u:  # OpenAI
                i = int(u.get("prompt_tokens", 0) or 0)
                o = int(u.get("completion_tokens", 0) or 0)
                t = int(u.get("total_tokens", i + o) or (i + o))
                return _measured(i, o, t, "openai")
        meta = obj.get("usageMetadata")
        if isinstance(meta, dict):  # Gemini
            i = int(meta.get("promptTokenCount", 0) or 0)
            o = int(meta.get("candidatesTokenCount", 0) or 0)
            t = int(meta.get("totalTokenCount", i + o) or (i + o))
            return _measured(i, o, t, "gemini")
        for value in obj.values():
            found = _usage_from_obj(value)
            if found:
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = _usage_from_obj(value)
            if found:
                return found
    return None


def _iter_json_objects(text: str):
    """Yield parsed JSON values from text: whole-document, JSONL lines, and
    brace-delimited substrings (handles streaming/wrapped worker output)."""
    stripped = text.strip()
    if not stripped:
        return
    try:
        yield json.loads(stripped)
        return
    except (json.JSONDecodeError, ValueError):
        pass
    for line in stripped.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                yield json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
    # Last resort: scan balanced top-level brace spans.
    depth = 0
    start = -1
    for idx, ch in enumerate(stripped):
        if ch == "{":
            if depth == 0:
                start = idx
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    span = stripped[start: idx + 1]
                    try:
                        yield json.loads(span)
                    except (json.JSONDecodeError, ValueError):
                        pass


def extract_usage(text: str | None) -> dict[str, Any]:
    """Return a normalized usage record, or an explicit UNAVAILABLE marker.

    Always returns a dict with a ``status`` key — cost is never silently omitted.
    """
    if not text:
        return _unavailable("empty worker output")
    for obj in _iter_json_objects(text):
        found = _usage_from_obj(obj)
        if found:
            return found
    return _unavailable("no usage/token fields found in worker output")
