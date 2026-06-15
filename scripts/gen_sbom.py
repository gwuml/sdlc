#!/usr/bin/env python3
"""Generate a CycloneDX SBOM from pyproject.toml declared dependencies.

Deterministic and dependency-free so it runs anywhere (CI uses cyclonedx-py for
resolved versions; this is the committed, reproducible declared-deps baseline).

Usage: python scripts/gen_sbom.py [output_path]
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_pyproject() -> dict:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    try:
        import tomllib  # Python 3.11+
        return tomllib.loads(text)
    except ModuleNotFoundError:
        return {}  # fall back to regex below


def _deps_from_text() -> list[str]:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r"dependencies\s*=\s*\[(.*?)\]", text, re.DOTALL)
    if not m:
        return []
    return re.findall(r'"([^"]+)"', m.group(1))


def _split(spec: str) -> tuple[str, str]:
    m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(.*)$", spec.strip())
    if not m:
        return spec.strip(), ""
    return m.group(1), m.group(2).strip()


def main() -> int:
    data = _load_pyproject()
    project = data.get("project", {})
    deps = project.get("dependencies") or _deps_from_text()
    version = project.get("version", "0.1.0")

    components = []
    for spec in deps:
        name, ver = _split(spec)
        components.append({
            "type": "library",
            "name": name,
            "version": ver or "unspecified",
            "purl": f"pkg:pypi/{name.lower()}",
        })

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "sdlc", "version": version}},
        "components": sorted(components, key=lambda c: c["name"].lower()),
    }

    out = Path(sys.argv[1]) if len(sys.argv) > 1 else (ROOT / "artifacts" / "sbom.cdx.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
    print(f"SBOM written: {out} ({len(components)} components)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
