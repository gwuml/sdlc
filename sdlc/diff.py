"""Quality-diff between two runs — `sdlc diff quality <old> <new>`.

Compares two runs across 12 structural fields (distinct from `sdlc bench compare`,
which scores benchmark dimensions). Fields with no underlying data are marked
UNAVAILABLE rather than omitted — same honesty discipline as the benchmark.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .engine import RunStore, final_verdict
from .models import Finding, RunPlan

CLAIM_WORDS = ["production-ready", "world-class", "100x", "compliant", "profitable", "bug-free"]
EVIDENCE_MARKERS = ["evidence", "ledger", "artifact", "sha256", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"]
SCANNERS = ["bandit", "detect-secrets", "pip-audit", "checkov"]

# The 12 structural fields, in order (FAC 23 asserts all are present).
FIELDS = [
    "gate_states", "evidence_coverage", "finding_lifecycle", "release_blockers",
    "unsupported_claim_count", "scanner_coverage", "redteam_findings", "prompt_overrides",
    "provider_model_choices", "cost_token_usage", "elapsed_time_per_gate", "final_verdict",
]


def _load(store: RunStore, run_id: str) -> tuple[RunPlan, list[Finding], list[dict[str, Any]], Path]:
    plan = store.load_plan(run_id)
    findings = store.load_findings(run_id)
    run_dir = store.run_dir(run_id)
    events: list[dict[str, Any]] = []
    ep = run_dir / "events.jsonl"
    if ep.exists():
        for line in ep.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return plan, findings, events, run_dir


def _blocking_gates(plan: RunPlan) -> set[str]:
    return {g.id for g in plan.gates
            if g.state in {"NO_GO", "FIX_REQUIRED", "BLOCKED"} or g.verdict == "NO_GO"}


def _finding_status_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.status] = counts.get(f.status, 0) + 1
    return counts


def _unsupported_claims(run_dir: Path) -> Any:
    report = run_dir / "final-report.md"
    if not report.exists():
        return "UNAVAILABLE"
    text = report.read_text(encoding="utf-8", errors="replace").lower()
    has_evidence = any(m in text for m in EVIDENCE_MARKERS)
    return sum(1 for w in CLAIM_WORDS if w in text and not has_evidence)


def _scanner_coverage(run_dir: Path) -> dict[str, bool]:
    art = run_dir / "artifacts"
    return {s: (art / f"{s}.json").exists() for s in SCANNERS}


def _redteam_findings(findings: list[Finding]) -> dict[str, int]:
    rt = [f for f in findings if f.id.startswith("RT-") or "redteam" in f.owner]
    by_sev: dict[str, int] = {}
    for f in rt:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return by_sev


def _elapsed_per_gate(events: list[dict[str, Any]]) -> Any:
    starts = {e["gate"]: e.get("ts") for e in events if e.get("event") == "gate.started" and e.get("gate")}
    ends = {e["gate"]: e.get("ts") for e in events if e.get("event") == "gate.completed" and e.get("gate")}
    common = [g for g in starts if g in ends]
    if not common:
        return "UNAVAILABLE"
    # Report which gates have a measurable start/complete pair (timestamps are ISO,
    # not differenced here to avoid tz parsing — presence is the structural signal).
    return {"gates_with_timing": sorted(common), "count": len(common)}


def _prompt_overrides(run_dir: Path) -> Any:
    custom = run_dir.parent.parent / ".sdlc" / "prompts"
    if custom.is_dir():
        files = [p.name for p in custom.glob("custom_*.md")]
        return files or "none"
    return "none"


def _cost_token_usage(run_dir: Path) -> Any:
    found = []
    for result in run_dir.glob("worker-results/**/*result*.json"):
        try:
            data = json.loads(result.read_text(encoding="utf-8"))
        except Exception:
            continue
        u = data.get("usage")
        if isinstance(u, dict) and u.get("status") == "MEASURED":
            found.append({"worker": data.get("worker"), "total_tokens": u.get("total_tokens")})
    return found or "UNAVAILABLE"


def quality_diff(repo: Path, old_id: str, new_id: str) -> dict[str, Any]:
    store = RunStore(repo)
    o_plan, o_find, o_events, o_dir = _load(store, old_id)
    n_plan, n_find, n_events, n_dir = _load(store, new_id)

    o_gates = {g.id: g for g in o_plan.gates}
    n_gates = {g.id: g for g in n_plan.gates}
    gate_states = {}
    for gid in sorted(set(o_gates) | set(n_gates)):
        og, ng = o_gates.get(gid), n_gates.get(gid)
        old_sv = f"{og.state}/{og.verdict}" if og else "—"
        new_sv = f"{ng.state}/{ng.verdict}" if ng else "—"
        gate_states[gid] = {"old": old_sv, "new": new_sv, "changed": old_sv != new_sv}

    evidence_coverage = {
        gid: {"old": len(o_gates[gid].evidence) if gid in o_gates else 0,
              "new": len(n_gates[gid].evidence) if gid in n_gates else 0}
        for gid in sorted(set(o_gates) | set(n_gates))
    }

    o_ids = {f.id for f in o_find}
    n_ids = {f.id for f in n_find}
    finding_lifecycle = {
        "old_counts": _finding_status_counts(o_find),
        "new_counts": _finding_status_counts(n_find),
        "added_ids": sorted(n_ids - o_ids),
        "removed_ids": sorted(o_ids - n_ids),
    }

    o_block, n_block = _blocking_gates(o_plan), _blocking_gates(n_plan)
    release_blockers = {
        "added": sorted(n_block - o_block),
        "removed": sorted(o_block - n_block),
        "unchanged": sorted(o_block & n_block),
    }

    fields = {
        "gate_states": gate_states,
        "evidence_coverage": evidence_coverage,
        "finding_lifecycle": finding_lifecycle,
        "release_blockers": release_blockers,
        "unsupported_claim_count": {"old": _unsupported_claims(o_dir), "new": _unsupported_claims(n_dir)},
        "scanner_coverage": {"old": _scanner_coverage(o_dir), "new": _scanner_coverage(n_dir)},
        "redteam_findings": {"old": _redteam_findings(o_find), "new": _redteam_findings(n_find)},
        "prompt_overrides": {"old": _prompt_overrides(o_dir), "new": _prompt_overrides(n_dir)},
        "provider_model_choices": {"old": dict(o_plan.worker_preferences or {}),
                                   "new": dict(n_plan.worker_preferences or {})},
        "cost_token_usage": {"old": _cost_token_usage(o_dir), "new": _cost_token_usage(n_dir)},
        "elapsed_time_per_gate": {"old": _elapsed_per_gate(o_events), "new": _elapsed_per_gate(n_events)},
        "final_verdict": {"old": final_verdict(o_find, o_plan), "new": final_verdict(n_find, n_plan)},
    }
    return {"schema": "sdlc.diff.quality/v1", "old_run": old_id, "new_run": new_id, "fields": fields}


def render_markdown(diff: dict[str, Any]) -> str:
    f = diff["fields"]
    lines = [
        f"# Quality Diff: {diff['old_run']} -> {diff['new_run']}",
        "",
        f"Final verdict: **{f['final_verdict']['old']}** -> **{f['final_verdict']['new']}**",
        "",
        "## Gate state changes",
    ]
    changed = [(g, v) for g, v in f["gate_states"].items() if v["changed"]]
    if not changed:
        lines.append("- none")
    for gid, v in changed:
        lines.append(f"- {gid}: {v['old']} -> {v['new']}")
    rb = f["release_blockers"]
    lines += [
        "",
        "## Release blockers",
        f"- added: {rb['added'] or 'none'}",
        f"- removed: {rb['removed'] or 'none'}",
        f"- unchanged: {len(rb['unchanged'])}",
        "",
        "## Findings",
        f"- added: {f['finding_lifecycle']['added_ids'] or 'none'}",
        f"- removed: {f['finding_lifecycle']['removed_ids'] or 'none'}",
        "",
        "## Provider/model choices",
        f"- old: {f['provider_model_choices']['old']}",
        f"- new: {f['provider_model_choices']['new']}",
        "",
        f"_All 12 structural fields are present in the JSON output ({', '.join(FIELDS)})._",
    ]
    return "\n".join(lines)
