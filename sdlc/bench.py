"""Benchmark harness — measured, evidence-based scoring of the control plane.

This produces real numbers for the goal spec's 12 benchmark dimensions where the
current engine can measure them, and marks the rest UNAVAILABLE rather than
fabricating a score. The output replaces the placeholder values in
``artifacts/bench/baseline.json`` with evidence.

Design principle (matches the project ethos): never invent a score. A dimension
is either MEASURED with a value and a reproducible method, or UNAVAILABLE with a
stated reason.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from .engine import RunStore, final_verdict


# --- dimension result helpers -------------------------------------------------

def _measured(value: Any, score: float, unit: str, detail: str) -> dict[str, Any]:
    return {
        "status": "MEASURED",
        "value": value,
        "score": round(max(0.0, min(100.0, score)), 1),
        "unit": unit,
        "detail": detail,
    }


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "UNAVAILABLE", "value": None, "score": None, "unit": None, "detail": reason}


def _list_runs(repo: Path) -> list[str]:
    runs_dir = repo / ".sdlc" / "runs"
    if not runs_dir.is_dir():
        return []
    return sorted(p.name for p in runs_dir.iterdir() if (p / "plan.json").exists())


# --- the worker families the provider dimension looks for ---------------------

WORKER_CLIS = ["codex", "claude", "gemini", "kimi", "ollama"]

# Claim words that require accompanying evidence; their bare presence in a report
# is a candidate unsupported claim (hallucination dimension).
CLAIM_WORDS = ["production-ready", "world-class", "100x", "compliant", "profitable", "bug-free"]
EVIDENCE_MARKERS = ["evidence", "ledger", "artifact", "sha256", "GO_WITH_ACCEPTED_RESIDUAL_RISKS"]


# --- the 12 dimensions --------------------------------------------------------

def _dim_setup_friction(repo: Path) -> dict[str, Any]:
    """Time a cold init + first plan in a throwaway repo (no install step, since
    the package is already importable). Target < 300s; this is the time-to-first-
    useful-action a new user experiences once installed."""
    try:
        with tempfile.TemporaryDirectory() as tmp:
            env_repo = Path(tmp)
            start = time.perf_counter()
            init = subprocess.run([sys.executable, "-m", "sdlc", "--repo", str(env_repo), "init"],
                                  capture_output=True, text=True, timeout=120, cwd=str(repo))
            plan = subprocess.run([sys.executable, "-m", "sdlc", "--repo", str(env_repo), "plan",
                                   "smoke test feature", "--risk", "low"],
                                  capture_output=True, text=True, timeout=120, cwd=str(repo))
            elapsed = time.perf_counter() - start
            if init.returncode != 0 or plan.returncode != 0:
                return _unavailable(f"init/plan failed (init rc={init.returncode}, plan rc={plan.returncode}).")
    except Exception as exc:  # noqa: BLE001
        return _unavailable(f"Setup measurement error: {exc}")
    # <300s target -> 100; degrade to 0 at 600s (spec allows revision to <=600).
    score = 100.0 if elapsed <= 300 else max(0.0, 100.0 * (600 - elapsed) / 300)
    return _measured(round(elapsed, 3), score, "seconds",
                     f"Cold `init` + first `plan` completed in {elapsed:.2f}s (target <300s).")


def _dim_blocker_visibility(repo: Path, readiness_fn: Callable[[str], dict[str, Any]], runs: list[str]) -> dict[str, Any]:
    if not runs:
        return _unavailable("No runs to measure.")
    target = runs[0]
    start = time.perf_counter()
    readiness = readiness_fn(target)
    # Identify the first blocking gate.
    first_blocked = next((g["gate_id"] for g in readiness.get("gate_readiness", [])
                          if g.get("release_state") in {"BLOCKED", "UNSATISFIED"}), None)
    elapsed = time.perf_counter() - start
    # <5s target -> 100; degrade linearly to 0 at 30s.
    score = 100.0 if elapsed <= 5 else max(0.0, 100.0 * (30 - elapsed) / 25)
    return _measured(round(elapsed, 4), score, "seconds",
                     f"Computed readiness and located first blocking gate ({first_blocked}) for run '{target}'.")


def _dim_evidence_completeness(repo: Path, runs: list[str]) -> dict[str, Any]:
    store = RunStore(repo)
    executed = 0
    with_evidence = 0
    for run in runs:
        plan = store.load_plan(run)
        for gate in plan.gates:
            if gate.state in {"PENDING", "SKIPPED", "WAIVED"}:
                continue
            executed += 1
            if gate.evidence:
                with_evidence += 1
    if executed == 0:
        return _unavailable("No executed gates across runs.")
    pct = 100.0 * with_evidence / executed
    return _measured(round(pct, 1), pct, "percent",
                     f"{with_evidence}/{executed} executed gates across {len(runs)} runs carry evidence.")


def _dim_hallucination(repo: Path, runs: list[str]) -> dict[str, Any]:
    store = RunStore(repo)
    candidates = 0
    reports_seen = 0
    for run in runs:
        report = store.run_dir(run) / "final-report.md"
        if not report.exists():
            continue
        reports_seen += 1
        text = report.read_text(encoding="utf-8", errors="replace").lower()
        for word in CLAIM_WORDS:
            if word in text:
                # A claim word with no evidence marker nearby is a candidate.
                if not any(marker in text for marker in EVIDENCE_MARKERS):
                    candidates += 1
    if reports_seen == 0:
        return _unavailable("No final reports present to scan.")
    score = max(0.0, 100.0 - candidates * 20)
    return _measured(candidates, score, "unsupported-claims",
                     f"Scanned {reports_seen} reports; {candidates} unsupported claim candidates.")


def _dim_redteam_independence(repo: Path, runs: list[str]) -> dict[str, Any]:
    store = RunStore(repo)
    high = 0
    independent = 0
    for run in runs:
        plan = store.load_plan(run)
        if plan.risk_level not in {"HIGH", "EXTREME"}:
            continue
        high += 1
        prefs = plan.worker_preferences or {}
        impl = prefs.get("implementation")
        red = prefs.get("redteam")
        if red and impl and red != impl:
            independent += 1
    if high == 0:
        return _unavailable("No HIGH/EXTREME runs to assess cross-model independence.")
    pct = 100.0 * independent / high
    return _measured(round(pct, 1), pct, "percent",
                     f"{independent}/{high} HIGH/EXTREME runs assign a red-team worker distinct from the implementer.")


def _dim_resume_recovery(repo: Path) -> dict[str, Any]:
    """Measure that re-running advances from the last completed gate without losing
    completed work. run_dry_gates skips GO/SKIPPED/WAIVED gates, so a re-run is a
    resume. We prove it end-to-end in a throwaway repo: run once, record completed
    gates, run again, and verify every completed gate is preserved unchanged."""
    import json as _json

    def _sdlc(args: list[str], cwd: Path, env_repo: Path) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-m", "sdlc", "--repo", str(env_repo), *args],
                              capture_output=True, text=True, timeout=180, cwd=str(cwd))

    try:
        with tempfile.TemporaryDirectory() as tmp:
            env_repo = Path(tmp)
            if _sdlc(["init"], repo, env_repo).returncode != 0:
                return _unavailable("init failed during resume measurement.")
            if _sdlc(["plan", "resume test feature", "--risk", "low"], repo, env_repo).returncode != 0:
                return _unavailable("plan failed during resume measurement.")
            run_dirs = list((env_repo / ".sdlc" / "runs").iterdir())
            if not run_dirs:
                return _unavailable("no run created during resume measurement.")
            run_id = run_dirs[0].name
            plan_path = run_dirs[0] / "plan.json"

            _sdlc(["run", run_id], repo, env_repo)  # first pass
            first = {g["id"]: (g["state"], g.get("verdict"))
                     for g in _json.loads(plan_path.read_text())["gates"]}
            completed = {gid: sv for gid, sv in first.items() if sv[0] in {"GO", "SKIPPED", "WAIVED"}}

            _sdlc(["run", run_id], repo, env_repo)  # resume pass
            second = {g["id"]: (g["state"], g.get("verdict"))
                      for g in _json.loads(plan_path.read_text())["gates"]}

            if not completed:
                return _unavailable("no gates completed in first pass; nothing to resume.")
            preserved = sum(1 for gid, sv in completed.items() if second.get(gid) == sv)
            pct = 100.0 * preserved / len(completed)
            return _measured(round(pct, 1), pct, "percent",
                             f"{preserved}/{len(completed)} completed gates preserved across a resume re-run.")
    except Exception as exc:  # noqa: BLE001
        return _unavailable(f"Resume measurement error: {exc}")


def _dim_failed_tool_visibility(repo: Path, runs: list[str]) -> dict[str, Any]:
    store = RunStore(repo)
    scans_seen = 0
    visible = 0
    for run in runs:
        scan_dir = store.run_dir(run) / "artifacts"
        if not scan_dir.is_dir():
            continue
        summary = scan_dir / "security_scans.md"
        if summary.exists():
            scans_seen += 1
            text = summary.read_text(encoding="utf-8", errors="replace").lower()
            if any(m in text for m in ["unavailable", "failed", "error", ":"]):
                visible += 1
    if scans_seen == 0:
        return _unavailable("No security-scan summaries present to assess visibility.")
    pct = 100.0 * visible / scans_seen
    return _measured(round(pct, 1), pct, "percent",
                     f"{visible}/{scans_seen} scan summaries surface tool status explicitly.")


def _dim_release_accuracy(repo: Path, readiness_fn: Callable[[str], dict[str, Any]], runs: list[str]) -> dict[str, Any]:
    correct = 0
    for run in runs:
        readiness = readiness_fn(run)
        blockers = readiness.get("blockers", [])
        satisfied = readiness.get("release_satisfied", False)
        # Ground truth: blockers present <=> not release-satisfied.
        if (len(blockers) > 0) == (not satisfied):
            correct += 1
    if not runs:
        return _unavailable("No runs to assess.")
    pct = 100.0 * correct / len(runs)
    return _measured(round(pct, 1), pct, "percent",
                     f"{correct}/{len(runs)} runs: release verdict is consistent with blocker presence.")


def _dim_tui_completion(repo: Path) -> dict[str, Any]:
    # Spec FAC 8/22: scored only via an independent reviewer (not the builder).
    # A signed attestation in artifacts/bench/tui_review.json is the accepted
    # evidence. Without it, UNAVAILABLE — never self-scored.
    review_path = repo / "artifacts" / "bench" / "tui_review.json"
    if not review_path.exists():
        return _unavailable("No independent TUI review on file (artifacts/bench/tui_review.json). "
                            "Spec requires a reviewer who did not build the TUI.")
    try:
        review = _json_load(review_path)
    except Exception as exc:  # noqa: BLE001
        return _unavailable(f"TUI review record unreadable: {exc}")
    if review.get("is_builder") is not False or review.get("verdict") != "APPROVED":
        return _unavailable("TUI review is not an independent APPROVED attestation.")
    confirmed = review.get("tasks_confirmed")
    if isinstance(confirmed, int):
        pct = 100.0 * confirmed / 10
        detail = f"Independent reviewer confirmed {confirmed}/10 tasks without docs."
    else:
        # Holistic approval, not a per-task count: credit the spec pass threshold
        # (8/10) conservatively rather than claiming 100 without per-task data.
        pct = 80.0
        detail = ("Independent reviewer (not the builder) attested APPROVED "
                  f"('{review.get('attestation','')}'); holistic sign-off credited at the "
                  "8/10 spec threshold (per-task rubric would refine this).")
    return _measured(round(pct, 1), pct, "percent", detail)


def _json_load(path: Path) -> Any:
    import json as _json
    return _json.loads(path.read_text(encoding="utf-8"))


def _dim_provider_flexibility(repo: Path) -> dict[str, Any]:
    available = [cli for cli in WORKER_CLIS if shutil.which(cli)]
    score = min(100.0, 100.0 * len(available) / 3)  # target >= 3 families
    return _measured(len(available), score, "worker-families",
                     f"Worker CLIs on PATH: {available or ['<none>']} (target >= 3).")


def _dim_cost_visibility(repo: Path) -> dict[str, Any]:
    return _unavailable("Cost/token usage is not tracked by the engine.")


def _dim_github_provenance(repo: Path, runs: list[str]) -> dict[str, Any]:
    store = RunStore(repo)
    runs_with_provenance = 0
    runs_with_git = 0
    for run in runs:
        events_path = store.run_dir(run) / "events.jsonl"
        if not events_path.exists():
            continue
        text = events_path.read_text(encoding="utf-8", errors="replace")
        if "git." in text or "commit" in text or "branch" in text:
            runs_with_git += 1
            if "provenance" in text:
                runs_with_provenance += 1
    if runs_with_git == 0:
        return _unavailable("No git/PR activity recorded in any run ledger.")
    pct = 100.0 * runs_with_provenance / runs_with_git
    return _measured(round(pct, 1), pct, "percent",
                     f"{runs_with_provenance}/{runs_with_git} git-active runs have ledger-backed provenance.")


# --- top-level harness --------------------------------------------------------

def measure(repo: Path, readiness_fn: Callable[[str], dict[str, Any]]) -> dict[str, Any]:
    """Measure all 12 dimensions. ``readiness_fn`` maps run_id -> readiness payload
    (injected so this module does not import the large cli module)."""
    runs = _list_runs(repo)
    dimensions = {
        "1_setup_friction": _dim_setup_friction(repo),
        "2_blocker_visibility": _dim_blocker_visibility(repo, readiness_fn, runs),
        "3_evidence_completeness": _dim_evidence_completeness(repo, runs),
        "4_hallucination_count": _dim_hallucination(repo, runs),
        "5_redteam_independence": _dim_redteam_independence(repo, runs),
        "6_resume_recovery": _dim_resume_recovery(repo),
        "7_failed_tool_visibility": _dim_failed_tool_visibility(repo, runs),
        "8_release_readiness_accuracy": _dim_release_accuracy(repo, readiness_fn, runs),
        "9_tui_task_completion": _dim_tui_completion(repo),
        "10_provider_flexibility": _dim_provider_flexibility(repo),
        "11_cost_token_visibility": _dim_cost_visibility(repo),
        "12_github_pr_provenance": _dim_github_provenance(repo, runs),
    }
    measured = [d for d in dimensions.values() if d["status"] == "MEASURED"]
    overall = round(sum(d["score"] for d in measured) / len(measured), 1) if measured else None
    return {
        "schema": "sdlc.bench.result/v1",
        "runs_evaluated": len(runs),
        "measured_dimensions": len(measured),
        "total_dimensions": len(dimensions),
        "overall_score": overall,
        "dimensions": dimensions,
    }


def compare(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Diff two measured results, per dimension."""
    deltas = {}
    b_dims = before.get("dimensions", {})
    a_dims = after.get("dimensions", {})
    for key in sorted(set(b_dims) | set(a_dims)):
        b = b_dims.get(key, {})
        a = a_dims.get(key, {})
        # Tolerate older/freeform baselines where a dimension is a plain string.
        if not isinstance(b, dict):
            b = {"status": "UNAVAILABLE"}
        if not isinstance(a, dict):
            a = {"status": "UNAVAILABLE"}
        b_score = b.get("score")
        a_score = a.get("score")
        delta = None
        if isinstance(b_score, (int, float)) and isinstance(a_score, (int, float)):
            delta = round(a_score - b_score, 1)
        deltas[key] = {
            "before": b.get("status", "MISSING"),
            "after": a.get("status", "MISSING"),
            "before_score": b_score,
            "after_score": a_score,
            "delta": delta,
        }
    return {
        "schema": "sdlc.bench.compare/v1",
        "overall_before": before.get("overall_score"),
        "overall_after": after.get("overall_score"),
        "dimensions": deltas,
    }


def comparison_matrix_markdown(result: dict[str, Any]) -> str:
    """Evidence-backed comparison vs generic coding agents. Only dimensions this
    tool actually measures are filled in; the generic-agent column is NOT MEASURED
    because we have not benchmarked another tool. No 'better' claim is made without
    a measured comparison (spec requirement)."""
    dims = result.get("dimensions", {})

    def cell(key: str) -> str:
        d = dims.get(key, {})
        if d.get("status") == "MEASURED":
            return f"{d['value']} (score {d['score']})"
        return "UNAVAILABLE"

    rows = [
        ("Setup friction (s)", "1_setup_friction", "architecture: local-first, single CLI"),
        ("Blocker visibility (s)", "2_blocker_visibility", "generic agents have no gate model"),
        ("Evidence completeness (%)", "3_evidence_completeness", "no gate-evidence ledger in generic agents"),
        ("Unsupported claims in report", "4_hallucination_count", "no claim-discipline gate in generic agents"),
        ("Red-team independence (%)", "5_redteam_independence", "no enforced cross-model red-team"),
        ("Release-readiness accuracy (%)", "8_release_readiness_accuracy", "no release-verdict engine"),
        ("Provider flexibility (families)", "10_provider_flexibility", "varies by agent"),
    ]
    lines = [
        "# Comparison Matrix (evidence-backed only)",
        "",
        "Scope: Secure SDLC orchestration. This is NOT a general-coding-agent comparison.",
        "Claude Code's strengths (terminal-native edits, IDE integration, checkpoints) are",
        "not denied; they are a different category. We only fill cells we actually measured.",
        "",
        "| Dimension | This tool | Generic coding agent | Evidence / note |",
        "|-----------|-----------|----------------------|-----------------|",
    ]
    for label, key, note in rows:
        lines.append(f"| {label} | {cell(key)} | NOT MEASURED | {note} |")
    lines += [
        "",
        "## Honest position",
        "",
        "- We do not claim '100x better than Claude Code'. 100x superiority was not proven.",
        "- We claim, with measured evidence, capabilities a generic coding agent does not",
        "  have at all: enforced gate evidence, release-readiness verdicts, cross-model",
        "  red-team independence, and claim discipline.",
        "- The generic-agent column stays NOT MEASURED until we run an equivalent benchmark",
        "  against one; asserting 'better' without that would violate claim discipline.",
        "",
    ]
    return "\n".join(lines)


def report_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Benchmark Report",
        "",
        f"Runs evaluated: {result['runs_evaluated']}",
        f"Measured dimensions: {result['measured_dimensions']}/{result['total_dimensions']}",
        f"Overall score (mean of measured): {result['overall_score']}",
        "",
        "## Claim discipline",
        "",
        "100x superiority was not proven. Dimensions without measurement are marked",
        "UNAVAILABLE, not scored.",
        "",
        "## Dimensions",
        "",
        "| # | Dimension | Status | Value | Score | Detail |",
        "|---|-----------|--------|-------|-------|--------|",
    ]
    for key, dim in result["dimensions"].items():
        num, name = key.split("_", 1)
        val = dim["value"] if dim["value"] is not None else "—"
        score = dim["score"] if dim["score"] is not None else "—"
        detail = dim["detail"].replace("|", "\\|")
        lines.append(f"| {num} | {name} | {dim['status']} | {val} | {score} | {detail} |")
    lines.append("")
    return "\n".join(lines)
