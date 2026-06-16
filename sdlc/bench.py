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

# Dimension kinds, honest about what each score actually reflects:
#   CORPUS       — observed over the real run corpus (counts toward the headline)
#   CAPABILITY   — a real but synthetic exercise of a mechanism (not headline)
#   CONFIG       — a policy/config check, not runtime behavior (not headline)
#   CONSISTENCY  — true largely by construction / tautological (not headline)
#   ENVIRONMENT  — machine-state dependent, e.g. PATH (not headline)
#   ATTESTATION  — depends on an external/human attestation (not headline)
# Only CORPUS dimensions are averaged into the headline, because the others are
# near-constant, environment-specific, or definitional and would inflate it.
HEADLINE_KIND = "CORPUS"


def _measured(value: Any, score: float, unit: str, detail: str, kind: str = "CORPUS") -> dict[str, Any]:
    return {
        "status": "MEASURED",
        "kind": kind,
        "value": value,
        "score": round(max(0.0, min(100.0, score)), 1),
        "unit": unit,
        "detail": detail,
    }


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "UNAVAILABLE", "kind": "UNAVAILABLE", "value": None, "score": None, "unit": None, "detail": reason}


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
                     f"Cold `init` + first `plan` completed in {elapsed:.2f}s (target <300s).",
                     kind="CAPABILITY")


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
                     f"{independent}/{high} HIGH/EXTREME runs assign a red-team worker distinct from the implementer.",
                     kind="CONFIG")


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
                             f"{preserved}/{len(completed)} completed gates preserved across a resume re-run.",
                             kind="CAPABILITY")
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
                     f"{correct}/{len(runs)} runs: release verdict is consistent with blocker presence.",
                     kind="CONSISTENCY")


def _dim_tui_completion(repo: Path) -> dict[str, Any]:
    # Spec FAC 8/22: scored ONLY via an independent reviewer (not the builder), and
    # only when that independence is corroborable by external evidence — NOT a
    # self-declared `is_builder:false` boolean (the builder can write that). We require
    # a `corroboration` block referencing verifiable evidence whose git author/identity
    # differs from the builder (e.g. a screen-recording artifact + a non-builder
    # reviewer commit/OIDC identity). Absent that, this is UNAVAILABLE — a recorded
    # operator attestation does not become a measured, headline-eligible score.
    review_path = repo / "artifacts" / "bench" / "tui_review.json"
    if not review_path.exists():
        return _unavailable("No TUI review on file; independent (non-builder) review required.")
    try:
        review = _json_load(review_path)
    except Exception as exc:  # noqa: BLE001
        return _unavailable(f"TUI review record unreadable: {exc}")
    corroboration = review.get("corroboration")
    if review.get("verdict") != "APPROVED" or not isinstance(corroboration, dict) \
            or not corroboration.get("independent_evidence"):
        return _unavailable(
            "TUI review independence is not corroborated. A self-declared 'is_builder:false' "
            "is insufficient; supply corroboration.independent_evidence (e.g. a screen "
            "recording artifact + a non-builder reviewer identity). Operator attestation is "
            "recorded but not credited as a measured score."
        )
    confirmed = review.get("tasks_confirmed")
    if isinstance(confirmed, int):
        pct = 100.0 * confirmed / 10
        detail = (f"Independent reviewer confirmed {confirmed}/10 tasks without docs; "
                  f"corroboration: {corroboration.get('independent_evidence')}.")
    else:
        pct = 80.0
        detail = ("Independent reviewer attested APPROVED with corroborating evidence "
                  f"({corroboration.get('independent_evidence')}); credited at the 8/10 threshold.")
    return _measured(round(pct, 1), pct, "percent", detail, kind="ATTESTATION")


def _json_load(path: Path) -> Any:
    import json as _json
    return _json.loads(path.read_text(encoding="utf-8"))


def _dim_provider_flexibility(repo: Path) -> dict[str, Any]:
    available = [cli for cli in WORKER_CLIS if shutil.which(cli)]
    score = min(100.0, 100.0 * len(available) / 3)  # target >= 3 families
    return _measured(len(available), score, "worker-families",
                     f"Worker CLIs on PATH: {available or ['<none>']} (target >= 3).",
                     kind="ENVIRONMENT")


def _dim_cost_visibility(repo: Path) -> dict[str, Any]:
    """Measure that cost/token visibility works: the extractor must surface real
    usage for each provider format and an explicit UNAVAILABLE when none is present
    (never silently omit). Executed worker runs carry this via WorkerResult.to_dict.
    Also credits any real worker-result artifacts that surface a usage field."""
    from . import usage as usage_mod

    samples = [
        ("anthropic", '{"usage": {"input_tokens": 1200, "output_tokens": 350}}', "MEASURED"),
        ("openai", '{"usage": {"prompt_tokens": 800, "completion_tokens": 200, "total_tokens": 1000}}', "MEASURED"),
        ("gemini", '{"usageMetadata": {"promptTokenCount": 500, "candidatesTokenCount": 150, "totalTokenCount": 650}}', "MEASURED"),
        ("no_usage", "plain assistant reply with no token accounting", "UNAVAILABLE"),
    ]
    correct = sum(1 for _name, out, expected in samples
                  if usage_mod.extract_usage(out).get("status") == expected)

    # Bonus visibility check over any real executed worker-result artifacts.
    store = RunStore(repo)
    real_total = real_surfaced = 0
    import json as _json
    for run in _list_runs(repo):
        for result in (store.run_dir(run)).glob("worker-results/**/*result*.json"):
            try:
                data = _json.loads(result.read_text(encoding="utf-8"))
            except Exception:
                continue
            if data.get("executed"):
                real_total += 1
                if isinstance(data.get("usage"), dict) and "status" in data["usage"]:
                    real_surfaced += 1

    pct = 100.0 * correct / len(samples)
    detail = (f"Usage extractor surfaced the correct result for {correct}/{len(samples)} "
              "representative provider outputs (anthropic/openai/gemini + no-usage).")
    if real_total:
        detail += f" Real executed worker runs surfacing usage: {real_surfaced}/{real_total}."
    else:
        detail += " No executed worker runs in corpus — this scores the extractor mechanism, not real coverage."
    return _measured(round(pct, 1), pct, "percent", detail, kind="CAPABILITY")


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
    # The headline averages ONLY corpus-observed dimensions. CAPABILITY / CONFIG /
    # CONSISTENCY / ENVIRONMENT / ATTESTATION dimensions are near-constant,
    # environment-specific, or definitional, so counting them would inflate the
    # number (the brutal-audit H1/H4 finding). They are reported separately.
    corpus = [d for d in measured if d.get("kind") == HEADLINE_KIND]
    headline = round(sum(d["score"] for d in corpus) / len(corpus), 1) if corpus else None
    kind_breakdown: dict[str, list[str]] = {}
    for key, dim in dimensions.items():
        kind_breakdown.setdefault(dim.get("kind", "UNAVAILABLE"), []).append(key)
    return {
        "schema": "sdlc.bench.result/v2",
        "runs_evaluated": len(runs),
        "measured_dimensions": len(measured),
        "total_dimensions": len(dimensions),
        "headline_kind": HEADLINE_KIND,
        "headline_score": headline,
        "headline_dimensions": [k for k, d in dimensions.items() if d.get("kind") == HEADLINE_KIND],
        "kind_breakdown": kind_breakdown,
        "corpus_relative": True,
        "note": "headline_score is the mean of CORPUS dimensions only and is relative to "
                "the evaluated run corpus; it is not an absolute tool-quality constant. "
                "Other dimensions are reported by kind (CAPABILITY/CONFIG/CONSISTENCY/"
                "ENVIRONMENT/ATTESTATION) and excluded from the headline.",
        # Back-compat: keep overall_score as an alias of the honest headline.
        "overall_score": headline,
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


def comparative_blocker_identification(repo: Path) -> dict[str, Any]:
    """Measure a real, reproducible factor: how many artifacts an operator must
    inspect to identify the release blockers and their reasons WITHOUT the tool,
    versus the one command the tool needs.

    Conservative by construction (it UNDER-counts the baseline effort):
    - baseline units = plan.json + findings.json + events.jsonl + one evidence
      artifact per gate. It does NOT count the extra effort of re-deriving the
      release-validation rules by hand (which the readiness engine encodes), so the
      true manual cost is higher than reported.
    - tool units = 1 (`sdlc next` returns the blocking gates and reasons directly).

    No other product is measured here; this is a same-task steps proxy, not wall-clock
    and not a Claude Code comparison.
    """
    store = RunStore(repo)
    per_run = []
    for run in _list_runs(repo):
        rd = store.run_dir(run)
        units = 0
        for base in ("plan.json", "findings.json", "events.jsonl"):
            if (rd / base).exists():
                units += 1
        artifacts_dir = rd / "artifacts"
        gate_artifacts = len(list(artifacts_dir.glob("*.md"))) if artifacts_dir.is_dir() else 0
        units += gate_artifacts
        per_run.append({"run_id": run, "baseline_inspection_units": units, "tool_units": 1, "factor": units})
    factors = sorted(r["factor"] for r in per_run)
    if not factors:
        return {"status": "UNAVAILABLE", "reason": "no runs to compare"}
    n = len(factors)
    median = factors[n // 2] if n % 2 else (factors[n // 2 - 1] + factors[n // 2]) / 2
    return {
        "status": "MEASURED",
        "metric": "artifacts inspected to identify release blockers + reasons (manual baseline) vs 1 tool command",
        "runs": n,
        "factor_min": factors[0],
        "factor_median": round(median, 1),
        "factor_max": factors[-1],
        "tool_units": 1,
        "proven_100x": factors[0] >= 100,  # honest: true only if even the WORST run clears 100x
        "note": "Conservative steps proxy; under-counts manual effort (excludes re-deriving validation rules). "
                "Not wall-clock; not a measurement of any other product.",
        "per_run": per_run,
    }


# Capabilities a raw-artifact baseline / generic coding agent cannot produce at all
# (category differences, reported separately — never expressed as a finite ratio).
CAPABILITY_DIFFERENCES = [
    "Deterministic release-readiness verdict (GO/NO_GO) computed from evidence",
    "Tamper-evident gate-evidence ledger with chained digests",
    "Enforced cross-model red-team independence on HIGH/EXTREME runs",
    "Claim-discipline gate blocking unsupported release claims",
    "Per-gate release-blocking reasons without manual rule re-derivation",
]


def comparison_matrix_markdown(result: dict[str, Any], comparative: dict[str, Any] | None = None) -> str:
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
    if comparative and comparative.get("status") == "MEASURED":
        c = comparative
        proven = "YES" if c["proven_100x"] else "NO"
        lines += [
            "",
            "## Measured factor: identifying release blockers",
            "",
            f"Task: find the release blockers and their reasons for a run. "
            f"Metric: {c['metric']}.",
            "",
            f"- Tool: **{c['tool_units']} command**.",
            f"- Manual baseline (conservative): **{c['factor_median']}x** more inspection units "
            f"(median across {c['runs']} runs; range {c['factor_min']}x–{c['factor_max']}x).",
            f"- **100x proven on this metric: {proven}.** "
            + ("" if c["proven_100x"] else "The honest factor is the median above, not 100x."),
            "",
            f"_{c['note']}_",
            "",
            "## Capability differences (category, not a ratio)",
            "",
            "A raw-artifact baseline or generic coding agent cannot produce these at all,",
            "so they are reported as present/absent, never as a finite multiple:",
            "",
            *[f"- {cap}" for cap in CAPABILITY_DIFFERENCES],
        ]
    lines += [
        "",
        "## Honest position",
        "",
        "- We do not claim '100x better than Claude Code'. 100x superiority was not proven.",
        "- The measured advantage on release-blocker identification is the factor above",
        "  (a conservative same-task steps proxy), plus capabilities a generic agent lacks",
        "  entirely.",
        "- The generic-agent column stays NOT MEASURED until we run an equivalent benchmark",
        "  against one; asserting 'better' without that would violate claim discipline.",
        "",
    ]
    return "\n".join(lines)


def report_markdown(result: dict[str, Any]) -> str:
    headline = result.get("headline_score", result.get("overall_score"))
    headline_dims = result.get("headline_dimensions", [])
    lines = [
        "# Benchmark Report",
        "",
        f"Runs evaluated: {result['runs_evaluated']}",
        f"Measured dimensions: {result['measured_dimensions']}/{result['total_dimensions']}",
        f"**Headline score (CORPUS dimensions only): {headline}** — corpus-relative, "
        "not an absolute tool-quality constant.",
        f"Headline dimensions: {', '.join(headline_dims) or '—'}",
        "",
        "## Claim discipline",
        "",
        "100x superiority was not proven. The headline averages only CORPUS dimensions",
        "(observed over the real run corpus). CAPABILITY / CONFIG / CONSISTENCY /",
        "ENVIRONMENT / ATTESTATION dimensions are reported but EXCLUDED from the headline",
        "because they are near-constant, environment-specific, definitional, or",
        "self-attested and would inflate it. Unmeasured dimensions are UNAVAILABLE.",
        "",
        "## Dimensions",
        "",
        "| # | Dimension | Status | Kind | Value | Score | In headline? | Detail |",
        "|---|-----------|--------|------|-------|-------|--------------|--------|",
    ]
    for key, dim in result["dimensions"].items():
        num, name = key.split("_", 1)
        val = dim["value"] if dim["value"] is not None else "—"
        score = dim["score"] if dim["score"] is not None else "—"
        kind = dim.get("kind", "—")
        in_headline = "yes" if kind == result.get("headline_kind", "CORPUS") and dim["status"] == "MEASURED" else "no"
        detail = dim["detail"].replace("|", "\\|")
        lines.append(f"| {num} | {name} | {dim['status']} | {kind} | {val} | {score} | {in_headline} | {detail} |")
    lines.append("")
    return "\n".join(lines)
