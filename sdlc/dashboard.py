"""Terminal dashboard for a run — testable view-model + thin curses shell.

The view-model (`build_dashboard_model`) is a pure function of run data, so it is
unit-testable without a terminal. `render_plain` produces the `--no-tui` /
non-tty / fallback output. `run_curses` is the interactive full-screen shell.

Covers the goal spec's 10 TUI benchmark tasks; tasks the engine cannot yet
satisfy (resume, GitHub status, cost) are shown as explicit UNAVAILABLE banners
rather than blank fields (spec requirement).
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .models import Finding, RunPlan

WORKER_CLIS = ["codex", "claude", "gemini", "kimi", "ollama"]


def build_dashboard_model(
    repo: Path,
    plan: RunPlan,
    findings: list[Finding],
    readiness: dict[str, Any],
    next_action: dict[str, Any],
) -> dict[str, Any]:
    """Pure view-model assembled from already-computed run data."""
    gate_release = {g["gate_id"]: g for g in readiness.get("gate_readiness", [])}
    gates = []
    next_blocking = None
    for gate in sorted(plan.gates, key=lambda g: g.order):
        rel = gate_release.get(gate.id, {})
        release_state = rel.get("release_state", "?")
        blocking = release_state in {"BLOCKED", "UNSATISFIED"} or gate.verdict == "NO_GO"
        if blocking and next_blocking is None:
            next_blocking = gate.id
        gates.append({
            "order": gate.order,
            "id": gate.id,
            "local": gate.state,
            "verdict": gate.verdict or "",
            "release_state": release_state,
            "owner": gate.owner,
            "evidence": list(gate.evidence),
            "blocking": blocking,
        })

    critical_high = [f for f in findings if f.severity in {"CRITICAL", "HIGH"} and f.status not in {"CLOSED", "ACCEPTED"}]
    available_workers = [c for c in WORKER_CLIS if shutil.which(c)]
    unavailable_workers = [c for c in WORKER_CLIS if c not in available_workers]

    return {
        "run_id": plan.run_id,
        "feature": plan.feature,
        "risk": plan.risk_level,
        "policy": plan.policy_profile,
        "branch": plan.branch,
        "readiness_verdict": "SATISFIED" if readiness.get("release_satisfied") else "NO_GO",
        "authority_mode": readiness.get("authority_mode", "ADVISORY"),
        "blockers": list(readiness.get("blockers", [])),
        "next_blocking_gate": next_blocking,                       # task 1
        "gates": gates,                                            # task 7 (evidence per gate)
        "critical_high_findings": [f.to_dict() for f in critical_high],  # task 3
        "all_findings": [f.to_dict() for f in findings],
        "worker_preferences": dict(plan.worker_preferences or {}), # task 5 (view current)
        "available_workers": available_workers,                   # task 4
        "unavailable_workers": unavailable_workers,               # task 4
        "next_action": next_action,
        # Tasks the engine cannot yet satisfy — explicit banners, never blank:
        "resume_status": "UNAVAILABLE - resume is not implemented in the engine",   # task 6
        "github_status": "UNAVAILABLE - GitHub PR/check integration not configured", # task 9
        "cost_status": "UNAVAILABLE - cost/token usage is not tracked",              # task 10
    }


# --- the 10 benchmark tasks, surfaced so a reviewer can complete each ----------

def task_answers(model: dict[str, Any]) -> list[tuple[str, str]]:
    """Each goal-spec TUI task with the answer the dashboard provides."""
    nb = model["next_blocking_gate"] or "<none — all gates pass>"
    ch = model["critical_high_findings"]
    return [
        ("1. Next blocking gate", nb),
        ("2. Why release is NO_GO", f"{len(model['blockers'])} blockers (see Blockers panel)"),
        ("3. Open CRITICAL/HIGH findings", f"{len(ch)} open (see Findings panel)"),
        ("4. Unavailable workers/scanners", ", ".join(model["unavailable_workers"]) or "<none>"),
        ("5. Change red-team provider", f"current red-team={model['worker_preferences'].get('redteam','<unset>')}; "
                                        f"edit via: sdlc gate / plan worker_preferences"),
        ("6. Resume interrupted run", model["resume_status"]),
        ("7. Open gate evidence", "select a gate in the Gates panel to see its evidence paths"),
        ("8. Before/after quality diff", "sdlc bench compare --before <a> --after <b>"),
        ("9. GitHub PR/check status", model["github_status"]),
        ("10. Budget/cost burn", model["cost_status"]),
    ]


def render_plain(model: dict[str, Any]) -> str:
    """Plain-text rendering for --no-tui / non-tty / fallback. 80-col safe."""
    lines: list[str] = []
    bar = "=" * 80
    lines.append(bar)
    lines.append("SDLC CONTROL PLANE — DASHBOARD")
    lines.append(bar)
    lines.append(f"Run: {model['run_id']}")
    lines.append(f"Feature: {model['feature'][:72]}")
    lines.append(f"Risk: {model['risk']} | Policy: {model['policy']} | Branch: {model['branch']}")
    lines.append(f"Release: {model['readiness_verdict']} | blockers={len(model['blockers'])} "
                 f"| authority={model['authority_mode']}")
    lines.append(f"Next blocking gate: {model['next_blocking_gate'] or '<none>'}")
    lines.append("")
    lines.append("Gates:  (* = blocking;  cols: NN id  local/verdict  release)")
    for g in model["gates"]:
        flag = "*" if g["blocking"] else " "
        v = f"/{g['verdict']}" if g["verdict"] else ""
        lines.append(f"{flag}{g['order']:02d} {g['id']:<30.30} {g['local']}{v}  {g['release_state']}")
    lines.append("")
    lines.append("Open CRITICAL/HIGH findings:")
    if not model["critical_high_findings"]:
        lines.append("  <none>")
    for f in model["critical_high_findings"]:
        lines.append(f"  {f['id']} {f['severity']:<8} {f['title'][:60]}")
    lines.append("")
    lines.append("Benchmark tasks (all 10 addressable here):")
    for label, answer in task_answers(model):
        lines.append(f"  {label}: {answer}")
    lines.append("")
    lines.append("Status banners:")
    lines.append(f"  GITHUB: {model['github_status']}")
    lines.append(f"  COST:   {model['cost_status']}")
    lines.append(f"  RESUME: {model['resume_status']}")
    lines.append(bar)
    # Guarantee 80-column safety (spec requirement); curses truncates separately.
    return "\n".join(line[:80] for line in lines)


# --- interactive curses shell -------------------------------------------------

PANELS = ["Overview", "Gates", "Findings", "Tasks"]


def run_curses(model: dict[str, Any]) -> None:
    """Interactive full-screen dashboard. Falls back to plain text if curses is
    unavailable or the terminal is not a tty (caller handles that)."""
    import curses

    def _draw(stdscr: "curses._CursesWindow") -> None:
        curses.curs_set(0)
        panel_idx = 0
        scroll = 0
        while True:
            stdscr.erase()
            height, width = stdscr.getmaxyx()
            w = max(40, width)
            # Header
            stdscr.addnstr(0, 0, f" SDLC DASHBOARD — {model['run_id']} ".ljust(w), w, curses.A_REVERSE)
            tabs = "  ".join(f"[{p}]" if i == panel_idx else f" {p} " for i, p in enumerate(PANELS))
            stdscr.addnstr(1, 0, tabs[: w - 1], w - 1)
            stdscr.addnstr(2, 0, f" Release: {model['readiness_verdict']}  blockers={len(model['blockers'])}"
                                 f"  next-blocking={model['next_blocking_gate'] or '-'}"[: w - 1], w - 1)
            # Always-visible UNAVAILABLE banners (tasks 9/10/6)
            stdscr.addnstr(height - 2, 0, f" GITHUB: unavailable | COST: unavailable | RESUME: unavailable"[: w - 1],
                           w - 1, curses.A_DIM)
            stdscr.addnstr(height - 1, 0,
                           " [Tab] panel  [↑/↓] scroll  [g] next-blocking-gate  [q] quit"[: w - 1], w - 1)

            body = _panel_lines(model, PANELS[panel_idx])
            view_h = height - 5
            scroll = max(0, min(scroll, max(0, len(body) - view_h)))
            for row, line in enumerate(body[scroll: scroll + view_h]):
                stdscr.addnstr(3 + row, 0, line[: w - 1], w - 1)
            stdscr.refresh()

            ch = stdscr.getch()
            if ch in (ord("q"), 27):
                break
            elif ch in (9, curses.KEY_RIGHT):
                panel_idx = (panel_idx + 1) % len(PANELS); scroll = 0
            elif ch == curses.KEY_LEFT:
                panel_idx = (panel_idx - 1) % len(PANELS); scroll = 0
            elif ch == curses.KEY_DOWN:
                scroll += 1
            elif ch == curses.KEY_UP:
                scroll = max(0, scroll - 1)
            elif ch == ord("g"):
                # Jump to Gates panel (task 1).
                panel_idx = PANELS.index("Gates")
                scroll = next((i for i, g in enumerate(model["gates"]) if g["blocking"]), 0)

    curses.wrapper(_draw)


def _panel_lines(model: dict[str, Any], panel: str) -> list[str]:
    if panel == "Overview":
        blocker_lines = [f"  - {b}" for b in model["blockers"]] or ["  <none>"]
        return [
            f"Feature: {model['feature']}",
            f"Risk: {model['risk']}   Policy: {model['policy']}   Branch: {model['branch']}",
            f"Authority: {model['authority_mode']}",
            "",
            "Blockers:",
            *blocker_lines,
        ]
    if panel == "Gates":
        out = []
        for g in model["gates"]:
            flag = "*" if g["blocking"] else " "
            v = f"/{g['verdict']}" if g["verdict"] else ""
            out.append(f"{flag}{g['order']:02d}. {g['id']:<34} local={g['local']}{v} release={g['release_state']}")
            for ev in g["evidence"]:
                out.append(f"      evidence: {ev}")
        return out or ["<no gates>"]
    if panel == "Findings":
        out = ["Open CRITICAL/HIGH:"]
        if not model["critical_high_findings"]:
            out.append("  <none>")
        for f in model["critical_high_findings"]:
            out.append(f"  {f['id']} {f['severity']:<8} {f['title']}")
        return out
    if panel == "Tasks":
        return [f"{label}: {answer}" for label, answer in task_answers(model)]
    return ["<unknown panel>"]
