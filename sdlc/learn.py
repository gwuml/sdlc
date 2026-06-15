"""Self-improvement loop — `sdlc learn record | suggest | apply`.

Records pattern-level lessons from runs, suggests improvements when patterns recur,
and applies only human-approved proposals. Built on the existing memory sqlite db.

Hard safety rules (goal spec):
- Never store secrets, credentials, raw prompts, or API keys — only counts, gate ids,
  severities, and templated summaries.
- Never silently change policy, bypass gates, or weaken safety rules — `apply` records
  an approval; it does NOT mutate policy files or thresholds.
- Never approve its own proposals — `apply` requires a named actor and --execute;
  `suggest` only creates PENDING proposals.
- Never transmit anything externally.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from .memory import memory_path
from .models import Finding, RunPlan
from .util import now_iso


def _connect(repo: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(memory_path(repo))
    conn.execute("create table if not exists learn_lessons("
                 "id integer primary key autoincrement, ts text not null, run_id text not null, "
                 "kind text not null, key text not null, detail text not null)")
    conn.execute("create table if not exists learn_proposals("
                 "id integer primary key autoincrement, ts text not null, kind text not null, "
                 "key text not null, occurrences integer not null, suggestion text not null, "
                 "status text not null default 'PENDING', applied_by text, applied_ts text)")
    return conn


def record_lessons(repo: Path, plan: RunPlan, findings: list[Finding]) -> dict[str, Any]:
    """Derive pattern-level lessons from a run. Summaries only — no secrets."""
    lessons: list[tuple[str, str, str]] = []  # (kind, key, detail)

    for gate in plan.gates:
        if gate.state in {"NO_GO", "FIX_REQUIRED", "BLOCKED"} or gate.verdict == "NO_GO":
            lessons.append(("gate_blocker", gate.id, f"Gate {gate.id} was {gate.state}/{gate.verdict}."))

    high = [f for f in findings if f.severity in {"CRITICAL", "HIGH"} and f.status not in {"CLOSED", "ACCEPTED"}]
    if high:
        lessons.append(("open_high_findings", "count", f"{len(high)} open CRITICAL/HIGH findings."))

    prefs = plan.worker_preferences or {}
    if prefs.get("implementation") and prefs.get("redteam") and prefs["implementation"] == prefs["redteam"]:
        lessons.append(("redteam_monoculture", prefs["redteam"],
                        "Implementer and red-team use the same worker family."))

    ts = now_iso()
    with closing(_connect(repo)) as conn:
        for kind, key, detail in lessons:
            conn.execute("insert into learn_lessons(ts, run_id, kind, key, detail) values(?,?,?,?,?)",
                         (ts, plan.run_id, kind, key, detail))
        conn.commit()
    return {"run_id": plan.run_id, "recorded": len(lessons),
            "lessons": [{"kind": k, "key": key, "detail": d} for k, key, d in lessons]}


SUGGESTION_TEMPLATES = {
    "gate_blocker": "Gate '{key}' blocked in {n} runs — add a pre-flight check or evidence template for it.",
    "open_high_findings": "{n} runs ended with open CRITICAL/HIGH findings — consider an earlier red-team pass.",
    "redteam_monoculture": "Worker '{key}' used as both implementer and red-team in {n} runs — assign a distinct red-team family.",
}


def suggest_proposals(repo: Path, *, min_occurrences: int = 2) -> dict[str, Any]:
    """Aggregate recurring lessons into PENDING proposals. Creates nothing actionable
    on its own — proposals require human apply."""
    ts = now_iso()
    created = []
    with closing(_connect(repo)) as conn:
        rows = conn.execute("select kind, key, count(*) from learn_lessons group by kind, key "
                            "having count(*) >= ?", (min_occurrences,)).fetchall()
        for kind, key, n in rows:
            # Skip if an identical PENDING proposal already exists.
            exists = conn.execute("select 1 from learn_proposals where kind=? and key=? and status='PENDING'",
                                  (kind, key)).fetchone()
            if exists:
                continue
            template = SUGGESTION_TEMPLATES.get(kind, "Pattern '{key}' recurred in {n} runs — review.")
            suggestion = template.format(key=key, n=n)
            cur = conn.execute("insert into learn_proposals(ts, kind, key, occurrences, suggestion) "
                               "values(?,?,?,?,?)", (ts, kind, key, n, suggestion))
            created.append({"id": cur.lastrowid, "kind": kind, "key": key,
                            "occurrences": n, "suggestion": suggestion})
        conn.commit()
        pending = conn.execute("select id, kind, key, occurrences, suggestion, status "
                               "from learn_proposals where status='PENDING' order by occurrences desc").fetchall()
    return {
        "created": created,
        "pending": [{"id": r[0], "kind": r[1], "key": r[2], "occurrences": r[3],
                     "suggestion": r[4], "status": r[5]} for r in pending],
    }


def apply_proposal(repo: Path, proposal_id: int, *, actor: str, execute: bool) -> dict[str, Any]:
    """Record human approval of a proposal. NEVER mutates policy, gates, or safety
    rules — it only marks the proposal APPLIED with the approving actor. Requires a
    named actor and --execute; otherwise returns a dry-run preview."""
    if not actor or not actor.strip():
        return {"status": "REJECTED", "reason": "an explicit --actor is required; learn cannot self-approve"}
    with closing(_connect(repo)) as conn:
        row = conn.execute("select id, kind, key, suggestion, status from learn_proposals where id=?",
                           (proposal_id,)).fetchone()
        if not row:
            return {"status": "NOT_FOUND", "proposal_id": proposal_id}
        proposal = {"id": row[0], "kind": row[1], "key": row[2], "suggestion": row[3], "status": row[4]}
        if not execute:
            return {"status": "DRY_RUN", "proposal": proposal,
                    "note": "Re-run with --execute to record approval. This never changes policy or gates."}
        if proposal["status"] == "APPLIED":
            return {"status": "ALREADY_APPLIED", "proposal": proposal}
        ts = now_iso()
        conn.execute("update learn_proposals set status='APPLIED', applied_by=?, applied_ts=? where id=?",
                     (actor.strip(), ts, proposal_id))
        conn.commit()
    return {"status": "APPLIED", "proposal_id": proposal_id, "applied_by": actor.strip(),
            "applied_ts": ts, "effect": "approval recorded only; no policy/gate/safety change"}
