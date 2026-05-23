"""Consent-based local episodic memory."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from .models import RunPlan, Finding
from .util import now_iso, redact_secrets, sha256_text


MEMORY_PATH = ".sdlc/memory.sqlite"


def memory_path(repo: Path) -> Path:
    return repo / MEMORY_PATH


def init_memory(repo: Path, *, enabled: bool = True) -> dict[str, Any]:
    path = memory_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as conn:
        _ensure_schema(conn)
        conn.execute("insert into privacy_events(ts, operation, detail) values (?, ?, ?)", (now_iso(), "init", json.dumps({"enabled": enabled})))
        conn.execute("insert or replace into settings(key, value) values ('enabled', ?)", ("true" if enabled else "false",))
        conn.commit()
    return {"status": "enabled" if enabled else "disabled", "path": str(path)}


def memory_status(repo: Path) -> dict[str, Any]:
    path = memory_path(repo)
    if not path.exists():
        return {"enabled": False, "initialized": False, "path": str(path), "episodes": 0}
    with closing(sqlite3.connect(path)) as conn:
        _ensure_schema(conn)
        enabled = _enabled(conn)
        episodes = conn.execute("select count(*) from episodes").fetchone()[0]
    return {"enabled": enabled, "initialized": True, "path": str(path), "episodes": episodes}


def disable_memory(repo: Path) -> dict[str, Any]:
    if not memory_path(repo).exists():
        init_memory(repo, enabled=False)
    with closing(sqlite3.connect(memory_path(repo))) as conn:
        _ensure_schema(conn)
        conn.execute("insert or replace into settings(key, value) values ('enabled', 'false')")
        conn.execute("insert into privacy_events(ts, operation, detail) values (?, ?, ?)", (now_iso(), "disable", "{}"))
        conn.commit()
    return memory_status(repo)


def record_episode(repo: Path, plan: RunPlan, findings: list[Finding]) -> dict[str, Any]:
    status = memory_status(repo)
    if not status["initialized"] or not status["enabled"]:
        return {"status": "REJECTED", "reason": "Memory is not enabled. Run `sdlc memory init` first."}
    open_items = [finding.id for finding in findings if finding.status == "OPEN"]
    summary = {
        "run_id": plan.run_id,
        "request_summary": redact_secrets(plan.feature),
        "request_sha256": sha256_text(plan.feature),
        "risk_level": plan.risk_level,
        "verdict": "NO_GO" if open_items else "RECORDED",
        "open_findings": open_items,
        "domains": plan.classification.get("activated_agents", []),
    }
    with closing(sqlite3.connect(memory_path(repo))) as conn:
        _ensure_schema(conn)
        conn.execute(
            "insert or replace into episodes(run_id, ts, request_summary, risk_level, verdict, summary_json) values (?, ?, ?, ?, ?, ?)",
            (plan.run_id, now_iso(), summary["request_summary"], plan.risk_level, summary["verdict"], json.dumps(summary, sort_keys=True)),
        )
        conn.execute("insert into privacy_events(ts, operation, detail) values (?, ?, ?)", (now_iso(), "record_episode", json.dumps({"run_id": plan.run_id})))
        conn.commit()
    return {"status": "RECORDED", "episode": summary}


def search_memory(repo: Path, query: str, *, limit: int = 10) -> dict[str, Any]:
    status = memory_status(repo)
    if not status["initialized"] or not status["enabled"]:
        return {"enabled": False, "results": [], "reason": "Memory is not enabled"}
    tokens = {token for token in query.lower().split() if token}
    rows: list[dict[str, Any]] = []
    with closing(sqlite3.connect(memory_path(repo))) as conn:
        _ensure_schema(conn)
        for run_id, ts, request_summary, risk_level, verdict, summary_json in conn.execute("select run_id, ts, request_summary, risk_level, verdict, summary_json from episodes"):
            haystack = f"{run_id} {request_summary} {risk_level} {verdict}".lower()
            score = sum(1 for token in tokens if token in haystack)
            if score:
                rows.append({
                    "run_id": run_id,
                    "ts": ts,
                    "request_summary": request_summary,
                    "risk_level": risk_level,
                    "verdict": verdict,
                    "score": score,
                    "influence_explanation": f"Matched query tokens against prior episode {run_id}.",
                    "summary": json.loads(summary_json),
                })
    rows.sort(key=lambda item: (-item["score"], item["ts"]))
    return {"enabled": True, "results": rows[:limit]}


def export_memory(repo: Path) -> dict[str, Any]:
    status = memory_status(repo)
    if not status["initialized"]:
        return {"enabled": False, "episodes": [], "privacy_events": []}
    with closing(sqlite3.connect(memory_path(repo))) as conn:
        _ensure_schema(conn)
        episodes = [dict(zip(["run_id", "ts", "request_summary", "risk_level", "verdict", "summary_json"], row)) for row in conn.execute("select run_id, ts, request_summary, risk_level, verdict, summary_json from episodes")]
        privacy = [dict(zip(["ts", "operation", "detail"], row)) for row in conn.execute("select ts, operation, detail from privacy_events")]
    for episode in episodes:
        episode["summary"] = json.loads(str(episode.pop("summary_json")))
    return {"enabled": status["enabled"], "episodes": episodes, "privacy_events": privacy}


def delete_memory(repo: Path) -> dict[str, Any]:
    path = memory_path(repo)
    if path.exists():
        path.unlink()
    return {"status": "DELETED", "path": str(path)}


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute("create table if not exists settings(key text primary key, value text not null)")
    conn.execute("create table if not exists episodes(run_id text primary key, ts text not null, request_summary text not null, risk_level text not null, verdict text not null, summary_json text not null)")
    conn.execute("create table if not exists user_preferences(key text primary key, value text not null, source_run_id text, ts text not null)")
    conn.execute("create table if not exists decision_patterns(id integer primary key autoincrement, ts text not null, pattern text not null, detail text not null)")
    conn.execute("create table if not exists question_outcomes(id integer primary key autoincrement, ts text not null, question text not null, useful integer not null, impact text not null)")
    conn.execute("create table if not exists standards_cache(id text primary key, source_url text not null, version_date text, retrieved_at text, sha256 text)")
    conn.execute("create table if not exists feedback(id integer primary key autoincrement, ts text not null, detail text not null)")
    conn.execute("create table if not exists privacy_events(id integer primary key autoincrement, ts text not null, operation text not null, detail text not null)")


def _enabled(conn: sqlite3.Connection) -> bool:
    row = conn.execute("select value from settings where key='enabled'").fetchone()
    return bool(row and row[0] == "true")
