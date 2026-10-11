"""
BreachPath graph persistence and version management (BP-14).

Manages graph_versions table in SQLite.
Immutable historical versions with content hash.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from backend.app.core.canonical import canonical_json
from backend.app.core.clock import get_clock
from backend.app.db import get_connection

SEED_GRAPH_PATH = Path(__file__).resolve().parent.parent.parent.parent / "seed" / "graph.json"


def init_seed_graph(conn: sqlite3.Connection | None = None) -> tuple[int, dict[str, Any]]:
    """
    Initialize seed graph versions in the DB if empty.
    Creates version 1 (raw seed) and version 2 (derived entry points) per seed-data.md §2.
    """
    if conn is None:
        conn = get_connection()

    row = conn.execute("SELECT graph_version, graph_json FROM graph_versions ORDER BY graph_version DESC LIMIT 1").fetchone()
    if row is not None:
        return row[0], json.loads(row[1])

    # Load seed/graph.json
    if not SEED_GRAPH_PATH.exists():
        raw_graph: dict[str, Any] = {
            "schema": "sentinel.graph/1",
            "name": "Sentinel default access graph",
            "settings": {"max_depth": 4, "max_paths": 1000, "time_budget_ms": 2000, "sensitive_min": "medium"},
            "nodes": [],
            "edges": [],
        }
    else:
        with open(SEED_GRAPH_PATH, encoding="utf-8") as f:
            raw_graph = json.load(f)

    clock = get_clock()
    now_iso = clock.now_iso()

    # Version 1: raw graph
    g1_json = canonical_json(raw_graph)
    g1_hash = hashlib.sha256(g1_json.encode("utf-8")).hexdigest()
    conn.execute(
        """INSERT OR REPLACE INTO graph_versions
           (graph_version, parent_version, graph_json, change_json, created_by, created_at, content_hash)
           VALUES (1, NULL, ?, 'seed', 'system', ?, ?)""",
        (g1_json, now_iso, g1_hash),
    )
    conn.commit()

    # Derive entry points for version 2
    from backend.app.actiongate.registries import get_action_type_registry
    from backend.app.breachpath.blast import derive_entry_points

    act_reg = get_action_type_registry()
    g2_model, changed, _ = derive_entry_points(act_reg, raw_graph)

    if changed:
        g2_json = canonical_json(g2_model)
        g2_hash = hashlib.sha256(g2_json.encode("utf-8")).hexdigest()
        conn.execute(
            """INSERT OR REPLACE INTO graph_versions
               (graph_version, parent_version, graph_json, change_json, created_by, created_at, content_hash)
               VALUES (2, 1, ?, ?, 'system', ?, ?)""",
            (g2_json, json.dumps([{"op": "derive_entry_points"}]), now_iso, g2_hash),
        )
        conn.commit()
        return 2, g2_model

    conn.commit()
    return 1, raw_graph


def get_current_graph(conn: sqlite3.Connection | None = None) -> tuple[int, dict[str, Any]]:
    """Get latest graph version and parsed model dict."""
    if conn is None:
        conn = get_connection()

    row = conn.execute(
        "SELECT graph_version, graph_json FROM graph_versions ORDER BY graph_version DESC LIMIT 1"
    ).fetchone()

    if row is None:
        return init_seed_graph(conn)

    return row[0], json.loads(row[1])


def save_graph_version(
    model: dict[str, Any],
    parent_version: int | None,
    change_summary: str | list[dict[str, Any]],
    created_by: str = "admin",
    conn: sqlite3.Connection | None = None,
) -> int:
    """Save new graph version and return new version integer."""
    if conn is None:
        conn = get_connection()

    latest_row = conn.execute(
        "SELECT graph_version FROM graph_versions ORDER BY graph_version DESC LIMIT 1"
    ).fetchone()
    next_ver = (latest_row[0] + 1) if latest_row else 1

    clock = get_clock()
    now_iso = clock.now_iso()

    g_json = canonical_json(model)
    g_hash = hashlib.sha256(g_json.encode("utf-8")).hexdigest()

    change_str = change_summary if isinstance(change_summary, str) else json.dumps(change_summary)

    conn.execute(
        """INSERT INTO graph_versions
           (graph_version, parent_version, graph_json, change_json, created_by, created_at, content_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (next_ver, parent_version, g_json, change_str, created_by, now_iso, g_hash),
    )
    conn.commit()
    return next_ver


def list_graph_versions(conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    """List historical graph versions."""
    if conn is None:
        conn = get_connection()

    rows = conn.execute(
        "SELECT graph_version, created_by, created_at, change_json FROM graph_versions ORDER BY graph_version ASC"
    ).fetchall()

    result: list[dict[str, Any]] = []
    for r in rows:
        chg = r["change_json"]
        summary = chg
        try:
            parsed = json.loads(chg)
            if isinstance(parsed, list):
                summary = f"{len(parsed)} changes applied"
        except Exception:
            pass

        result.append({
            "graph_version": r["graph_version"],
            "created_by": r["created_by"],
            "created_at": r["created_at"],
            "change_summary": summary,
        })
    return result
