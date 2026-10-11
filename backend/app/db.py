"""
SQLite database layer for Sentinel.

Design choices:
- WAL mode for concurrent reads + one writer (architecture.md §6).
- foreign_keys=ON for referential integrity.
- All tables, triggers, and indexes are created by ensure_schema().
- Connection is per-thread via threading.local() to avoid sharing
  SQLite connection objects across threads.
- Tests pass db=":memory:" via SENTINEL_DB env var.
"""

from __future__ import annotations

import contextlib
import sqlite3
import threading
from typing import Any, cast

from backend.app.config import settings

_local = threading.local()


def _connect(db_path: str) -> sqlite3.Connection:
    uri = False
    if db_path == ":memory:":
        db_path = "file:sentinel_mem?mode=memory&cache=shared"
        uri = True
    conn = sqlite3.connect(db_path, uri=uri, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    if not uri:
        with contextlib.suppress(sqlite3.OperationalError):
            conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def get_connection() -> sqlite3.Connection:
    """Return the thread-local DB connection, creating it if necessary."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = _connect(settings.db)
        ensure_schema(_local.conn)
    return cast(sqlite3.Connection, _local.conn)


def close_connection() -> None:
    """Close the thread-local connection (call in tests between modules)."""
    if hasattr(_local, "conn") and _local.conn is not None:
        _local.conn.close()
        _local.conn = None


# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    user_id      TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    roles_json   TEXT NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    agent_id                   TEXT PRIMARY KEY,
    name                       TEXT NOT NULL,
    status                     TEXT NOT NULL CHECK (status IN ('active','suspended')),
    allowed_action_types_json  TEXT NOT NULL,
    graph_node_id              TEXT NOT NULL,
    api_key_hash               TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS action_types (
    action_type     TEXT PRIMARY KEY,
    definition_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_versions (
    version        INTEGER PRIMARY KEY,
    parent_version INTEGER,
    content_json   TEXT NOT NULL,
    content_hash   TEXT NOT NULL,
    created_by     TEXT NOT NULL,
    approved_by    TEXT,
    created_at     TEXT NOT NULL,
    activated_at   TEXT
);

CREATE TRIGGER IF NOT EXISTS policy_no_update
    BEFORE UPDATE OF content_json, content_hash, version ON policy_versions
BEGIN
    SELECT RAISE(ABORT, 'policy versions are immutable');
END;

CREATE TRIGGER IF NOT EXISTS policy_no_delete
    BEFORE DELETE ON policy_versions
BEGIN
    SELECT RAISE(ABORT, 'policy versions are immutable');
END;

CREATE TABLE IF NOT EXISTS sessions (
    session_id        TEXT PRIMARY KEY,
    agent_id          TEXT NOT NULL REFERENCES agents(agent_id),
    owner_user_id     TEXT NOT NULL REFERENCES users(user_id),
    taint_level       INTEGER NOT NULL DEFAULT 0 CHECK (taint_level BETWEEN 0 AND 2),
    taint_reasons_json TEXT NOT NULL DEFAULT '[]',
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actions (
    action_id        TEXT PRIMARY KEY,
    session_id       TEXT NOT NULL REFERENCES sessions(session_id),
    agent_id         TEXT NOT NULL,
    action_type      TEXT NOT NULL,
    arguments_json   TEXT NOT NULL,
    target           TEXT,
    fingerprint      TEXT NOT NULL,
    requester        TEXT NOT NULL,
    outcome          TEXT NOT NULL CHECK (outcome IN ('allow','block','hold')),
    reason           TEXT NOT NULL,
    rule_ids_json    TEXT NOT NULL,
    decision_path    TEXT NOT NULL CHECK (decision_path IN ('rules','rules+llm','fallback')),
    policy_version   INTEGER NOT NULL,
    signals_json     TEXT NOT NULL,
    status           TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    executed_at      TEXT
);

CREATE INDEX IF NOT EXISTS actions_by_session ON actions(session_id);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id  TEXT PRIMARY KEY,
    kind         TEXT NOT NULL CHECK (kind IN ('action','ingress_review','policy.update')),
    action_id    TEXT,
    fingerprint  TEXT NOT NULL,
    requester    TEXT NOT NULL,
    approver     TEXT,
    decision     TEXT CHECK (decision IN ('approve','reject')),
    status       TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','expired','consumed')),
    created_at   TEXT NOT NULL,
    ts           TEXT,
    expires_at   TEXT NOT NULL,
    used         INTEGER NOT NULL DEFAULT 0,
    used_at      TEXT,
    signature    TEXT
);

CREATE TABLE IF NOT EXISTS ingress_reviews (
    review_id              TEXT PRIMARY KEY,
    session_id             TEXT NOT NULL,
    source_tier            TEXT NOT NULL,
    source_ref             TEXT NOT NULL,
    text_encrypted_or_plain TEXT NOT NULL,
    findings_json          TEXT NOT NULL,
    status                 TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ledger (
    seq            INTEGER PRIMARY KEY,
    ts             TEXT NOT NULL,
    module         TEXT NOT NULL CHECK (module IN ('promptshield','actiongate','breachpath','policy','auth')),
    event_type     TEXT NOT NULL,
    subject        TEXT NOT NULL,
    outcome        TEXT NOT NULL,
    reason         TEXT NOT NULL,
    rule_ids_json  TEXT NOT NULL,
    decision_path  TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    payload_ref    TEXT,
    payload_digest TEXT NOT NULL,
    prev_hash      TEXT NOT NULL,
    hash           TEXT NOT NULL UNIQUE
);

CREATE TRIGGER IF NOT EXISTS ledger_no_update
    BEFORE UPDATE ON ledger
BEGIN
    SELECT RAISE(ABORT, 'ledger is append-only');
END;

CREATE TRIGGER IF NOT EXISTS ledger_no_delete
    BEFORE DELETE ON ledger
BEGIN
    SELECT RAISE(ABORT, 'ledger is append-only');
END;

CREATE TABLE IF NOT EXISTS ledger_payloads (
    payload_id   TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS graph_versions (
    graph_version  INTEGER PRIMARY KEY,
    parent_version INTEGER,
    graph_json     TEXT NOT NULL,
    change_json    TEXT NOT NULL,
    created_by     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    content_hash   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS protected_values (
    pv_id      TEXT PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('canary','secret','national_id')),
    value_norm TEXT NOT NULL,
    min_len    INTEGER NOT NULL DEFAULT 8
);

CREATE TABLE IF NOT EXISTS customers (
    customer_id       INTEGER PRIMARY KEY,
    name              TEXT,
    email             TEXT,
    phone             TEXT,
    order_total_cents INTEGER,
    internal_notes    TEXT
);

CREATE TABLE IF NOT EXISTS marketing_prefs (
    contact_id INTEGER PRIMARY KEY,
    email      TEXT,
    opted_in   INTEGER
);

CREATE TABLE IF NOT EXISTS outbox (
    outbox_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id   TEXT,
    ts          TEXT,
    to_json     TEXT,
    subject     TEXT,
    body_excerpt TEXT,
    simulated   INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS fakedb_ops (
    op_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id    TEXT,
    ts           TEXT,
    op           TEXT,
    resource     TEXT,
    record_count INTEGER,
    simulated    INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS exec_tokens_used (
    nonce   TEXT PRIMARY KEY,
    used_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS benchmark_runs (
    run_id       TEXT PRIMARY KEY,
    ts           TEXT,
    split        TEXT,
    policy_version INTEGER,
    result_json  TEXT
);

CREATE TABLE IF NOT EXISTS policy_proposals (
    proposal_id   TEXT PRIMARY KEY,
    base_version  INTEGER NOT NULL,
    content_json  TEXT NOT NULL,
    diff_json     TEXT NOT NULL,
    fingerprint   TEXT NOT NULL,
    note          TEXT,
    proposed_by   TEXT NOT NULL,
    approval_id   TEXT,
    created_at    TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending'
);
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create all tables and triggers if they do not exist."""
    conn.executescript(_SCHEMA_SQL)
    conn.commit()


# ── Query helpers ─────────────────────────────────────────────────────────────

def fetchone(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
    return cast(sqlite3.Row | None, conn.execute(sql, params).fetchone())


def fetchall(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    return cast(list[sqlite3.Row], conn.execute(sql, params).fetchall())


def execute(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
    return conn.execute(sql, params)
