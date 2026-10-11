"""
Sentinel test harness — conftest.py

Provides shared fixtures:
    app          FastAPI TestClient backed by a fresh in-memory SQLite
    clock        FixedClock injected into the app
    alice/bob/admin/dana  — human auth tokens
    agent_key    — agent bearer token for supportbot
    session()    — creates a session with given taint level
"""

from __future__ import annotations

import json
import os
import threading

import pytest
from fastapi.testclient import TestClient

# Force in-memory DB for all tests
os.environ.setdefault("SENTINEL_DB", ":memory:")
os.environ.setdefault("SENTINEL_TESTING", "1")
os.environ.setdefault("SENTINEL_DEMO_MODE", "1")
os.environ.setdefault("SENTINEL_HUMAN_KEY", "test-human-key")
os.environ.setdefault("SENTINEL_APPROVAL_KEY", "test-approval-key")
os.environ.setdefault("SENTINEL_EXEC_KEY", "test-exec-key")
os.environ.setdefault("SENTINEL_AGENT_PEPPER", "test-pepper")
os.environ.setdefault("SENTINEL_LLM_MODE", "ok")

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def app_client():
    """
    Session-scoped TestClient on a fresh in-memory SQLite.
    The DB is seeded with the minimum data needed for tests.
    """
    # Reset thread-local DB connection so each test session gets fresh memory DB
    from backend.app import db as db_module
    db_module._local = threading.local()

    from backend.app.core.clock import FixedClock, set_clock
    from backend.app.core.ids import reset_counters
    from backend.app.db import ensure_schema, get_connection
    from backend.app.main import app

    reset_counters()
    clock = FixedClock()
    set_clock(clock)

    conn = get_connection()
    ensure_schema(conn)

    # Minimal seed: users, agents, policy v1
    _seed_test_db(conn)

    with TestClient(app, raise_server_exceptions=True) as client:
        yield client, clock


@pytest.fixture
def client(app_client):
    """Per-test alias for the TestClient."""
    c, _ = app_client
    return c


@pytest.fixture
def clock(app_client):
    """Per-test alias for the FixedClock."""
    _, clk = app_client
    return clk


@pytest.fixture(autouse=True)
def ensure_db_seeded(app_client):
    """Ensure minimal DB is seeded for every test."""
    pass


def _seed_test_db(conn):
    """Insert minimum fixture data so auth and health tests pass."""
    import hashlib

    from backend.app.config import settings

    def hash_password(pw: str) -> str:
        return hashlib.sha256(pw.encode()).hexdigest()

    users = [
        ("alice", "Alice (requester)", json.dumps(["requester"]), hash_password("demo")),
        ("bob", "Bob (approver)", json.dumps(["approver"]), hash_password("demo")),
        ("admin", "Admin", json.dumps(["admin", "approver"]), hash_password("demo")),
        ("dana", "Admin 2", json.dumps(["admin", "approver"]), hash_password("demo")),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO users (user_id, display_name, roles_json, password_hash) VALUES (?,?,?,?)",
        users,
    )

    # Agent: supportbot
    pepper = settings.agent_pepper
    secret = "demo0000000000000000000000"
    agent_key_hash = hashlib.sha256((pepper + secret).encode()).hexdigest()
    conn.execute(
        """INSERT OR IGNORE INTO agents
           (agent_id, name, status, allowed_action_types_json, graph_node_id, api_key_hash)
           VALUES (?,?,?,?,?,?)""",
        (
            "supportbot", "SupportBot", "active",
            json.dumps(["web.fetch", "reviews.read", "db.read", "email.send", "db.update", "db.delete"]),
            "agent:supportbot", agent_key_hash,
        ),
    )

    # Agent: legacybot (suspended)
    conn.execute(
        """INSERT OR IGNORE INTO agents
           (agent_id, name, status, allowed_action_types_json, graph_node_id, api_key_hash)
           VALUES (?,?,?,?,?,?)""",
        (
            "legacybot", "LegacyBot", "suspended",
            json.dumps(["db.read"]),
            "agent:legacybot", agent_key_hash,
        ),
    )

    # Policy v1 (activated)
    import hashlib as hl

    from backend.app.core.canonical import canonical_json
    from backend.app.core.clock import get_clock
    policy_doc = _default_policy_v1()
    policy_json = canonical_json(policy_doc)
    policy_hash = hl.sha256(policy_json.encode()).hexdigest()
    ts = get_clock().now_iso()
    conn.execute(
        """INSERT OR IGNORE INTO policy_versions
           (version, parent_version, content_json, content_hash, created_by, approved_by, created_at, activated_at)
           VALUES (1, NULL, ?, ?, 'system', 'system', ?, ?)""",
        (policy_json, policy_hash, ts, ts),
    )

    conn.commit()


def _default_policy_v1() -> dict:
    """Return the minimal policy v1 dict for testing (full version from policy-spec.md §6)."""
    return {
        "schema": "sentinel.policy/1",
        "policy_id": "sentinel-default",
        "description": "Acme Retail SupportBot default policy, v1",
        "default_outcome": "block",
        "settings": {
            "approval_ttl_s": 900,
            "execution_token_ttl_s": 60,
            "internal_domains": ["acme.example"],
            "llm": {
                "enabled": True,
                "timeout_ms": 3000,
                "breaker_failures": 3,
                "breaker_cooldown_s": 30,
                "tighten_min_confidence": 70,
                "on_failure": "rules_only",
            },
            "breachpath": {"edge_traversal": {}},
        },
        "impact": {
            "factors": [
                {"id": "IMP-SENS", "source": "action.sensitivity",
                 "map": {"low": "low", "medium": "medium", "high": "high"}},
                {"id": "IMP-RECORDS", "source": "action.record_count",
                 "steps": [{"gte": 50, "level": "high"}, {"gte": 10, "level": "medium"}]},
                {"id": "IMP-IRREV", "when": {"field": "action.reversible", "op": "eq", "value": False},
                 "level": "medium"},
                {"id": "IMP-EXTERNAL",
                 "when": {"field": "action.destination_external", "op": "eq", "value": True},
                 "level": "high"},
            ]
        },
        "constraints": {
            "global": {
                "protected_value_scan": True,
                "forbidden_patterns": [
                    {"id": "FP-SQL",
                     "regex": r"(?i)\b(drop|truncate)\s+table\b",
                     "applies_to": ["db.read", "db.update", "db.delete"]},
                ],
            },
            "per_action": {
                "email.send": {"deny_domains": ["pastebin.example", "mailinator.example", "blocked.example"],
                               "max_recipients": 20},
                "db.read": {"max_records_hard": 500},
                "db.update": {"max_records_hard": 100},
                "db.delete": {"max_records_hard": 100},
            },
        },
        "action_rules": [
            {"id": "AG-R-A01", "priority": 100, "outcome": "allow",
             "reason": "Fetching a page is low impact",
             "when": {"field": "action.type", "op": "eq", "value": "web.fetch"}},
            {"id": "AG-R-A02", "priority": 101, "outcome": "allow",
             "reason": "Reading reviews is low impact",
             "when": {"field": "action.type", "op": "eq", "value": "reviews.read"}},
            {"id": "AG-R-A03", "priority": 102, "outcome": "allow",
             "reason": "Small customer read in a clean session",
             "when": {"all": [
                 {"field": "action.type", "op": "eq", "value": "db.read"},
                 {"field": "session.taint_level", "op": "eq", "value": 0},
                 {"field": "action.record_count", "op": "lte", "value": 20},
             ]}},
            {"id": "AG-R-A04", "priority": 103, "outcome": "allow",
             "reason": "Email to internal recipients only",
             "when": {"all": [
                 {"field": "action.type", "op": "eq", "value": "email.send"},
                 {"field": "action.destination_external", "op": "eq", "value": False},
             ]}},
            {"id": "AG-R-A05", "priority": 104, "outcome": "allow",
             "reason": "Small account update",
             "when": {"all": [
                 {"field": "action.type", "op": "eq", "value": "db.update"},
                 {"field": "action.record_count", "op": "lte", "value": 10},
             ]}},
            {"id": "AG-R-H01", "priority": 10, "outcome": "hold",
             "reason": "External recipient requires human approval",
             "when": {"all": [
                 {"field": "action.type", "op": "eq", "value": "email.send"},
                 {"field": "action.destination_external", "op": "eq", "value": True},
             ]}},
            {"id": "AG-R-H02", "priority": 11, "outcome": "hold",
             "reason": "Flagged session, all outbound email needs approval (X-01)",
             "when": {"all": [
                 {"field": "action.type", "op": "eq", "value": "email.send"},
                 {"field": "session.taint_level", "op": "gte", "value": 2},
             ]}},
            {"id": "AG-R-H03", "priority": 12, "outcome": "hold",
             "reason": "High-sensitivity read in a tainted session or above the automatic row limit (X-01)",
             "when": {"all": [
                 {"field": "action.type", "op": "eq", "value": "db.read"},
                 {"field": "action.sensitivity", "op": "gte", "value": "high"},
                 {"any": [
                     {"field": "session.taint_level", "op": "gte", "value": 1},
                     {"field": "action.record_count", "op": "gt", "value": 20},
                 ]},
             ]}},
            {"id": "AG-R-H04", "priority": 13, "outcome": "hold",
             "reason": "Irreversible bulk delete requires approval",
             "when": {"all": [
                 {"field": "action.type", "op": "eq", "value": "db.delete"},
                 {"field": "action.reversible", "op": "eq", "value": False},
                 {"field": "action.record_count", "op": "gt", "value": 1},
             ]}},
            {"id": "AG-R-H05", "priority": 14, "outcome": "hold",
             "reason": "Action on a node on an attack path to a sensitive asset while the session is tainted (X-02)",
             "when": {"all": [
                 {"field": "blast.level", "op": "eq", "value": "high"},
                 {"field": "session.taint_level", "op": "gte", "value": 1},
             ]}},
            {"id": "AG-R-H06", "priority": 15, "outcome": "hold",
             "reason": "Account changes in a flagged session need approval",
             "when": {"all": [
                 {"field": "action.type", "op": "eq", "value": "db.update"},
                 {"field": "session.taint_level", "op": "gte", "value": 2},
             ]}},
            {"id": "AG-R-H07", "priority": 16, "outcome": "hold",
             "reason": "Update above the automatic row limit",
             "when": {"all": [
                 {"field": "action.type", "op": "eq", "value": "db.update"},
                 {"field": "action.record_count", "op": "gt", "value": 10},
             ]}},
            {"id": "AG-R-H08", "priority": 17, "outcome": "hold",
             "reason": "Fetching in a flagged session could carry data in the URL",
             "when": {"all": [
                 {"field": "action.type", "op": "eq", "value": "web.fetch"},
                 {"field": "session.taint_level", "op": "gte", "value": 2},
             ]}},
            {"id": "AG-R-H09", "priority": 18, "outcome": "hold",
             "reason": "Irreversible action with high impact",
             "when": {"all": [
                 {"field": "action.reversible", "op": "eq", "value": False},
                 {"field": "impact.level", "op": "eq", "value": "high"},
             ]}},
            {"id": "AG-R-B01", "priority": 1, "outcome": "block",
             "reason": "Deletes are refused in a flagged session",
             "when": {"all": [
                 {"field": "action.type", "op": "eq", "value": "db.delete"},
                 {"field": "session.taint_level", "op": "gte", "value": 2},
             ]}},
        ],
        "policy_rules": [
            {"id": "PC-R-001", "priority": 10, "outcome": "hold",
             "reason": "Every policy change needs approval from a different admin",
             "when": {"field": "diff.size", "op": "gte", "value": 0}},
            {"id": "PC-R-002", "priority": 1, "outcome": "block",
             "reason": "Only admins may propose policy changes",
             "when": {"field": "proposer.is_admin", "op": "eq", "value": False}},
        ],
        "ingress": {
            "thresholds": {
                "band_min": 40,
                "act_min": 60,
                "high_impact_types": ["exfil_target", "protected_value", "extraction"],
            },
            "table": {
                "developer":          {"override": "allow", "extraction": "allow", "exfil_target": "allow",
                                       "protected_value": "allow", "hidden_content": "allow", "directive": "allow"},
                "user":               {"override": "block", "extraction": "block", "exfil_target": "escalate",
                                       "protected_value": "block", "hidden_content": "sanitize", "directive": "allow"},
                "retrieved_document": {"override": "sanitize", "extraction": "sanitize", "exfil_target": "sanitize",
                                       "protected_value": "sanitize", "hidden_content": "sanitize",
                                       "directive": "sanitize"},
                "tool_output":        {"override": "sanitize", "extraction": "sanitize", "exfil_target": "sanitize",
                                       "protected_value": "sanitize", "hidden_content": "sanitize",
                                       "directive": "sanitize"},
            },
        },
    }


# ── Auth token helpers ────────────────────────────────────────────────────────

def _get_token(client, user_id: str, password: str = "demo") -> str:
    resp = client.post("/api/v1/auth/login", json={"user_id": user_id, "password": password})
    assert resp.status_code == 200, f"Login failed for {user_id}: {resp.text}"
    return resp.json()["token"]


@pytest.fixture
def alice_token(client):
    return _get_token(client, "alice")


@pytest.fixture
def bob_token(client):
    return _get_token(client, "bob")


@pytest.fixture
def admin_token(client):
    return _get_token(client, "admin")


@pytest.fixture
def dana_token(client):
    return _get_token(client, "dana")


@pytest.fixture
def agent_key():
    """Bearer token for supportbot agent plane calls."""
    return "agk_supportbot_demo0000000000000000000000"


@pytest.fixture
def alice_headers(alice_token):
    return {"Authorization": f"Bearer {alice_token}"}


@pytest.fixture
def bob_headers(bob_token):
    return {"Authorization": f"Bearer {bob_token}"}


@pytest.fixture
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def dana_headers(dana_token):
    return {"Authorization": f"Bearer {dana_token}"}


@pytest.fixture
def agent_headers(agent_key):
    return {"Authorization": f"Bearer {agent_key}"}
