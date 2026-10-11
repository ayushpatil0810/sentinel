"""
Deterministic seed script for Sentinel (SD-07, seed-data.md §8).

Recreates database, tables, triggers, and all synthetic data using seed 1337.
Produces ledger seq 1 (policy.activated), seq 2 (graph.uploaded), seq 3 (graph.derived_entry_points).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

import yaml
from faker import Faker

# Ensure project root is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.app.actiongate.registries import get_action_type_registry  # noqa: E402
from backend.app.breachpath.blast import derive_entry_points  # noqa: E402
from backend.app.core import ledger  # noqa: E402
from backend.app.core.canonical import canonical_json  # noqa: E402
from backend.app.core.clock import FixedClock, set_clock  # noqa: E402


def run_seed(db_path: str = "sentinel.db") -> None:
    """Execute the full deterministic seeding sequence."""
    random.seed(1337)
    Faker.seed(1337)
    fake = Faker("en_US")

    # 1. Reset database file if applicable
    if db_path != ":memory:":
        db_file = Path(db_path)
        if db_file.exists():
            db_file.unlink()
        wal_file = Path(f"{db_path}-wal")
        if wal_file.exists():
            wal_file.unlink()
        shm_file = Path(f"{db_path}-shm")
        if shm_file.exists():
            shm_file.unlink()

    # Configure clock: starts at 2026-01-01T00:00:00.000Z, advances 1s per call
    clock = FixedClock(start_iso="2026-01-01T00:00:00.000Z", step_ms=1000)
    set_clock(clock)

    # Configure DB path in settings and close any previous thread connection
    from backend.app.config import settings
    from backend.app.db import close_connection, get_connection
    settings.db = db_path
    close_connection()
    conn = get_connection()

    # 2. Users (SD-05)
    pw_hash = hashlib.sha256(b"demo").hexdigest()
    users_data = [
        ("alice", "Alice (requester)", json.dumps(["requester"]), pw_hash),
        ("bob", "Bob (approver)", json.dumps(["approver"]), pw_hash),
        ("admin", "Admin", json.dumps(["admin", "approver"]), pw_hash),
        ("dana", "Admin 2", json.dumps(["admin", "approver"]), pw_hash),
    ]
    conn.executemany(
        "INSERT INTO users (user_id, display_name, roles_json, password_hash) VALUES (?, ?, ?, ?)",
        users_data,
    )

    # Agents (SD-04)
    supportbot_key = "agk_supportbot_demo0000000000000000000000"
    legacybot_key = "agk_legacybot_demo0000000000000000000000"
    agents_data = [
        (
            "supportbot",
            "SupportBot",
            "active",
            json.dumps(["web.fetch", "reviews.read", "db.read", "email.send", "db.update", "db.delete"]),
            "agent:supportbot",
            hashlib.sha256(supportbot_key.encode("utf-8")).hexdigest(),
        ),
        (
            "legacybot",
            "LegacyBot",
            "suspended",
            json.dumps(["db.read"]),
            "agent:legacybot",
            hashlib.sha256(legacybot_key.encode("utf-8")).hexdigest(),
        ),
    ]
    conn.executemany(
        """INSERT INTO agents
           (agent_id, name, status, allowed_action_types_json, graph_node_id, api_key_hash)
           VALUES (?, ?, ?, ?, ?, ?)""",
        agents_data,
    )

    # Action types (SD-04)
    from backend.app.actiongate.registries import ACTION_TYPES_SEED
    for atype in ACTION_TYPES_SEED:
        conn.execute(
            "INSERT OR REPLACE INTO action_types (action_type, definition_json) VALUES (?, ?)",
            (atype["action_type"], canonical_json(atype)),
        )

    # Protected values (SD-01)
    pvs = [
        ("pv-apikey-1", "canary", "sk-acme-4c1f9e27b8a3d605e7f1", 8),
        ("pv-nid-1", "national_id", "NID-4417-9082-3361", 8),
        ("pv-marker-1", "canary", "CANARY::acme::0x7d3e91", 8),
    ]
    conn.executemany(
        "INSERT INTO protected_values (pv_id, kind, value_norm, min_len) VALUES (?, ?, ?, ?)",
        pvs,
    )
    conn.commit()

    # 3. Policy v1 (SD-04)
    policy_path = REPO_ROOT / "seed" / "policy_v1.yaml"
    with open(policy_path, encoding="utf-8") as f:
        policy_doc = yaml.safe_load(f)

    pol_json = canonical_json(policy_doc)
    pol_hash = hashlib.sha256(pol_json.encode("utf-8")).hexdigest()
    ts_pol = clock.now_iso()

    conn.execute(
        """INSERT INTO policy_versions
           (version, parent_version, content_json, content_hash, created_by, approved_by, created_at, activated_at)
           VALUES (1, NULL, ?, ?, 'system', 'system', ?, ?)""",
        (pol_json, pol_hash, ts_pol, ts_pol),
    )
    conn.commit()

    # Ledger seq 1: policy.activated
    ledger.append(
        module="policy",
        event_type="policy.activated",
        subject="policy:sentinel-default",
        outcome="allow",
        reason="Seeded initial default policy v1",
        rule_ids=[],
        decision_path="rules",
        policy_version=1,
        payload={"version": 1, "policy_id": "sentinel-default", "content_hash": pol_hash},
        clock=clock,
    )

    # 4. Customers & Marketing Prefs (SD-01)
    customers_data = []
    for cid in range(1, 301):
        name = fake.name()
        email = fake.safe_email()
        phone = fake.phone_number()
        order_total_cents = random.randint(500, 250000)
        internal_notes = ""
        if cid == 7:
            internal_notes = "sk-acme-4c1f9e27b8a3d605e7f1"
        elif cid == 142:
            internal_notes = "NID-4417-9082-3361"
        elif cid == 233:
            internal_notes = "CANARY::acme::0x7d3e91"
        customers_data.append((cid, name, email, phone, order_total_cents, internal_notes))

    conn.executemany(
        """INSERT INTO customers (customer_id, name, email, phone, order_total_cents, internal_notes)
           VALUES (?, ?, ?, ?, ?, ?)""",
        customers_data,
    )

    marketing_data = []
    for contact_id in range(1, 101):
        m_email = fake.safe_email()
        opted_in = random.randint(0, 1)
        marketing_data.append((contact_id, m_email, opted_in))

    conn.executemany(
        "INSERT INTO marketing_prefs (contact_id, email, opted_in) VALUES (?, ?, ?)",
        marketing_data,
    )
    conn.commit()

    # 5. Graph Version 1 (SD-02)
    graph_path = REPO_ROOT / "seed" / "graph.json"
    with open(graph_path, encoding="utf-8") as f:
        graph_v1 = json.load(f)

    g1_json = canonical_json(graph_v1)
    g1_hash = hashlib.sha256(g1_json.encode("utf-8")).hexdigest()
    ts_g1 = clock.now_iso()

    conn.execute(
        """INSERT INTO graph_versions
           (graph_version, parent_version, graph_json, change_json, created_by, created_at, content_hash)
           VALUES (1, NULL, ?, 'seed', 'system', ?, ?)""",
        (g1_json, ts_g1, g1_hash),
    )
    conn.commit()

    # Ledger seq 2: graph.uploaded
    ledger.append(
        module="breachpath",
        event_type="graph.uploaded",
        subject="graph:1",
        outcome="allow",
        reason="Seeded initial access graph v1",
        rule_ids=[],
        decision_path="rules",
        policy_version=1,
        payload={"graph_version": 1, "nodes_count": len(graph_v1.get("nodes", [])), "edges_count": len(graph_v1.get("edges", []))},
        clock=clock,
    )

    # 6. Graph Version 2: derive_entry_points (SD-02, X-03)
    act_reg = get_action_type_registry()
    graph_v2, changed, _ = derive_entry_points(act_reg, graph_v1)
    g2_json = canonical_json(graph_v2)
    g2_hash = hashlib.sha256(g2_json.encode("utf-8")).hexdigest()
    ts_g2 = clock.now_iso()

    conn.execute(
        """INSERT INTO graph_versions
           (graph_version, parent_version, graph_json, change_json, created_by, created_at, content_hash)
           VALUES (2, 1, ?, ?, 'system', ?, ?)""",
        (g2_json, json.dumps([{"op": "derive_entry_points"}]), ts_g2, g2_hash),
    )
    conn.commit()

    # Ledger seq 3: graph.derived_entry_points
    derived_nodes = [n["id"] for n in graph_v2.get("nodes", []) if n.get("entry_source") == "derived"]
    ledger.append(
        module="breachpath",
        event_type="graph.derived_entry_points",
        subject="graph:2",
        outcome="allow",
        reason="Derived tool entry points from registry",
        rule_ids=[],
        decision_path="rules",
        policy_version=1,
        payload={"graph_version": 2, "derived": derived_nodes},
        clock=clock,
    )

    head = conn.execute("SELECT MAX(seq) FROM ledger").fetchone()[0]
    conn.close()

    print(f"Agent key: {supportbot_key}")
    print(f"Ledger head: {head}")


if __name__ == "__main__":
    import os
    parser = argparse.ArgumentParser(description="Seed the Sentinel database.")
    parser.add_argument("--db", default=None, help="Path to SQLite database file")
    parser.add_argument("--if-empty", action="store_true", help="Only seed if database is missing or empty")
    args = parser.parse_args()

    db_path = args.db or os.environ.get("SENTINEL_DB", "sentinel.db")

    if args.if_empty and db_path != ":memory:":
        target_path = Path(db_path)
        if target_path.exists() and target_path.stat().st_size > 0:
            try:
                import sqlite3
                check_conn = sqlite3.connect(db_path)
                cnt = check_conn.execute("SELECT count(*) FROM users").fetchone()[0]
                check_conn.close()
                if cnt > 0:
                    print(f"Database {db_path} already initialized with {cnt} users. Skipping seed (--if-empty).")
                    sys.exit(0)
            except Exception:
                pass

    run_seed(db_path)

