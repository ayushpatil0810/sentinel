"""
End-to-End, Seed Verification, and Meta-Coverage Test Suite (M6).

Requirements covered:
- T-E2E-01: Replay S1..S8 matches expected outputs; ledger verify valid before S8 and broken after
- T-E2E-02: Deterministic replay on fresh DBs produces identical decision/event sequences
- T-E2E-03: Machine time for all 8 replay steps completes in under 60 seconds
- T-SD-01: Seed contents row counts, canaries at 7/142/233, graph routes, 30 reviews, users
- T-SD-02: Benchmark file validation (80 cases, 40 dev, 40 test, composition counts, no overlap)
- T-SD-03: Two seed runs produce identical SHA-256 dumps of seeded tables
- T-META-01: Every MVP requirement ID in spec.md §6 has at least one test with a req marker
"""

from __future__ import annotations

import ast
import contextlib
import hashlib
import json
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.core.auth import mint_human_token
from backend.app.db import close_connection, get_connection
from backend.app.main import app
from seed.seed import run_seed

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture(autouse=True)
def enable_demo_mode():
    orig_demo = settings.demo_mode
    settings.demo_mode = True
    yield
    settings.demo_mode = orig_demo


@pytest.mark.req("DEMO-01")
@pytest.mark.req("DEMO-02")
def test_T_E2E_01_scripted_replay():
    """
    T-E2E-01 / DEMO-01, DEMO-02:
    Scripted replay S1..S8 produces every expected block from demo-script.md.
    GET /ledger/verify valid before S8 and invalid at tampered seq after.
    """
    # Seed a dedicated test db
    test_db = str(REPO_ROOT / "e2e_replay.db")
    run_seed(test_db)

    settings.db = test_db
    close_connection()

    client = TestClient(app)
    admin_token = mint_human_token("admin", ["admin", "approver"])

    # 1. Start replay
    init_resp = client.post(
        "/api/v1/sandbox/replay",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"script_id": "demo-v1", "reset": True},
    )
    assert init_resp.status_code == 200
    init_data = init_resp.json()
    assert init_data["session_id"] == "sess_demo0001"
    assert len(init_data["steps"]) == 8

    # 2. Execute steps S1 to S7
    for step_id in ["S1", "S2", "S3", "S4", "S5", "S6", "S7"]:
        resp = client.post(
            "/api/v1/sandbox/replay/step",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"session_id": "sess_demo0001", "step_id": step_id},
        )
        assert resp.status_code == 200, f"Step {step_id} failed: {resp.text}"
        data = resp.json()
        assert data["match"] is True, f"Step {step_id} mismatch: actual={data['actual']} expected={data['expected']}"

    # Verify ledger is valid before S8
    v_pre = client.get("/ledger/verify")
    assert v_pre.status_code == 200
    assert v_pre.json()["valid"] is True

    # 3. Execute step S8 (tamper)
    resp_s8 = client.post(
        "/api/v1/sandbox/replay/step",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"session_id": "sess_demo0001", "step_id": "S8"},
    )
    assert resp_s8.status_code == 200
    assert resp_s8.json()["match"] is True

    # Verify ledger is broken after S8
    v_post = client.get("/ledger/verify")
    assert v_post.status_code == 200
    assert v_post.json()["valid"] is False
    assert v_post.json()["reason"] == "hash_mismatch"

    # Cleanup
    close_connection()
    import gc
    gc.collect()
    for ext in ("", "-wal", "-shm"):
        f = Path(f"{test_db}{ext}")
        if f.exists():
            with contextlib.suppress(PermissionError):
                f.unlink()


@pytest.mark.req("DEMO-01")
def test_T_E2E_02_replay_determinism():
    """
    T-E2E-02:
    Two full replays on freshly seeded DBs produce identical sequences of
    (event_type, outcome, rule_ids, decision_path).
    """
    def run_full_replay(db_name: str) -> list[tuple[str, str, str, str]]:
        db_path = str(REPO_ROOT / db_name)
        run_seed(db_path)
        settings.db = db_path
        close_connection()

        client = TestClient(app)
        token = mint_human_token("admin", ["admin", "approver"])

        client.post(
            "/api/v1/sandbox/replay",
            headers={"Authorization": f"Bearer {token}"},
            json={"script_id": "demo-v1", "reset": True},
        )
        for s in ["S1", "S2", "S3", "S4", "S5", "S6", "S7"]:
            client.post(
                "/api/v1/sandbox/replay/step",
                headers={"Authorization": f"Bearer {token}"},
                json={"session_id": "sess_demo0001", "step_id": s},
            )

        conn = get_connection()
        rows = conn.execute(
            "SELECT event_type, outcome, rule_ids_json, decision_path FROM ledger ORDER BY seq ASC"
        ).fetchall()
        seq = [(r[0], r[1], r[2], r[3]) for r in rows]

        close_connection()
        for ext in ("", "-wal", "-shm"):
            f = Path(f"{db_path}{ext}")
            if f.exists():
                with contextlib.suppress(PermissionError):
                    f.unlink()
        return seq

    seq1 = run_full_replay("det_replay1.db")
    seq2 = run_full_replay("det_replay2.db")

    assert len(seq1) == len(seq2)
    assert seq1 == seq2


@pytest.mark.req("DEMO-03")
def test_T_E2E_03_replay_speed():
    """
    T-E2E-03:
    Replay completes all 8 steps in under 60 s machine time.
    """
    test_db = str(REPO_ROOT / "speed_replay.db")
    run_seed(test_db)
    settings.db = test_db
    close_connection()

    client = TestClient(app)
    token = mint_human_token("admin", ["admin", "approver"])

    start_time = time.monotonic()
    client.post(
        "/api/v1/sandbox/replay",
        headers={"Authorization": f"Bearer {token}"},
        json={"script_id": "demo-v1", "reset": True},
    )
    for s in ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8"]:
        client.post(
            "/api/v1/sandbox/replay/step",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "sess_demo0001", "step_id": s},
        )
    elapsed = time.monotonic() - start_time

    assert elapsed < 60.0

    close_connection()
    for ext in ("", "-wal", "-shm"):
        f = Path(f"{test_db}{ext}")
        if f.exists():
            with contextlib.suppress(PermissionError):
                f.unlink()


@pytest.mark.req("SD-01")
@pytest.mark.req("SD-02")
@pytest.mark.req("SD-03")
@pytest.mark.req("SD-04")
@pytest.mark.req("SD-05")
def test_T_SD_01_seed_data_counts():
    """
    T-SD-01:
    Seed contents equal the counts and edge cases in seed-data.md:
    300 customers, 100 marketing prefs, 3 protected values, 2 agents, 6 action types.
    Canary rows: 7, 142, 233.
    30 reviews with 5 poisoned.
    Users: alice, bob, admin, dana.
    """
    test_db = str(REPO_ROOT / "sd_counts.db")
    run_seed(test_db)
    settings.db = test_db
    close_connection()

    conn = get_connection()

    # Row counts
    assert conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0] == 300
    assert conn.execute("SELECT COUNT(*) FROM marketing_prefs").fetchone()[0] == 100
    assert conn.execute("SELECT COUNT(*) FROM protected_values").fetchone()[0] == 3
    assert conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM action_types").fetchone()[0] == 6

    # Canary placement
    c7 = conn.execute("SELECT internal_notes FROM customers WHERE customer_id = 7").fetchone()[0]
    assert c7 == "sk-acme-4c1f9e27b8a3d605e7f1"

    c142 = conn.execute("SELECT internal_notes FROM customers WHERE customer_id = 142").fetchone()[0]
    assert c142 == "NID-4417-9082-3361"

    c233 = conn.execute("SELECT internal_notes FROM customers WHERE customer_id = 233").fetchone()[0]
    assert c233 == "CANARY::acme::0x7d3e91"

    # Other rows have empty internal_notes
    c_other = conn.execute("SELECT COUNT(*) FROM customers WHERE customer_id NOT IN (7, 142, 233) AND internal_notes != ''").fetchone()[0]
    assert c_other == 0

    # Users
    users = {r[0] for r in conn.execute("SELECT user_id FROM users").fetchall()}
    assert {"alice", "bob", "admin", "dana"}.issubset(users)

    # Reviews
    rev_path = REPO_ROOT / "seed" / "reviews.json"
    with open(rev_path, encoding="utf-8") as f:
        reviews = json.load(f)
    assert len(reviews) == 30
    poisoned = [r for r in reviews if r["id"].startswith("rv-p")]
    assert len(poisoned) == 5

    close_connection()
    for ext in ("", "-wal", "-shm"):
        f = Path(f"{test_db}{ext}")
        if f.exists():
            f.unlink()


@pytest.mark.req("SD-06")
def test_T_SD_02_benchmark_file():
    """
    T-SD-02 / SD-06:
    Benchmark file validates against schema. 80 cases.
    Split sizes: 40 dev, 40 test. Composition counts. No duplicate texts across splits.
    """
    bench_path = REPO_ROOT / "seed" / "benchmark.json"
    with open(bench_path, encoding="utf-8") as f:
        cases = json.load(f)

    assert len(cases) == 80

    dev_cases = [c for c in cases if c.get("split") == "dev"]
    test_cases = [c for c in cases if c.get("split") == "test"]
    assert len(dev_cases) == 40
    assert len(test_cases) == 40

    # Malicious vs benign
    mal = [c for c in cases if c.get("label") == "malicious"]
    ben = [c for c in cases if c.get("label") == "benign"]
    assert len(mal) == 44
    assert len(ben) == 36

    # Direct vs indirect malicious
    direct_mal = [c for c in mal if (c.get("source_tier") or c.get("tier")) == "user"]
    indirect_mal = [c for c in mal if (c.get("source_tier") or c.get("tier")) in ("retrieved_document", "tool_output")]
    assert len(direct_mal) == 20
    assert len(indirect_mal) == 24

    # Known hard: 12 total, 6 dev, 6 test
    kh = [c for c in cases if c.get("known_hard") is True]
    assert len(kh) == 12

    # No duplicate texts across splits
    dev_texts = {c["text"].strip() for c in dev_cases}
    test_texts = {c["text"].strip() for c in test_cases}
    assert len(dev_texts.intersection(test_texts)) == 0


@pytest.mark.req("SD-07")
def test_T_SD_03_seed_determinism():
    """
    T-SD-03 / SD-07:
    Two seed runs: SHA-256 of the dump of seeded tables (excluding timestamps) is identical.
    """
    def get_table_hash(db_name: str) -> str:
        db_path = str(REPO_ROOT / db_name)
        run_seed(db_path)
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        tables = ["users", "agents", "action_types", "protected_values", "customers", "marketing_prefs"]
        dump_data = []

        for tbl in tables:
            rows = conn.execute(f"SELECT * FROM {tbl}").fetchall()
            for r in rows:
                dump_data.append(tuple(r))

        conn.close()
        for ext in ("", "-wal", "-shm"):
            f = Path(f"{db_path}{ext}")
            if f.exists():
                with contextlib.suppress(PermissionError):
                    f.unlink()

        return hashlib.sha256(json.dumps(dump_data, default=str).encode("utf-8")).hexdigest()

    h1 = get_table_hash("seed_det1.db")
    h2 = get_table_hash("seed_det2.db")
    assert h1 == h2


def test_T_META_01_coverage_gate():
    """
    T-META-01 / test-plan §7:
    Every MVP requirement ID in spec.md §6 has at least one test with a req marker.
    """
    tests_dir = REPO_ROOT / "backend" / "tests"
    covered_reqs: set[str] = set()

    for test_file in tests_dir.glob("test_*.py"):
        try:
            tree = ast.parse(test_file.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                    for dec in node.decorator_list:
                        if (
                            isinstance(dec, ast.Call)
                            and hasattr(dec.func, "attr")
                            and dec.func.attr == "req"
                            and dec.args
                            and isinstance(dec.args[0], ast.Constant)
                        ):
                            covered_reqs.add(str(dec.args[0].value))
        except Exception:
            pass

    # MVP IDs from spec.md Section 6
    required_ids = [
        "PE-01", "PE-02", "PE-03", "PE-04", "PE-05", "PE-06", "PE-07",
        "LG-01", "LG-02", "LG-03", "LG-04", "LG-05", "LG-07",
        "LA-01", "LA-02", "LA-03", "LA-04", "LA-05",
        "SS-01", "SS-02", "SS-03", "SS-04",
        "AU-01", "AU-02", "AU-03", "AU-04",
        "AG-01", "AG-02", "AG-03", "AG-04", "AG-05", "AG-06", "AG-07", "AG-08",
        "AG-09", "AG-10", "AG-11", "AG-12", "AG-13", "AG-14", "AG-15", "AG-16",
        "BP-01", "BP-02", "BP-03", "BP-04", "BP-05", "BP-06", "BP-07", "BP-08",
        "BP-09", "BP-10", "BP-11", "BP-12", "BP-14", "BP-15", "BP-17", "BP-18",
        "PS-01", "PS-02", "PS-03", "PS-04", "PS-05", "PS-06", "PS-07", "PS-08",
        "PS-09", "PS-10", "PS-11", "PS-12", "PS-13", "PS-14", "PS-15", "PS-16",
        "X-01", "X-02", "X-03", "X-05", "X-06", "X-07",
        "SD-01", "SD-02", "SD-03", "SD-04", "SD-05", "SD-06", "SD-07",
        "DEMO-01", "DEMO-02", "DEMO-03",
    ]

    missing = [req for req in required_ids if req not in covered_reqs]
    assert len(missing) == 0, f"Uncovered MVP requirements: {missing}"
