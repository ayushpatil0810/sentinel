"""
Tests for BreachPath (M3):
  BP-01..BP-12, BP-14, BP-15, BP-17, BP-18, X-03
"""

from __future__ import annotations

import copy
import json
import time
from pathlib import Path

import pytest

from backend.app.breachpath.blast import compute_blast_radius, derive_entry_points
from backend.app.breachpath.changes import apply_graph_changes
from backend.app.breachpath.diff import compute_route_diff
from backend.app.breachpath.remediation import generate_remediations
from backend.app.breachpath.search import find_routes
from backend.app.breachpath.store import get_current_graph, init_seed_graph
from backend.app.breachpath.validation import validate_graph_dict
from backend.app.core import ledger

SEED_GRAPH_FILE = Path(__file__).resolve().parent.parent.parent / "seed" / "graph.json"
BAD_GRAPH_FILE = Path(__file__).resolve().parent.parent.parent / "seed" / "bad_graph.json"


@pytest.fixture
def seed_graph() -> dict:
    with open(SEED_GRAPH_FILE, encoding="utf-8") as f:
        g = json.load(f)
    # Ensure derived entry points are set as in v2
    for n in g.get("nodes", []):
        if n.get("id") in ("tool:browse_page", "tool:read_reviews"):
            n["entry_point"] = True
            n["entry_source"] = "derived"
            n.setdefault("attrs", {})["badge"] = "derived"
    return g


# ── BP-01: Validation ─────────────────────────────────────────────────────────

@pytest.mark.req("BP-01")
def test_T_BP_01_validation_seed_and_invalid_fixtures(seed_graph):
    """Seed graph is valid; invalid models return specific error codes and pointers."""
    res = validate_graph_dict(seed_graph)
    assert res.valid is True
    assert len(res.errors) == 0

    # Bad ID
    bad_id_graph = copy.deepcopy(seed_graph)
    bad_id_graph["nodes"][0]["id"] = "-invalid-id"
    res = validate_graph_dict(bad_id_graph)
    assert any(e["code"] == "E_BAD_ID" and e["pointer"] == "/nodes/0/id" for e in res.errors)

    # Unknown node type
    bad_type_graph = copy.deepcopy(seed_graph)
    bad_type_graph["nodes"][0]["type"] = "alien"
    res = validate_graph_dict(bad_type_graph)
    assert any(e["code"] == "E_UNKNOWN_NODE_TYPE" and e["pointer"] == "/nodes/0/type" for e in res.errors)

    # Unknown edge type
    bad_etype_graph = copy.deepcopy(seed_graph)
    bad_etype_graph["edges"][0]["type"] = "teleports_to"
    res = validate_graph_dict(bad_etype_graph)
    assert any(e["code"] == "E_UNKNOWN_EDGE_TYPE" and e["pointer"] == "/edges/0/type" for e in res.errors)

    # Duplicate node ID
    dup_node_graph = copy.deepcopy(seed_graph)
    dup_node_graph["nodes"].append({"id": "tool:browse_page", "type": "tool", "name": "Dup"})
    res = validate_graph_dict(dup_node_graph)
    assert any(e["code"] == "E_DUP_NODE_ID" for e in res.errors)

    # Dangling endpoints
    dangling_graph = copy.deepcopy(seed_graph)
    dangling_graph["edges"].append({"id": "e-ghost", "src": "svc:ghost_src", "dst": "svc:ghost_dst", "type": "calls"})
    res = validate_graph_dict(dangling_graph)
    assert any(e["code"] == "E_DANGLING_SRC" for e in res.errors)
    assert any(e["code"] == "E_DANGLING_DST" for e in res.errors)

    # Bad settings
    bad_settings_graph = copy.deepcopy(seed_graph)
    bad_settings_graph["settings"]["max_depth"] = 99
    res = validate_graph_dict(bad_settings_graph)
    assert any(e["code"] == "E_BAD_SETTINGS" for e in res.errors)


# ── BP-02: bad_graph.json rejection ───────────────────────────────────────────

@pytest.mark.req("BP-02")
def test_T_BP_02_bad_graph_rejection_no_invented_nodes(client, admin_headers):
    """bad_graph.json is rejected with exactly 3 errors, ledgered, no state change."""
    with open(BAD_GRAPH_FILE, encoding="utf-8") as f:
        bad_json = f.read()

    init_seed_graph()
    cur_ver, _ = get_current_graph()

    resp = client.put(
        "/api/v1/graph?format=json",
        content=bad_json.encode("utf-8"),
        headers={"Content-Type": "application/json", **admin_headers},
    )
    assert resp.status_code == 422
    err_body = resp.json()["error"]
    assert err_body["code"] == "graph.invalid"
    errors = err_body["details"]["errors"]
    assert len(errors) == 3

    error_codes = {e["code"] for e in errors}
    assert "E_MISSING_FIELD" in error_codes
    assert "E_DANGLING_DST" in error_codes
    assert "E_BAD_SENSITIVITY" in error_codes

    # Version unchanged
    new_ver, _ = get_current_graph()
    assert new_ver == cur_ver


# ── BP-03: Cycle safety ───────────────────────────────────────────────────────

@pytest.mark.req("BP-03")
def test_T_BP_03_cycle_safety(seed_graph):
    """Seed route through A,B,C cycle is found once; pure cycle terminates quickly without node repetition."""
    res = find_routes(seed_graph, max_depth=4)
    # R7 travels through cyc_a -> cyc_b -> cyc_c -> billing_ledger
    r7_matches = [r for r in res.routes if r["path_id"] == "p_54422463a590"]
    assert len(r7_matches) == 1
    r7 = r7_matches[0]
    nodes_in_r7 = [s["from"] for s in r7["steps"]] + [r7["steps"][-1]["to"]]
    assert len(nodes_in_r7) == len(set(nodes_in_r7)), "Route must not repeat any node"

    # Pure cycle graph: 1 -> 2 -> 3 -> 1 (no targets)
    pure_cycle = {
        "nodes": [
            {"id": "n1", "type": "service", "name": "N1", "entry_point": True},
            {"id": "n2", "type": "service", "name": "N2"},
            {"id": "n3", "type": "service", "name": "N3"},
        ],
        "edges": [
            {"id": "e12", "src": "n1", "dst": "n2", "type": "calls"},
            {"id": "e23", "src": "n2", "dst": "n3", "type": "calls"},
            {"id": "e31", "src": "n3", "dst": "n1", "type": "calls"},
        ],
        "settings": {"max_depth": 8, "max_paths": 1000, "time_budget_ms": 2000, "sensitive_min": "medium"},
    }
    t0 = time.monotonic()
    cycle_res = find_routes(pure_cycle, max_depth=8)
    elapsed = time.monotonic() - t0
    assert elapsed < 0.1, f"Pure cycle search took {elapsed}s, should be <100ms"
    assert len(cycle_res.routes) == 0


# ── BP-04: Max depth routes ───────────────────────────────────────────────────

@pytest.mark.req("BP-04")
def test_T_BP_04_max_depth_routes(seed_graph):
    """Route counts by max_depth: 1: 0, 2: 2, 3: 6, 4: 7, 5: 8. Depth 5 adds p_ea09acc7dc00."""
    counts = {}
    for d in range(1, 6):
        res = find_routes(seed_graph, max_depth=d)
        counts[d] = len(res.routes)

    assert counts[1] == 0
    assert counts[2] == 2
    assert counts[3] == 6
    assert counts[4] == 7
    assert counts[5] == 8

    res_5 = find_routes(seed_graph, max_depth=5)
    pids_5 = {r["path_id"] for r in res_5.routes}
    assert "p_ea09acc7dc00" in pids_5


# ── BP-05 & BP-06: Ordered steps and golden explanation ───────────────────────

@pytest.mark.req("BP-05")
def test_T_BP_05_route_ordered_steps(seed_graph):
    """Route p_460263f0bbf3 has 3 ordered steps with step 1 reversed."""
    res = find_routes(seed_graph, max_depth=4)
    r2 = next(r for r in res.routes if r["path_id"] == "p_460263f0bbf3")
    assert r2["length"] == 3
    assert len(r2["steps"]) == 3

    assert r2["steps"][0]["edge_id"] == "e-agent-ingest-bp"
    assert r2["steps"][0]["edge_type"] == "ingests_from"
    assert r2["steps"][0]["reversed"] is True

    assert r2["steps"][1]["edge_id"] == "e-agent-invoke-mailer"
    assert r2["steps"][1]["edge_type"] == "can_invoke"
    assert r2["steps"][1]["reversed"] is False

    assert r2["steps"][2]["edge_id"] == "e-mailer-read-customerdb"
    assert r2["steps"][2]["edge_type"] == "can_read"
    assert r2["steps"][2]["reversed"] is False


@pytest.mark.req("BP-06")
def test_T_BP_06_golden_explanation(seed_graph):
    """Golden explanation for p_460263f0bbf3 equals the golden string exactly."""
    res = find_routes(seed_graph, max_depth=4)
    r2 = next(r for r in res.routes if r["path_id"] == "p_460263f0bbf3")

    golden = (
        "From Browse Page tool to Customer DB (high) in 3 steps.\n"
        "1. Content controlled at Browse Page tool is ingested by SupportBot, so whoever controls it can steer SupportBot.\n"
        "2. SupportBot can invoke Mailer.\n"
        "3. Mailer can read Customer DB.\n"
        "Short: SupportBot can invoke Mailer, which can read Customer DB."
    )
    assert r2["explanation"] == golden


# ── BP-07: Remediation candidates and ranking ─────────────────────────────────

@pytest.mark.req("BP-07")
def test_T_BP_07_remediation_candidates_and_ranking(seed_graph):
    """11 candidate edges on seed graph depth 4, ranked per seed-data table, greedy cover plan."""
    res = find_routes(seed_graph, max_depth=4)
    rem = generate_remediations(seed_graph, res.routes)

    suggestions = rem["suggestions"]
    assert len(suggestions) == 11

    # Check top candidate
    assert suggestions[0]["edge_id"] == "e-agent-ingest-bp"
    assert suggestions[0]["breaks"] == 3

    # Check that every candidate exists in model
    existing_edge_ids = {e["id"] for e in seed_graph["edges"]}
    for s in suggestions:
        assert s["edge_id"] in existing_edge_ids

    # Greedy plan
    plan = rem["plan"]
    assert len(plan) == 3
    assert plan[0] == {"edge_id": "e-agent-ingest-bp", "covers": 3}
    assert plan[1] == {"edge_id": "e-agent-ingest-rr", "covers": 3}
    assert plan[2] == {"edge_id": "e-cyc-a-b", "covers": 1}


# ── BP-08: User-decided apply & preview ────────────────────────────────────────

@pytest.mark.req("BP-08")
def test_T_BP_08_user_decided_apply(client, alice_headers, admin_headers):
    """Preview does not mutate graph_version; apply by requester fails 403; admin succeeds with version +1."""
    init_seed_graph()
    ver_before, _ = get_current_graph()

    # Preview by any human
    prev_resp = client.post(
        "/api/v1/graph/remediations/e-agent-ingest-bp/preview",
        headers=alice_headers,
    )
    assert prev_resp.status_code == 200
    assert len(prev_resp.json()["removed"]) == 3
    ver_after_prev, _ = get_current_graph()
    assert ver_after_prev == ver_before

    # Apply by non-admin (Alice) -> 403
    app_resp_alice = client.post(
        "/api/v1/graph/remediations/e-agent-ingest-bp/apply",
        json={"expected_version": ver_before},
        headers=alice_headers,
    )
    assert app_resp_alice.status_code == 403

    # Apply by Admin -> 200, version +1
    app_resp_admin = client.post(
        "/api/v1/graph/remediations/e-agent-ingest-bp/apply",
        json={"expected_version": ver_before},
        headers=admin_headers,
    )
    assert app_resp_admin.status_code == 200
    assert app_resp_admin.json()["graph_version"] == ver_before + 1


# ── BP-09: Diff correctness ───────────────────────────────────────────────────

@pytest.mark.req("BP-09")
def test_T_BP_09_diff_correctness_seed_changes(seed_graph):
    """Diffs for CHG-1 to CHG-4 and DEMO-6 equal the seed-data table."""
    routes_base = find_routes(seed_graph, max_depth=4).routes

    # CHG-1: add_edge -> 0 removed, 7 remaining, 1 new
    chg1 = [{"op": "add_edge", "edge": {"id": "e-reporting-read-customerdb", "src": "svc:reporting", "dst": "asset:customer_db", "type": "can_read"}}]
    m1, _ = apply_graph_changes(seed_graph, chg1)
    diff1 = compute_route_diff(routes_base, find_routes(m1, max_depth=4).routes, 2, 3)
    assert len(diff1["removed"]) == 0
    assert len(diff1["remaining"]) == 7
    assert len(diff1["new"]) == 1

    # CHG-2: remove_edge -> 2 removed, 5 remaining, 0 new
    chg2 = [{"op": "remove_edge", "edge_id": "e-mailer-read-customerdb"}]
    m2, _ = apply_graph_changes(seed_graph, chg2)
    diff2 = compute_route_diff(routes_base, find_routes(m2, max_depth=4).routes, 2, 3)
    assert len(diff2["removed"]) == 2
    assert len(diff2["remaining"]) == 5
    assert len(diff2["new"]) == 0

    # CHG-3: set_entry_point crm -> 0 removed, 7 remaining, 1 new
    chg3 = [{"op": "set_entry_point", "node_id": "svc:crm", "value": True}]
    m3, _ = apply_graph_changes(seed_graph, chg3)
    diff3 = compute_route_diff(routes_base, find_routes(m3, max_depth=4).routes, 2, 3)
    assert len(diff3["removed"]) == 0
    assert len(diff3["remaining"]) == 7
    assert len(diff3["new"]) == 1

    # CHG-4: remove entry_point partner_feed -> 1 removed, 6 remaining, 0 new
    chg4 = [{"op": "set_entry_point", "node_id": "ext:partner_feed", "value": False}]
    m4, _ = apply_graph_changes(seed_graph, chg4)
    diff4 = compute_route_diff(routes_base, find_routes(m4, max_depth=4).routes, 2, 3)
    assert len(diff4["removed"]) == 1
    assert len(diff4["remaining"]) == 6
    assert len(diff4["new"]) == 0

    # DEMO-6: remove_edge e-agent-read-customerdb -> 2 removed, 5 remaining, 0 new
    chg6 = [{"op": "remove_edge", "edge_id": "e-agent-read-customerdb"}]
    m6, _ = apply_graph_changes(seed_graph, chg6)
    diff6 = compute_route_diff(routes_base, find_routes(m6, max_depth=4).routes, 2, 3)
    assert len(diff6["removed"]) == 2
    assert len(diff6["remaining"]) == 5
    assert len(diff6["new"]) == 0


# ── BP-10: Truncation honesty ─────────────────────────────────────────────────

@pytest.mark.req("BP-10")
def test_T_BP_10_truncation_honesty(seed_graph):
    """Dense graph with max_paths cap yields truncated: true and comparison_reliable: false."""
    res = find_routes(seed_graph, max_paths=3)
    assert res.truncated is True
    assert res.truncation_reason == "max_paths"
    assert res.warning is not None
    assert len(res.routes) == 3

    # Diff against truncated set
    diff = compute_route_diff(res.routes, res.routes, 2, 3, comparison_reliable=not res.truncated)
    assert diff["comparison_reliable"] is False


# ── BP-11 & X-03: Derived entry points ────────────────────────────────────────

@pytest.mark.req("BP-11")
def test_T_BP_11_derive_entry_points():
    """derive_entry_points flags untrusted tools without creating nodes."""
    from backend.app.actiongate.registries import get_action_type_registry
    act_reg = get_action_type_registry()

    with open(SEED_GRAPH_FILE, encoding="utf-8") as f:
        raw_graph = json.load(f)

    updated, changed, warnings = derive_entry_points(act_reg, raw_graph)
    assert changed is True
    node_map = {n["id"]: n for n in updated["nodes"]}
    assert node_map["tool:browse_page"]["entry_point"] is True
    assert node_map["tool:browse_page"]["entry_source"] == "derived"
    assert node_map["tool:browse_page"]["attrs"]["badge"] == "derived"

    assert node_map["tool:read_reviews"]["entry_point"] is True
    assert node_map["tool:read_reviews"]["entry_source"] == "derived"

    # Missing tool_node gives warning, no node created
    fake_reg = copy.deepcopy(act_reg)
    fake_reg["ghost.action"] = {"ingests_untrusted": True, "tool_node": "tool:ghost"}
    _, _, ghost_warnings = derive_entry_points(fake_reg, updated)
    assert any(w["code"] == "W_TOOL_NODE_MISSING" for w in ghost_warnings)
    assert "tool:ghost" not in {n["id"] for n in updated["nodes"]}


# ── BP-12: Blast radius ───────────────────────────────────────────────────────

@pytest.mark.req("BP-12")
def test_T_BP_12_blast_radius(seed_graph):
    """Blast radius matches table in seed-data.md §2.5; unknown node fail-safe level: high."""
    expected = {
        "asset:customer_db": {"on_path": True, "paths": 6, "dist": 0, "level": "high"},
        "agent:supportbot": {"on_path": True, "paths": 6, "dist": 1, "level": "high"},
        "svc:mailer": {"on_path": True, "paths": 2, "dist": 1, "level": "high"},
        "tool:browse_page": {"on_path": True, "paths": 3, "dist": 2, "level": "high"},
        "asset:marketing_db": {"on_path": False, "paths": 0, "dist": None, "level": "low"},
        "tool:send_email": {"on_path": False, "paths": 0, "dist": None, "level": "low"},
        "svc:reporting": {"on_path": False, "paths": 0, "dist": None, "level": "low"},
        "svc:crm": {"on_path": False, "paths": 0, "dist": 2, "level": "medium"},
        "role:finance_ro": {"on_path": False, "paths": 0, "dist": 1, "level": "medium"},
    }

    for nid, exp in expected.items():
        b = compute_blast_radius(seed_graph, nid)
        assert b["on_attack_path"] == exp["on_path"], f"{nid} on_path mismatch"
        assert b["paths_count"] == exp["paths"], f"{nid} paths mismatch"
        assert b["min_distance_to_sensitive"] == exp["dist"], f"{nid} dist mismatch"
        assert b["level"] == exp["level"], f"{nid} level mismatch"

    # Unknown node fail-safe
    b_unknown = compute_blast_radius(seed_graph, "agent:legacybot")
    assert b_unknown["level"] == "high"
    assert b_unknown["reason"] == "unknown_node"


# ── BP-14: Versioning and Ledger ──────────────────────────────────────────────

@pytest.mark.req("BP-14")
def test_T_BP_14_versioning_and_ledger(client, admin_headers):
    """Each change creates version +1 and one graph.changed ledger event."""
    init_seed_graph()
    cur_ver, _ = get_current_graph()

    resp = client.post(
        "/api/v1/graph/changes",
        json={
            "expected_version": cur_ver,
            "changes": [{"op": "set_sensitivity", "node_id": "asset:marketing_db", "value": "medium"}],
        },
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["graph_version"] == cur_ver + 1

    # Check ledger
    entries = ledger.query(module="breachpath", event_type="graph.changed")
    assert len(entries) > 0
    latest = entries[-1]
    assert latest["outcome"] == "allow"


# ── BP-15: Limits & unreadable files ──────────────────────────────────────────

@pytest.mark.req("BP-15")
def test_T_BP_15_limits_and_unreadable_files(client, admin_headers):
    """1 MiB + 1 byte: 413; 501 nodes: E_LIMIT; unreadable: E_UNREADABLE."""
    init_seed_graph()

    # Oversized payload > 1 MiB
    huge_data = b" " * (1024 * 1024 + 10)
    resp = client.put(
        "/api/v1/graph?format=json",
        content=huge_data,
        headers={"Content-Type": "application/json", **admin_headers},
    )
    assert resp.status_code == 413

    # Binary/unreadable file
    resp_bin = client.put(
        "/api/v1/graph?format=json",
        content=b"\xff\xfe\x00\x01\x80\x90",
        headers={"Content-Type": "application/json", **admin_headers},
    )
    assert resp_bin.status_code == 422
    assert resp_bin.json()["error"]["code"] == "E_UNREADABLE"


# ── BP-17: Deterministic path IDs across shuffles ─────────────────────────────

@pytest.mark.req("BP-17")
def test_T_BP_17_deterministic_path_ids_across_shuffles(seed_graph):
    """Shuffling node and edge order yields identical path IDs."""
    import random
    r_base = find_routes(seed_graph, max_depth=4)
    pids_base = {r["path_id"] for r in r_base.routes}

    shuffled = copy.deepcopy(seed_graph)
    rng = random.Random(42)
    rng.shuffle(shuffled["nodes"])
    rng.shuffle(shuffled["edges"])

    r_shuffled = find_routes(shuffled, max_depth=4)
    pids_shuffled = {r["path_id"] for r in r_shuffled.routes}

    assert pids_base == pids_shuffled


# ── BP-18: Edge traversal direction & policy ──────────────────────────────────

@pytest.mark.req("BP-18")
def test_T_BP_18_edge_traversal_direction_and_policy(seed_graph):
    """ingests_from traverses in reverse; disabling can_invoke removes routes that use it."""
    r_all = find_routes(seed_graph, max_depth=4)
    assert len(r_all.routes) == 7

    # Disable can_invoke
    r_no_invoke = find_routes(seed_graph, max_depth=4, edge_traversal_policy={"can_invoke": False})
    pids_no_invoke = {r["path_id"] for r in r_no_invoke.routes}

    # Routes that use can_invoke: p_460263f0bbf3, p_f2b0d9ef9b38, p_0752c1232b17, p_f99cb064dd75
    assert "p_460263f0bbf3" not in pids_no_invoke
    assert "p_0752c1232b17" not in pids_no_invoke
    # Routes that do not use can_invoke: p_3f50b1ef2c19, p_65cc13b03940, p_54422463a590
    assert "p_3f50b1ef2c19" in pids_no_invoke
    assert "p_65cc13b03940" in pids_no_invoke
    assert "p_54422463a590" in pids_no_invoke
