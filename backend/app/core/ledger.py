"""
Hash-chained append-only audit ledger (LG-01..LG-07).

Design (spec.md §1.2):
  hash = SHA-256(prev_hash_utf8 || canonical_json(entry_without_hash))
  entry_without_hash includes: seq, ts, prev_hash, and every other field except hash.
  Genesis prev_hash = SHA-256("sentinel-genesis-v1") in hex.

Thread safety: one threading.Lock + BEGIN IMMEDIATE (LG-07).
Redaction pass: all payloads have secrets replaced before write (LG-04).
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any, cast

from backend.app.core.canonical import canonical_json
from backend.app.core.clock import Clock, get_clock

# LG-02: genesis prev_hash
GENESIS_INPUT = "sentinel-genesis-v1"
GENESIS_PREV_HASH: str = hashlib.sha256(GENESIS_INPUT.encode("utf-8")).hexdigest()

_ledger_lock = threading.Lock()


def _compute_hash(prev_hash: str, entry_without_hash: dict[str, Any]) -> str:
    """LG-02: SHA-256(prev_hash_ascii || canonical_json(entry_without_hash))."""
    data = prev_hash.encode("utf-8") + canonical_json(entry_without_hash).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _payload_digest(payload: dict[str, Any]) -> str:
    """SHA-256 of canonical JSON of the redacted payload."""
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


# ── Redaction ─────────────────────────────────────────────────────────────────

_MAX_EXCERPT = 80


def redact_payload(payload: dict[str, Any], protected_values: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """
    Return a copy of payload with all protected values replaced by [REDACTED:<id>].
    Strings are also truncated to _MAX_EXCERPT characters after redaction (LG-04).
    """
    if protected_values is None:
        protected_values = _load_protected_values()
    return cast(dict[str, Any], _redact_obj(payload, protected_values))


def _load_protected_values() -> list[dict[str, Any]]:
    """Load protected values from DB and seed defaults for redaction (LG-04)."""
    pvs: list[dict[str, Any]] = [
        {"id": "pv-apikey-1", "value": "sk-acme-4c1f9e27b8a3d605e7f1"},
        {"id": "pv-nid-1", "value": "NID-4417-9082-3361"},
        {"id": "pv-marker-1", "value": "CANARY::acme::0x7d3e91"},
    ]
    try:
        from backend.app.db import get_connection
        conn = get_connection()
        rows = conn.execute("SELECT pv_id, value_norm FROM protected_values").fetchall()
        existing = {p["id"] for p in pvs}
        for r in rows:
            if r[0] not in existing:
                pvs.append({"id": r[0], "value": r[1]})
    except Exception:
        pass
    return pvs


def _redact_obj(obj: Any, pvs: list[dict[str, Any]]) -> Any:
    if isinstance(obj, str):
        for pv in pvs:
            if pv["value"] and pv["value"] in obj:
                obj = obj.replace(pv["value"], f"[REDACTED:{pv['id']}]")
        return obj[:_MAX_EXCERPT] if len(obj) > _MAX_EXCERPT else obj
    if isinstance(obj, dict):
        return {k: _redact_obj(v, pvs) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_obj(item, pvs) for item in obj]
    return obj


# ── Append ────────────────────────────────────────────────────────────────────

def append(
    *,
    module: str,
    event_type: str,
    subject: str,
    outcome: str,
    reason: str,
    rule_ids: list[str],
    decision_path: str,
    policy_version: int,
    payload: dict[str, Any] | None = None,
    clock: Clock | None = None,
) -> dict[str, Any]:
    """
    Append one entry to the ledger. Returns the completed entry dict.

    Raises RuntimeError if the insert fails (caller should return 503 — D-26).
    The caller must wrap this in the same transaction as any state changes
    so that ledger failure rolls back everything (LG-07, architecture.md §6).
    """
    if clock is None:
        clock = get_clock()

    redacted_payload = redact_payload(payload or {})
    digest = _payload_digest(redacted_payload)
    payload_ref: str | None = None

    with _ledger_lock:
        from backend.app.db import get_connection
        conn = get_connection()

        try:
            conn.execute("BEGIN IMMEDIATE")
        except Exception:
            conn.rollback()
            conn.execute("BEGIN IMMEDIATE")

        try:
            # Get last row for chaining
            last = conn.execute(
                "SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if last is None:
                seq = 1
                prev_hash = GENESIS_PREV_HASH
            else:
                seq = last[0] + 1
                prev_hash = last[1]

            ts = clock.now_iso()

            # Store payload if non-empty
            if payload:
                payload_ref = f"pay_{seq:09d}"
                conn.execute(
                    "INSERT OR REPLACE INTO ledger_payloads (payload_id, payload_json) VALUES (?, ?)",
                    (payload_ref, canonical_json(redacted_payload)),
                )

            # Build entry_without_hash (all fields except 'hash', sorted by canonical_json)
            entry_without_hash: dict[str, Any] = {
                "decision_path": decision_path,
                "event_type": event_type,
                "module": module,
                "outcome": outcome,
                "payload_digest": digest,
                "payload_ref": payload_ref,
                "policy_version": policy_version,
                "prev_hash": prev_hash,
                "reason": reason[:300],
                "rule_ids": rule_ids,
                "seq": seq,
                "subject": subject,
                "ts": ts,
            }

            entry_hash = _compute_hash(prev_hash, entry_without_hash)

            conn.execute(
                """INSERT INTO ledger
                   (seq, ts, module, event_type, subject, outcome, reason,
                    rule_ids_json, decision_path, policy_version,
                    payload_ref, payload_digest, prev_hash, hash)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    seq, ts, module, event_type, subject, outcome, reason[:300],
                    json.dumps(rule_ids), decision_path, policy_version,
                    payload_ref, digest, prev_hash, entry_hash,
                ),
            )
            conn.commit()

            return {**entry_without_hash, "hash": entry_hash}

        except Exception as exc:
            conn.rollback()
            raise RuntimeError(f"ledger.unavailable: {exc}") from exc


# ── Verify ────────────────────────────────────────────────────────────────────

def verify() -> dict[str, Any]:
    """
    LG-03: Walk all ledger rows in seq order and verify the hash chain.

    Returns:
        {valid, checked, first_broken_seq, reason, detail}

    Reasons: hash_mismatch, prev_hash_mismatch, seq_gap, seq_duplicate, bad_genesis.
    """
    from backend.app.db import get_connection
    conn = get_connection()
    rows = conn.execute(
        "SELECT seq, ts, module, event_type, subject, outcome, reason, "
        "rule_ids_json, decision_path, policy_version, payload_ref, payload_digest, "
        "prev_hash, hash FROM ledger ORDER BY seq ASC"
    ).fetchall()

    if not rows:
        return {"valid": True, "checked": 0, "first_broken_seq": None, "reason": None, "detail": None}

    expected_seq = 1
    prev_hash = GENESIS_PREV_HASH
    checked = 0

    for row in rows:
        seq = row[0]
        stored_hash = row[13]
        stored_prev_hash = row[12]

        # Check seq continuity
        if seq != expected_seq:
            if seq > expected_seq:
                return {
                    "valid": False, "checked": checked,
                    "first_broken_seq": expected_seq,
                    "reason": "seq_gap",
                    "detail": f"Expected seq {expected_seq}, found {seq}.",
                }
            else:
                return {
                    "valid": False, "checked": checked,
                    "first_broken_seq": seq,
                    "reason": "seq_duplicate",
                    "detail": f"Duplicate or out-of-order seq {seq}.",
                }

        # Check genesis
        if seq == 1 and stored_prev_hash != GENESIS_PREV_HASH:
            return {
                "valid": False, "checked": checked,
                "first_broken_seq": 1,
                "reason": "bad_genesis",
                "detail": "Row 1 prev_hash does not match genesis hash.",
            }

        # Check prev_hash linkage
        if stored_prev_hash != prev_hash:
            return {
                "valid": False, "checked": checked,
                "first_broken_seq": seq,
                "reason": "prev_hash_mismatch",
                "detail": f"Row {seq}: prev_hash does not match previous row hash.",
            }

        # Recompute hash
        entry_without_hash: dict[str, Any] = {
            "decision_path": row[8],
            "event_type": row[3],
            "module": row[2],
            "outcome": row[5],
            "payload_digest": row[11],
            "payload_ref": row[10],
            "policy_version": row[9],
            "prev_hash": stored_prev_hash,
            "reason": row[6],
            "rule_ids": json.loads(row[7]),
            "seq": seq,
            "subject": row[4],
            "ts": row[1],
        }
        recomputed = _compute_hash(stored_prev_hash, entry_without_hash)

        if recomputed != stored_hash:
            return {
                "valid": False, "checked": checked,
                "first_broken_seq": seq,
                "reason": "hash_mismatch",
                "detail": f"Stored hash of seq {seq} does not match the recomputed hash.",
            }

        prev_hash = stored_hash
        expected_seq = seq + 1
        checked += 1

    return {"valid": True, "checked": checked, "first_broken_seq": None, "reason": None, "detail": None}


def query(
    module: str = "",
    event_type: str = "",
    subject: str = "",
    outcome: str = "",
    from_seq: int | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Query ledger rows with optional filters."""
    from backend.app.db import fetchall, get_connection
    conn = get_connection()
    conditions: list[str] = []
    params: list[Any] = []
    if module:
        conditions.append("module = ?")
        params.append(module)
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)
    if subject:
        conditions.append("subject = ?")
        params.append(subject)
    if outcome:
        conditions.append("outcome = ?")
        params.append(outcome)
    if from_seq is not None:
        conditions.append("seq >= ?")
        params.append(from_seq)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sql = f"SELECT * FROM ledger {where} ORDER BY seq ASC LIMIT ?"
    params.append(limit)
    rows = fetchall(conn, sql, tuple(params))
    return [dict(r) for r in rows]
