"""
Mock LLM adapter (LA-01..LA-05).

Provides two interfaces:
    classify_input(text, tier) -> ClassifyResult | None    (PS ingress)
    summarize_intent(action)   -> IntentResult | None      (AG actions)

All modes are mock — no real network calls.
Mode is set globally (LA-05) via set_mode() / POST /api/v1/llm/mode.

Circuit breaker (LA-02):
    Opens after N consecutive failures (default 3).
    Stays open for cooldown_s seconds (default 30).
    Half-open: one probe. Success → closed. Fail → open again.

Mock modes (LA-03):
    ok              — answers from fixtures file keyed by SHA-256(input);
                      falls back to keyword heuristic (D-29)
    says_safe_always — returns benign/allow with confidence 99
    timeout         — sleeps past timeout, returns None
    garbage         — returns non-JSON, returns None
    down            — raises exception, returns None

Output validation (LA-01): both functions validate against JSON Schema;
an invalid response returns None (treated as LLM unavailable).

Monotonic tightening (LA-04): the caller is responsible for the tightening
logic (policy.py tighten_to). This module never tightens; it only returns signals.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Callable
from typing import Any

from backend.app.core.canonical import canonical_json

# ── Output schemas (data-models.md §7) ───────────────────────────────────────

_CLASSIFY_SCHEMA = {
    "type": "object",
    "required": ["label", "threat_types", "confidence"],
    "additionalProperties": False,
    "properties": {
        "label": {"enum": ["benign", "suspicious", "malicious"]},
        "threat_types": {
            "type": "array",
            "items": {"enum": ["override", "extraction", "exfil_target",
                               "protected_value", "hidden_content", "directive"]},
        },
        "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
        "rationale": {"type": "string", "maxLength": 200},
    },
}

_INTENT_SCHEMA = {
    "type": "object",
    "required": ["summary", "risk_flags", "suggested_outcome"],
    "additionalProperties": False,
    "properties": {
        "summary": {"type": "string", "maxLength": 300},
        "risk_flags": {
            "type": "array",
            "items": {"enum": ["external_recipient", "bulk_data", "irreversible",
                               "sensitive_resource", "taint_context", "unusual_target"]},
        },
        "suggested_outcome": {"enum": ["allow", "hold", "block"]},
    },
}


def _validate(data: Any, schema: dict[str, Any]) -> bool:
    """Simple JSON Schema validation (subset used by these schemas)."""
    try:
        import jsonschema
        jsonschema.validate(data, schema)
        return True
    except Exception:
        return False


# ── Types ─────────────────────────────────────────────────────────────────────

class ClassifyResult:
    def __init__(self, label: str, threat_types: list[str], confidence: int, rationale: str = "") -> None:
        self.label = label
        self.threat_types = threat_types
        self.confidence = confidence
        self.confidence_pct = confidence
        self.rationale = rationale
        self.reason = rationale


class IntentResult:
    def __init__(self, summary: str, risk_flags: list[str], suggested_outcome: str) -> None:
        self.summary = summary
        self.risk_flags = risk_flags
        self.suggested_outcome = suggested_outcome


# ── Fixtures loader ───────────────────────────────────────────────────────────

_fixtures: dict[str, Any] | None = None
_fixtures_lock = threading.Lock()


def _load_fixtures() -> dict[str, Any]:
    global _fixtures
    with _fixtures_lock:
        if _fixtures is not None:
            return _fixtures
        try:
            from pathlib import Path
            # Try seed/llm_fixtures.json
            fixture_path = Path("seed/llm_fixtures.json")
            _fixtures = json.loads(fixture_path.read_text("utf-8")) if fixture_path.exists() else {}
        except Exception:
            _fixtures = {}
        return _fixtures


def _fixture_key_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _fixture_key_action(action: dict[str, Any]) -> str:
    """seed-data.md §7: key for summarize_intent is SHA-256(canonical_json({action_type, arguments}))."""
    payload = {"action_type": action.get("action_type", ""), "arguments": action.get("arguments", {})}
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


# ── Keyword heuristic (D-29) ──────────────────────────────────────────────────

_TIGHTEN_KEYWORDS = ["extract internal notes", "set aside the initial", "paraphrase"]

_SUSPICIOUS_KEYWORDS = [
    "ignore previous instructions", "ignore all previous", "disregard your",
    "you are now", "new persona", "admin mode", "system prompt",
    "forward the customer list", "email the customer list",
    "attacker@", "evil.example",
]


def _heuristic_classify(text: str) -> ClassifyResult:
    t = text.lower()
    for kw in _TIGHTEN_KEYWORDS:
        if kw in t:
            return ClassifyResult("malicious", ["override"], 85, f"subtle paraphrase: {kw}")
    for kw in _SUSPICIOUS_KEYWORDS:
        if kw in t:
            return ClassifyResult("suspicious", ["override"], 60, f"keyword heuristic: {kw}")
    return ClassifyResult("benign", [], 10, "keyword heuristic")


def _heuristic_intent(action: dict[str, Any]) -> IntentResult:
    args_str = json.dumps(action.get("arguments", {})).lower()
    flags: list[str] = []
    if "evil.example" in args_str or "attacker@" in args_str:
        flags.append("external_recipient")
    if "customer_list" in args_str or "customer list" in args_str:
        flags.append("bulk_data")
    outcome = "hold" if flags else "allow"
    return IntentResult(
        summary=f"Action: {action.get('action_type', 'unknown')}",
        risk_flags=flags,
        suggested_outcome=outcome,
    )


# ── Circuit breaker ───────────────────────────────────────────────────────────

class CircuitBreaker:
    """LA-02: Opens after N failures; half-open after cooldown."""

    def __init__(self, max_failures: int = 3, cooldown_s: float = 30.0) -> None:
        self.max_failures = max_failures
        self.cooldown_s = cooldown_s
        self._failures = 0
        self._state = "closed"  # closed | open | half_open
        self._opened_at: float = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def consecutive_failures(self) -> int:
        with self._lock:
            return self._failures

    def allow_call(self) -> bool:
        """Return True if a call should be attempted."""
        with self._lock:
            if self._state == "closed":
                return True
            if self._state == "open":
                if time.monotonic() - self._opened_at >= self.cooldown_s:
                    self._state = "half_open"
                    return True  # probe
                return False
            # half_open: allow one probe
            return True

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._state = "closed"

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._state in ("closed", "half_open") and self._failures >= self.max_failures:
                self._state = "open"
                self._opened_at = time.monotonic()

    def reset(self) -> None:
        with self._lock:
            self._failures = 0
            self._state = "closed"
            self._opened_at = 0.0


# ── Adapter ───────────────────────────────────────────────────────────────────

_LLM_TIMEOUT_S = 3.0  # LA-02 hard timeout

_VALID_MODES = {"ok", "says_safe_always", "timeout", "garbage", "down"}


class MockLLMAdapter:
    """
    Mock LLM adapter implementing LA-01..LA-05.
    """

    def __init__(self) -> None:
        self._mode = "ok"
        self._breaker = CircuitBreaker()
        self._lock = threading.Lock()

    # ── Mode management (LA-05) ───────────────────────────────────────────────

    def get_mode(self) -> str:
        with self._lock:
            return self._mode

    def set_mode(self, mode: str) -> None:
        if mode not in _VALID_MODES:
            raise ValueError(f"Unknown LLM mode: {mode!r}. Valid: {_VALID_MODES}")
        with self._lock:
            self._mode = mode
        # Reset breaker when mode changes
        self._breaker.reset()

    @property
    def breaker_state(self) -> str:
        return self._breaker.state

    @property
    def consecutive_failures(self) -> int:
        return self._breaker.consecutive_failures

    # ── Internal call machinery ───────────────────────────────────────────────

    def _call_with_timeout(self, fn: Callable[..., Any], *args: Any) -> Any:
        """Run fn(*args) with a hard timeout. Returns result or None."""
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(fn, *args)
            try:
                return future.result(timeout=_LLM_TIMEOUT_S)
            except concurrent.futures.TimeoutError:
                return "TIMEOUT"
            except Exception as exc:
                return exc

    def _emit_fallback(self, reason: str, module: str, request_id: str = "") -> None:
        """Write an llm.fallback ledger entry (LA-02)."""
        try:
            from backend.app.core import ledger
            from backend.app.core.policy import get_engine
            engine = get_engine()
            try:
                pv = engine.active_version()
            except Exception:
                pv = 0
            ledger.append(
                module=module,
                event_type="llm.fallback",
                subject="llm",
                outcome="info",
                reason=f"LLM fallback: {reason}",
                rule_ids=[],
                decision_path="fallback",
                policy_version=pv,
                payload={
                    "component": module,
                    "mode": self.get_mode(),
                    "reason": reason,
                    "consecutive_failures": self._breaker.consecutive_failures,
                    "request_id": request_id,
                },
            )
        except Exception:
            pass  # ledger failure must not crash the fallback path

    def _simulate_call(self, raw_result: Any) -> Any | None:
        """Apply mode simulation to a raw result and return data or None."""
        mode = self.get_mode()

        if not self._breaker.allow_call():
            self._emit_fallback("breaker_open", "policy")
            return None

        if mode == "timeout":
            time.sleep(_LLM_TIMEOUT_S + 1)
            return None

        if mode == "garbage":
            return "not-valid-json-!@#"

        if mode == "down":
            raise RuntimeError("LLM is down")

        return raw_result

    def classify_input(
        self,
        text: str,
        tier: str,
        module: str = "promptshield",
        request_id: str = "",
    ) -> ClassifyResult | None:
        """LA-01: Classify ingress text. Returns None if LLM unavailable."""
        mode = self.get_mode()

        if not self._breaker.allow_call():
            self._emit_fallback("breaker_open", module, request_id)
            return None

        def _do_call() -> Any:
            if mode == "timeout":
                time.sleep(_LLM_TIMEOUT_S + 1)
                return None
            if mode == "garbage":
                return "not-json"
            if mode == "down":
                raise RuntimeError("down")
            if mode == "says_safe_always":
                return {"label": "benign", "threat_types": [], "confidence": 99, "rationale": "safe always"}
            # mode == "ok": fixtures then heuristic
            fixtures = _load_fixtures()
            key = _fixture_key_text(text)
            if key in fixtures:
                return fixtures[key]
            result = _heuristic_classify(text)
            return {"label": result.label, "threat_types": result.threat_types,
                    "confidence": result.confidence, "rationale": result.rationale}

        result = self._call_with_timeout(_do_call)

        if isinstance(result, str) and result == "TIMEOUT":
            self._breaker.record_failure()
            self._emit_fallback("timeout", module, request_id)
            return None
        if isinstance(result, Exception):
            self._breaker.record_failure()
            self._emit_fallback("exception", module, request_id)
            return None
        if isinstance(result, str):
            # garbage
            try:
                data = json.loads(result)
            except Exception:
                self._breaker.record_failure()
                self._emit_fallback("invalid_json", module, request_id)
                return None
        else:
            data = result

        if not _validate(data, _CLASSIFY_SCHEMA):
            self._breaker.record_failure()
            self._emit_fallback("schema_violation", module, request_id)
            return None

        self._breaker.record_success()
        return ClassifyResult(
            label=data["label"],
            threat_types=data.get("threat_types", []),
            confidence=data["confidence"],
            rationale=data.get("rationale", ""),
        )

    def summarize_intent(
        self,
        action: dict[str, Any],
        module: str = "actiongate",
        request_id: str = "",
    ) -> IntentResult | None:
        """LA-01: Summarize action intent. Returns None if LLM unavailable."""
        mode = self.get_mode()

        if not self._breaker.allow_call():
            self._emit_fallback("breaker_open", module, request_id)
            return None

        def _do_call() -> Any:
            if mode == "timeout":
                time.sleep(_LLM_TIMEOUT_S + 1)
                return None
            if mode == "garbage":
                return "not-json"
            if mode == "down":
                raise RuntimeError("down")
            if mode == "says_safe_always":
                return {"summary": "looks safe", "risk_flags": [], "suggested_outcome": "allow"}
            # mode == "ok"
            fixtures = _load_fixtures()
            key = _fixture_key_action(action)
            if key in fixtures:
                return fixtures[key]
            result = _heuristic_intent(action)
            return {"summary": result.summary, "risk_flags": result.risk_flags,
                    "suggested_outcome": result.suggested_outcome}

        result = self._call_with_timeout(_do_call)

        if isinstance(result, str) and result == "TIMEOUT":
            self._breaker.record_failure()
            self._emit_fallback("timeout", module, request_id)
            return None
        if isinstance(result, Exception):
            self._breaker.record_failure()
            self._emit_fallback("exception", module, request_id)
            return None
        if isinstance(result, str):
            try:
                data = json.loads(result)
            except Exception:
                self._breaker.record_failure()
                self._emit_fallback("invalid_json", module, request_id)
                return None
        else:
            data = result

        if not _validate(data, _INTENT_SCHEMA):
            self._breaker.record_failure()
            self._emit_fallback("schema_violation", module, request_id)
            return None

        self._breaker.record_success()
        return IntentResult(
            summary=data["summary"],
            risk_flags=data.get("risk_flags", []),
            suggested_outcome=data["suggested_outcome"],
        )


# ── Module-level singleton ─────────────────────────────────────────────────────

_adapter = MockLLMAdapter()


def get_adapter() -> MockLLMAdapter:
    """Return the shared LLM adapter instance."""
    return _adapter


def get_mode() -> str:
    return _adapter.get_mode()


def set_mode(mode: str) -> None:
    _adapter.set_mode(mode)


def get_mode_status() -> dict[str, Any]:
    return {
        "mode": _adapter.get_mode(),
        "breaker": _adapter.breaker_state,
        "consecutive_failures": _adapter.consecutive_failures,
    }


def classify_input(text: str, tier: str, module: str = "promptshield", request_id: str = "") -> ClassifyResult | None:
    return _adapter.classify_input(text, tier, module=module, request_id=request_id)


def summarize_intent(action: dict[str, Any], module: str = "actiongate", request_id: str = "") -> IntentResult | None:
    return _adapter.summarize_intent(action, module=module, request_id=request_id)
