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

import threading
import time
from collections.abc import Callable
from typing import Any, cast

from backend.app.config import settings
from backend.app.core.providers.base import (
    AgentTurnResult,
    ClassifyResult,
    ConnectionTestResult,
    IntentResult,
    LLMProvider,
    ToolCall,
)
from backend.app.core.providers.mock_provider import MockProvider
from backend.app.core.providers.openai_provider import OpenAIProvider
from backend.app.core.providers.scripted_agent import ScriptedAgent

# ── Output schemas (data-models.md §7) ───────────────────────────────────────

_CLASSIFY_SCHEMA = {
    "type": "object",
    "required": ["label", "threat_types", "confidence"],
    "additionalProperties": False,
    "properties": {
        "label": {"enum": ["benign", "suspicious", "malicious"]},
        "threat_types": {
            "type": "array",
            "items": {
                "enum": [
                    "override",
                    "extraction",
                    "exfil_target",
                    "protected_value",
                    "hidden_content",
                    "directive",
                ]
            },
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
            "items": {
                "enum": [
                    "external_recipient",
                    "bulk_data",
                    "irreversible",
                    "sensitive_resource",
                    "taint_context",
                    "unusual_target",
                ]
            },
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
    Unified LLM adapter implementing LA-01..LA-10.
    Delegates to the active LLMProvider while managing the circuit breaker,
    hard timeout, schema validation, and fallback ledgering.
    """

    def __init__(self, provider: LLMProvider | None = None) -> None:
        self._mock_provider = MockProvider(mode="ok")
        self._provider: LLMProvider = provider or self._mock_provider
        self._mode = "ok"
        self._breaker = CircuitBreaker()
        self._lock = threading.Lock()

    # ── Provider & mode management (LA-05, LA-07) ──────────────────────────────

    def get_provider(self) -> LLMProvider:
        with self._lock:
            return self._provider

    def set_provider(self, provider: LLMProvider) -> None:
        with self._lock:
            self._provider = provider
        self._breaker.reset()

    def get_mode(self) -> str:
        with self._lock:
            if isinstance(self._provider, MockProvider):
                return self._provider.mode
            return self._mode

    def set_mode(self, mode: str) -> None:
        if mode not in _VALID_MODES:
            raise ValueError(f"Unknown LLM mode: {mode!r}. Valid: {_VALID_MODES}")
        with self._lock:
            self._mode = mode
            self._mock_provider.set_mode(mode)
            self._provider = self._mock_provider
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

        timeout = getattr(settings, "llm_timeout_seconds", _LLM_TIMEOUT_S)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(fn, *args)
            try:
                return future.result(timeout=timeout)
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

    def classify_input(
        self,
        text: str,
        tier: str,
        module: str = "promptshield",
        request_id: str = "",
    ) -> ClassifyResult | None:
        """LA-01, LA-08: Classify ingress text. Returns None if LLM unavailable."""
        if not self._breaker.allow_call():
            self._emit_fallback("breaker_open", module, request_id)
            return None

        with self._lock:
            provider = self._provider

        def _do_call() -> Any:
            return provider.classify_input(text, tier, module=module, request_id=request_id)

        result = self._call_with_timeout(_do_call)

        if isinstance(result, str) and result == "TIMEOUT":
            self._breaker.record_failure()
            self._emit_fallback("timeout", module, request_id)
            return None
        if isinstance(result, Exception):
            self._breaker.record_failure()
            self._emit_fallback("exception", module, request_id)
            return None
        if result is None:
            self._breaker.record_failure()
            self._emit_fallback("invalid_json", module, request_id)
            return None

        # Schema validation
        data = {
            "label": result.label,
            "threat_types": result.threat_types,
            "confidence": result.confidence,
            "rationale": result.rationale,
        }
        if not _validate(data, _CLASSIFY_SCHEMA):
            self._breaker.record_failure()
            self._emit_fallback("schema_violation", module, request_id)
            return None

        self._breaker.record_success()
        return cast(ClassifyResult, result)

    def summarize_intent(
        self,
        action: dict[str, Any],
        module: str = "actiongate",
        request_id: str = "",
    ) -> IntentResult | None:
        """LA-01, LA-08: Summarize action intent. Returns None if LLM unavailable."""
        if not self._breaker.allow_call():
            self._emit_fallback("breaker_open", module, request_id)
            return None

        with self._lock:
            provider = self._provider

        def _do_call() -> Any:
            return provider.summarize_intent(action, module=module, request_id=request_id)

        result = self._call_with_timeout(_do_call)

        if isinstance(result, str) and result == "TIMEOUT":
            self._breaker.record_failure()
            self._emit_fallback("timeout", module, request_id)
            return None
        if isinstance(result, Exception):
            self._breaker.record_failure()
            self._emit_fallback("exception", module, request_id)
            return None
        if result is None:
            self._breaker.record_failure()
            self._emit_fallback("invalid_json", module, request_id)
            return None

        data = {
            "summary": result.summary,
            "risk_flags": result.risk_flags,
            "suggested_outcome": result.suggested_outcome,
        }
        if not _validate(data, _INTENT_SCHEMA):
            self._breaker.record_failure()
            self._emit_fallback("schema_violation", module, request_id)
            return None

        self._breaker.record_success()
        return cast(IntentResult, result)

    def generate_turn(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentTurnResult:
        with self._lock:
            provider = self._provider
        return provider.generate_turn(messages, tools)

    def test_connection(self) -> ConnectionTestResult:
        with self._lock:
            provider = self._provider
        return provider.test_connection()


# ── Module-level singleton ─────────────────────────────────────────────────────

_adapter = MockLLMAdapter()


def get_adapter() -> MockLLMAdapter:
    """Return the shared LLM adapter instance."""
    return _adapter


def get_mode() -> str:
    return _adapter.get_mode()


def set_mode(mode: str) -> None:
    _adapter.set_mode(mode)


def get_provider() -> LLMProvider:
    return _adapter.get_provider()


def set_provider(provider: LLMProvider) -> None:
    _adapter.set_provider(provider)


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


def generate_turn(messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None) -> AgentTurnResult:
    return _adapter.generate_turn(messages, tools)


def test_connection() -> ConnectionTestResult:
    return _adapter.test_connection()


__all__ = [
    "AgentTurnResult",
    "CircuitBreaker",
    "ClassifyResult",
    "ConnectionTestResult",
    "IntentResult",
    "LLMProvider",
    "MockLLMAdapter",
    "MockProvider",
    "OpenAIProvider",
    "ScriptedAgent",
    "ToolCall",
    "classify_input",
    "generate_turn",
    "get_adapter",
    "get_mode",
    "get_mode_status",
    "get_provider",
    "set_mode",
    "set_provider",
    "summarize_intent",
    "test_connection",
]
