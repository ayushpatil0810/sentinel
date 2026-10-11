"""
Base interfaces and data structures for LLM providers (LA-01, LA-06).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ClassifyResult:
    """Ingress screening classification result from Guard LLM."""

    def __init__(
        self,
        label: str,
        threat_types: list[str],
        confidence: int,
        rationale: str = "",
    ) -> None:
        self.label = label
        self.threat_types = threat_types
        self.confidence = confidence
        self.confidence_pct = confidence
        self.rationale = rationale
        self.reason = rationale

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "threat_types": self.threat_types,
            "confidence": self.confidence,
            "rationale": self.rationale,
        }


class IntentResult:
    """Action intent summarization result from Guard LLM."""

    def __init__(
        self,
        summary: str,
        risk_flags: list[str],
        suggested_outcome: str,
    ) -> None:
        self.summary = summary
        self.risk_flags = risk_flags
        self.suggested_outcome = suggested_outcome

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "risk_flags": self.risk_flags,
            "suggested_outcome": self.suggested_outcome,
        }


class ToolCall:
    """Function / tool call emitted by an LLM turn."""

    def __init__(
        self,
        id: str,
        name: str,
        arguments: dict[str, Any],
    ) -> None:
        self.id = id
        self.name = name
        self.arguments = arguments

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "arguments": self.arguments,
        }


class AgentTurnResult:
    """Outcome of an agent model turn."""

    def __init__(
        self,
        role: str = "assistant",
        content: str | None = None,
        tool_calls: list[ToolCall] | None = None,
        finish_reason: str = "stop",
        agent_source: str = "live",
    ) -> None:
        self.role = role
        self.content = content
        self.tool_calls = tool_calls or []
        self.finish_reason = finish_reason
        self.agent_source = agent_source

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0


class ConnectionTestResult:
    """Diagnostic round-trip connection test result."""

    def __init__(
        self,
        success: bool,
        latency_ms: int,
        model: str,
        error: str | None = None,
    ) -> None:
        self.success = success
        self.latency_ms = latency_ms
        self.model = model
        self.error = error

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "latency_ms": self.latency_ms,
            "model": self.model,
            "error": self.error,
        }


class LLMProvider(ABC):
    """Abstract base class for all LLM providers (OpenAI, Mock, Scripted)."""

    @abstractmethod
    def classify_input(
        self,
        text: str,
        tier: str,
        module: str = "promptshield",
        request_id: str = "",
    ) -> ClassifyResult | None:
        """Advisory classification of untrusted input text."""
        ...

    @abstractmethod
    def summarize_intent(
        self,
        action: dict[str, Any],
        module: str = "actiongate",
        request_id: str = "",
    ) -> IntentResult | None:
        """Advisory summarization of proposed action intent."""
        ...

    @abstractmethod
    def generate_turn(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentTurnResult:
        """Generate next conversational turn or proposed tool calls."""
        ...

    @abstractmethod
    def test_connection(self) -> ConnectionTestResult:
        """Check provider connectivity and latency."""
        ...
