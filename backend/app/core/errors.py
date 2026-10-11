"""
Structured error helpers for Sentinel.

Error envelope shape (api.md §0):
    {"error": {"code": str, "message": str, "details": dict | None, "request_id": str}}

All HTTP errors that Sentinel raises deliberately use SentinelError.
Unexpected exceptions are caught in the global exception handler in main.py.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse


class SentinelError(Exception):
    """
    Base class for all Sentinel HTTP errors.

    Args:
        status_code: HTTP status code to return.
        code: Machine-readable error code, e.g. "approval.self_approval".
        message: Human-readable explanation.
        details: Optional dict with extra context shown to the client.
    """

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or {}

    def to_response(self, request_id: str = "") -> JSONResponse:
        body: dict[str, Any] = {
            "error": {
                "code": self.code,
                "message": self.message,
                "details": self.details,
                "request_id": request_id,
            }
        }
        return JSONResponse(status_code=self.status_code, content=body)


# ── convenience subclasses ────────────────────────────────────────────────────

class NotFound(SentinelError):
    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(404, code, message, details)


class Forbidden(SentinelError):
    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(403, code, message, details)


class Unauthorized(SentinelError):
    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(401, code, message, details)


class Conflict(SentinelError):
    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(409, code, message, details)


class UnprocessableEntity(SentinelError):
    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(422, code, message, details)


class TooLarge(SentinelError):
    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(413, code, message, details)


class ServiceUnavailable(SentinelError):
    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(503, code, message, details)


# ── FastAPI exception handler ─────────────────────────────────────────────────

def make_request_id(request: Request) -> str:
    """Return the request_id from state (set by middleware) or empty string."""
    return getattr(request.state, "request_id", "")


async def sentinel_error_handler(request: Request, exc: SentinelError) -> JSONResponse:
    return exc.to_response(make_request_id(request))
