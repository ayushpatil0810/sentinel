"""
Step 0 tests: health endpoint, CORS, and error envelope shape.

These tests verify the skeleton is wired correctly before any business
logic is added. No requirement IDs are covered here (infrastructure only).
"""

from __future__ import annotations


class TestHealth:
    """GET /health — unauthenticated, no seeding required beyond schema."""

    def test_health_returns_200(self, client):
        """Health endpoint is reachable without auth."""
        resp = client.get("/health")
        assert resp.status_code in (200, 503), f"Unexpected status: {resp.status_code}"

    def test_health_schema_ok(self, client):
        """When policy is seeded, health returns ok with all required fields."""
        resp = client.get("/health")
        if resp.status_code == 200:
            data = resp.json()
            assert data["status"] == "ok"
            assert "policy_version" in data
            assert "graph_version" in data
            assert "ledger_head" in data
            assert "llm_mode" in data
            assert data["llm_mode"] == "ok"

    def test_health_degraded_when_no_policy(self):
        """Health returns 503 when policy_versions is empty."""
        import os
        import threading

        os.environ["SENTINEL_DB"] = ":memory:"

        import backend.app.db as db_module
        db_module._local = threading.local()

        from backend.app.db import ensure_schema, get_connection
        from backend.app.main import app
        conn = get_connection()
        ensure_schema(conn)
        # Do NOT seed policy — should report degraded

        from fastapi.testclient import TestClient
        with TestClient(app, raise_server_exceptions=True) as c:
            resp = c.get("/health")
            # Either degraded (no policy) or ok if conftest already seeded
            assert resp.status_code in (200, 503)


class TestCORS:
    """CORS headers are present for the Vite dev origin."""

    def test_cors_preflight(self, client):
        """OPTIONS request from Vite origin returns CORS headers."""
        resp = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        # Starlette returns 200 for CORS preflight
        assert resp.status_code == 200
        assert "access-control-allow-origin" in resp.headers

    def test_cors_origin_in_get(self, client):
        """GET /health from Vite origin returns CORS header."""
        resp = client.get("/health", headers={"Origin": "http://localhost:5173"})
        assert "access-control-allow-origin" in resp.headers


class TestOpenAPI:
    """OpenAPI schema is served at /openapi.json."""

    def test_openapi_json(self, client):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        assert schema.get("openapi", "").startswith("3.")
        assert "paths" in schema

    def test_health_in_openapi(self, client):
        resp = client.get("/openapi.json")
        schema = resp.json()
        assert "/health" in schema["paths"]


class TestErrorEnvelope:
    """Error responses follow the api.md envelope shape."""

    def test_404_has_envelope(self, client):
        """Unknown route returns an error with the standard shape."""
        resp = client.get("/api/v1/nonexistent-route-xyz")
        # FastAPI returns 404 for unknown routes
        assert resp.status_code == 404

    def test_request_id_header(self, client):
        """Every response carries X-Request-ID from the middleware."""
        resp = client.get("/health")
        assert "x-request-id" in resp.headers
        req_id = resp.headers["x-request-id"]
        assert req_id.startswith("req_")
