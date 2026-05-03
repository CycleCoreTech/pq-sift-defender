"""Unit tests for SGClient (mocked httpx)."""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from pq_sift_defender.clients.sg_client import (
    DEFAULT_BASE_URL,
    ScanResult,
    SGClient,
)


def _scan_payload(safe: bool = True, recommendation: str = "PASS") -> dict:
    return {
        "safe": safe,
        "risk_score": 0.0 if safe else 0.85,
        "flags": [
            {
                "gate": "injection_sql",
                "confidence": 0.85,
                "detected": not safe,
                "pattern": "OR 1=1" if not safe else None,
            }
        ],
        "latency_us": 42.3,
        "recommendation": recommendation,
    }


def test_scan_text_safe(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=f"{DEFAULT_BASE_URL}/v1/security/scan/text",
        method="POST",
        json=_scan_payload(safe=True),
    )
    with SGClient() as c:
        result = c.scan_text("hello")
    assert isinstance(result, ScanResult)
    assert result.safe is True
    assert result.recommendation == "PASS"
    assert result.flags[0].gate == "injection_sql"


def test_scan_text_blocked(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=f"{DEFAULT_BASE_URL}/v1/security/scan/text",
        method="POST",
        json=_scan_payload(safe=False, recommendation="BLOCK"),
    )
    with SGClient() as c:
        result = c.scan_text("SELECT * FROM users WHERE 1=1")
    assert result.safe is False
    assert result.recommendation == "BLOCK"
    assert result.flags[0].pattern == "OR 1=1"


def test_scan_with_filtered_gates(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=f"{DEFAULT_BASE_URL}/v1/security/scan",
        method="POST",
        json=_scan_payload(safe=True),
    )
    with SGClient() as c:
        result = c.scan(
            method="POST",
            path="/api/v1/test",
            body={"q": "hello"},
            gates=["injection_sql"],
        )
    assert result.safe is True


def test_gates_endpoint(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=f"{DEFAULT_BASE_URL}/v1/security/gates",
        method="GET",
        json={"gates": ["injection_sql", "injection_cmd"], "count": 2},
    )
    with SGClient() as c:
        gates = c.gates()
    assert gates == ["injection_sql", "injection_cmd"]


def test_health_endpoint(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=f"{DEFAULT_BASE_URL}/v1/security/health",
        method="GET",
        json={"status": "ok"},
    )
    with SGClient() as c:
        h = c.health()
    assert h["status"] == "ok"


def test_api_key_header_forwarded(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=f"{DEFAULT_BASE_URL}/v1/security/health",
        method="GET",
        json={"status": "ok"},
    )
    with SGClient(api_key="test-key") as c:
        c.health()
    request = httpx_mock.get_request()
    assert request is not None
    assert request.headers.get("x-api-key") == "test-key"


def test_user_agent_set(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=f"{DEFAULT_BASE_URL}/v1/security/health",
        method="GET",
        json={"status": "ok"},
    )
    with SGClient() as c:
        c.health()
    request = httpx_mock.get_request()
    assert request is not None
    assert "pq-sift-defender" in request.headers.get("user-agent", "")


def test_4xx_raises(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=f"{DEFAULT_BASE_URL}/v1/security/scan/text",
        method="POST",
        status_code=422,
        json={"detail": "validation error"},
    )
    import httpx

    with SGClient() as c, pytest.raises(httpx.HTTPStatusError):
        c.scan_text("x")
