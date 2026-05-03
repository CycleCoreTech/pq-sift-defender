"""Client for the public CycleCore SecurityGates API.

API reference: https://sg-api.cyclecore.ai/docs

This wrapper covers the documented endpoints in the public OpenAPI spec at
https://sg-api.cyclecore.ai/openapi.json.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import httpx

DEFAULT_BASE_URL = os.environ.get("CYCLECORE_SG_BASE_URL", "https://sg-api.cyclecore.ai")
DEFAULT_TIMEOUT_S = 5.0
USER_AGENT = "pq-sift-defender/0.2.0"


@dataclass(frozen=True)
class ScanFlag:
    gate: str
    confidence: float
    detected: bool
    pattern: str | None = None


@dataclass(frozen=True)
class ScanResult:
    safe: bool
    risk_score: float
    flags: list[ScanFlag]
    latency_us: float
    recommendation: str  # "PASS" | "FLAG" | "BLOCK"


class SGClient:
    """Synchronous client for SecurityGates."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        headers = {"User-Agent": USER_AGENT}
        key = api_key if api_key is not None else os.environ.get("CYCLECORE_SG_API_KEY")
        if key:
            headers["X-API-Key"] = key
        self._http = httpx.Client(
            base_url=base_url or DEFAULT_BASE_URL,
            headers=headers,
            timeout=timeout_s,
        )

    # --- public endpoints ---

    def scan_text(self, text: str, gates: Sequence[str] | None = None) -> ScanResult:
        """POST /v1/security/scan/text"""
        payload: dict[str, Any] = {"text": text}
        if gates is not None:
            payload["gates"] = list(gates)
        r = self._http.post("/v1/security/scan/text", json=payload)
        r.raise_for_status()
        return self._parse(r.json())

    def scan(
        self,
        method: str = "GET",
        path: str = "/",
        headers: Mapping[str, str] | None = None,
        body: Mapping[str, Any] | None = None,
        query_params: Mapping[str, str] | None = None,
        gates: Sequence[str] | None = None,
    ) -> ScanResult:
        """POST /v1/security/scan"""
        request_payload: dict[str, Any] = {"method": method, "path": path}
        if headers is not None:
            request_payload["headers"] = dict(headers)
        if body is not None:
            request_payload["body"] = dict(body)
        if query_params is not None:
            request_payload["query_params"] = dict(query_params)
        payload: dict[str, Any] = {"request": request_payload}
        if gates is not None:
            payload["gates"] = list(gates)
        r = self._http.post("/v1/security/scan", json=payload)
        r.raise_for_status()
        return self._parse(r.json())

    def gates(self) -> list[str]:
        """GET /v1/security/gates"""
        r = self._http.get("/v1/security/gates")
        r.raise_for_status()
        return list(r.json().get("gates", []))

    def health(self) -> dict[str, Any]:
        """GET /v1/security/health"""
        r = self._http.get("/v1/security/health")
        r.raise_for_status()
        return r.json()

    # --- helpers ---

    @staticmethod
    def _parse(j: dict[str, Any]) -> ScanResult:
        flags = [
            ScanFlag(
                gate=f["gate"],
                confidence=f["confidence"],
                detected=f["detected"],
                pattern=f.get("pattern"),
            )
            for f in j.get("flags", [])
        ]
        return ScanResult(
            safe=j["safe"],
            risk_score=j["risk_score"],
            flags=flags,
            latency_us=j["latency_us"],
            recommendation=j["recommendation"],
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> SGClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
