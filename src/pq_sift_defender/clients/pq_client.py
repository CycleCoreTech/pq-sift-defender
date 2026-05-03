"""Client for the public CycleCore PQ API.

Wraps the official `cyclecore-pq` SDK (https://pypi.org/project/cyclecore-pq/)
with helpers tuned for the IR audit-chain use case. See
https://pq-api.cyclecore.ai/openapi.json for the underlying API surface.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from cyclecore_pq import (
    AttestExportResult,
    AttestResult,
    AttestVerifyResult,
    CycleCoreClient,
)

DEFAULT_BASE_URL = os.environ.get("CYCLECORE_PQ_BASE_URL", "https://pq-api.cyclecore.ai")
DEFAULT_TIMEOUT_S = 10.0


class PQClient:
    """Thin facade around the official SDK for IR audit-chain operations."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        key = api_key or os.environ.get("CYCLECORE_PQ_API_KEY")
        if not key:
            raise ValueError(
                "PQ API key required. Set CYCLECORE_PQ_API_KEY env var or pass "
                "api_key=. Get a free-tier key via POST /v1/auth/register."
            )
        self._client = CycleCoreClient(
            api_key=key, base_url=base_url or DEFAULT_BASE_URL, timeout=timeout_s
        )

    # --- attestation chain (the IR audit-trail use case) ---

    def attest(self, data: Mapping[str, Any], chain_id: str | None = None) -> AttestResult:
        """POST /v1/attest — append signed entry to a chain."""
        return self._client.attest(data=dict(data), chain_id=chain_id)

    def attest_verify(self, chain_id: str) -> AttestVerifyResult:
        """POST /v1/attest/verify — server-validated chain integrity."""
        return self._client.attest_verify(chain_id)

    def attest_export(self, chain_id: str) -> AttestExportResult:
        """POST /v1/attest/export — full chain JSON for offline audit."""
        return self._client.attest_export(chain_id)

    # --- standalone signing (occasional use) ---

    def sign(self, message: bytes) -> Any:
        """POST /v1/sign — Dilithium3 signature."""
        return self._client.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key: str | None = None) -> Any:
        """POST /v1/verify — Dilithium3 verification."""
        return self._client.verify(message, signature, public_key=public_key)

    def health(self) -> dict[str, Any]:
        """GET /health"""
        return self._client.health()

    # --- lifecycle ---

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> PQClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
