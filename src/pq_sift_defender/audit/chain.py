"""Per-investigation audit chain.

Server-authoritative — chain entries are signed and linked by the public
attestation endpoints (POST /v1/attest, /v1/attest/verify, /v1/attest/export
at https://pq-api.cyclecore.ai). This wrapper provides run lifecycle and a
local index for in-process bookkeeping; trust is established by the server.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pq_sift_defender.clients.pq_client import PQClient


@dataclass
class _LocalEntry:
    entry_index: int
    action_type: str
    entry_hash: str
    timestamp: str


@dataclass
class IRChain:
    """Per-investigation audit chain backed by the public attestation API."""

    pq: PQClient
    chain_id: str | None = None
    _index: list[_LocalEntry] = field(default_factory=list)

    def append(self, action_type: str, payload: Mapping[str, Any]) -> Any:
        """Append a signed entry. Creates the chain on first call if needed."""
        ts = datetime.now(timezone.utc).isoformat()
        entry = {"action_type": action_type, "ts": ts, **dict(payload)}
        result = self.pq.attest(data=entry, chain_id=self.chain_id)
        if self.chain_id is None:
            self.chain_id = result.chain_id  # type: ignore[attr-defined]
        self._index.append(
            _LocalEntry(
                entry_index=result.entry_index,  # type: ignore[attr-defined]
                action_type=action_type,
                entry_hash=result.entry_hash,  # type: ignore[attr-defined]
                timestamp=ts,
            )
        )
        return result

    def verify(self) -> Any:
        """Server-validated chain integrity."""
        if self.chain_id is None:
            raise RuntimeError("Chain not started")
        return self.pq.attest_verify(self.chain_id)

    def export(self) -> Any:
        """Full chain JSON for offline audit."""
        if self.chain_id is None:
            raise RuntimeError("Chain not started")
        return self.pq.attest_export(self.chain_id)

    @property
    def length(self) -> int:
        return len(self._index)
