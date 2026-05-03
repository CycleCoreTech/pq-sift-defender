"""Live integration test against pq-api.cyclecore.ai.

Requires CYCLECORE_PQ_API_KEY env var (free-tier key works).
"""

import os

import pytest

from pq_sift_defender.clients.pq_client import PQClient


@pytest.mark.live
def test_health_live() -> None:
    if not os.environ.get("CYCLECORE_PQ_API_KEY"):
        pytest.skip("CYCLECORE_PQ_API_KEY not set")
    with PQClient() as c:
        h = c.health()
    assert "version" in h or "status" in h


@pytest.mark.live
def test_attest_chain_round_trip_live() -> None:
    """Append → verify → export round-trip on a fresh chain."""
    if not os.environ.get("CYCLECORE_PQ_API_KEY"):
        pytest.skip("CYCLECORE_PQ_API_KEY not set")
    with PQClient() as c:
        first = c.attest({"action": "test", "step": 1})
        chain_id = first.chain_id  # type: ignore[attr-defined]
        c.attest({"action": "test", "step": 2}, chain_id=chain_id)
        verified = c.attest_verify(chain_id)
        assert verified.valid is True  # type: ignore[attr-defined]
