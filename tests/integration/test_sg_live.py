"""Live integration test against sg-api.cyclecore.ai."""

import pytest

from pq_sift_defender.clients.sg_client import SGClient


@pytest.mark.live
def test_health_live() -> None:
    with SGClient(timeout_s=10.0) as c:
        h = c.health()
    assert "status" in h


@pytest.mark.live
def test_scan_text_safe_input_live() -> None:
    with SGClient(timeout_s=10.0) as c:
        result = c.scan_text("hello world")
    assert result.safe is True
    assert result.recommendation == "PASS"
