"""Unit tests for SiftPrefilter."""

from __future__ import annotations

from unittest.mock import MagicMock

from pq_sift_defender.clients.sg_client import ScanFlag, ScanResult
from pq_sift_defender.sift.prefilter import SiftPrefilter


def _scan(recommendation: str = "PASS") -> ScanResult:
    return ScanResult(
        safe=recommendation == "PASS",
        risk_score=0.1 if recommendation == "PASS" else 0.9,
        flags=[ScanFlag(gate="injection_sql", confidence=0.1, detected=False)],
        latency_us=42.0,
        recommendation=recommendation,
    )


def test_pass_allows() -> None:
    sg = MagicMock()
    sg.scan_text.return_value = _scan("PASS")
    f = SiftPrefilter(sg)
    decision = f.check_text("hello")
    assert decision.allow is True


def test_flag_allows_with_warning() -> None:
    sg = MagicMock()
    sg.scan_text.return_value = _scan("FLAG")
    f = SiftPrefilter(sg)
    decision = f.check_text("borderline")
    assert decision.allow is True
    assert decision.scan.recommendation == "FLAG"


def test_block_denies() -> None:
    sg = MagicMock()
    sg.scan_text.return_value = _scan("BLOCK")
    f = SiftPrefilter(sg)
    decision = f.check_text("'; DROP TABLE users;--")
    assert decision.allow is False


def test_check_dict_extracts_nested_strings() -> None:
    sg = MagicMock()
    sg.scan_text.return_value = _scan("PASS")
    f = SiftPrefilter(sg)
    payload = {"alert": {"src": "1.2.3.4", "msg": "suspicious traffic", "tags": ["a", "b"]}}
    f.check_dict(payload)
    call_text = sg.scan_text.call_args.args[0]
    assert "1.2.3.4" in call_text
    assert "suspicious traffic" in call_text
    assert "a" in call_text
