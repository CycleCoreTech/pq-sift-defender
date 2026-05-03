"""Unit tests for YARAClient (real yara-python; no subprocess to mock)."""

from __future__ import annotations

import pytest

from pq_sift_defender.sift_tools.yara_wrapper import YARAClient, YARAFailed

EICAR_LIKE_RULE = """
rule TestEicarLike
{
    meta:
        author = "test"
        severity = "low"
    strings:
        $a = "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $a
}
"""

SUSPICIOUS_STRING_RULE = """
rule SuspiciousLogin
{
    strings:
        $sql = "OR 1=1"
        $cmd = "/bin/sh"
    condition:
        any of them
}
"""


def test_compile_then_scan_data_no_match() -> None:
    c = YARAClient()
    c.compile_source(EICAR_LIKE_RULE)
    r = c.scan_data(b"hello world")
    assert r.match_count == 0


def test_compile_then_scan_data_match() -> None:
    c = YARAClient()
    c.compile_source(SUSPICIOUS_STRING_RULE)
    r = c.scan_data(b"x' OR 1=1 -- y")
    assert r.match_count == 1
    assert r.matches[0].rule == "SuspiciousLogin"


def test_scan_file(tmp_path) -> None:
    target = tmp_path / "evidence.bin"
    target.write_bytes(b"some data with OR 1=1 inside")
    c = YARAClient()
    c.compile_source(SUSPICIOUS_STRING_RULE)
    r = c.scan_file(target)
    assert r.match_count == 1


def test_scan_without_compile_raises() -> None:
    c = YARAClient()
    with pytest.raises(YARAFailed, match="no rules compiled"):
        c.scan_data(b"x")


def test_invalid_rule_raises() -> None:
    c = YARAClient()
    with pytest.raises(YARAFailed, match="syntax error"):
        c.compile_source("rule Bad { condition: nonsense_token }")


def test_target_not_found(tmp_path) -> None:
    c = YARAClient()
    c.compile_source(SUSPICIOUS_STRING_RULE)
    with pytest.raises(YARAFailed, match="target not found"):
        c.scan_file(tmp_path / "missing.bin")


def test_metadata_preserved() -> None:
    c = YARAClient()
    c.compile_source(EICAR_LIKE_RULE)
    r = c.scan_data(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    assert r.match_count == 1
    assert r.matches[0].meta.get("severity") == "low"
