"""Test the MITRE ATT&CK technique attribution.

Confirms the `_harvest_attacks` helper extracts the right techniques
from each tool dispatch shape, and the IOC scanner annotates suspicious
processes with their ATT&CK mapping.
"""

from __future__ import annotations

import json

import pytest

from pq_sift_defender.agent.core import (
    _attack_for_gate,
    _attack_for_ioc_fragment,
    _harvest_attacks,
    _scan_processes_for_iocs,
)


def test_attack_for_gate_known() -> None:
    a = _attack_for_gate("path_traversal")
    assert a is not None
    assert a["id"] == "T1083"
    assert "File and Directory" in a["name"]


def test_attack_for_gate_unknown() -> None:
    assert _attack_for_gate("not_a_real_gate") is None


def test_attack_for_ioc_keylog() -> None:
    a = _attack_for_ioc_fragment("keylog")
    assert a is not None
    assert a["id"] == "T1056.001"


def test_scan_processes_annotates_ioc() -> None:
    rows = [
        {"PID": 100, "PPID": 1, "ImageFileName": "explorer.exe"},
        {"PID": 280, "PPID": 168, "ImageFileName": "ToolKeylogger.exe"},
        {"PID": 666, "PPID": 4, "ImageFileName": "xmrig-miner.exe"},
    ]
    out = _scan_processes_for_iocs(rows)
    assert len(out) == 2
    assert out[0]["matched_fragment"] == "keylog"
    assert out[0]["attack_technique"]["id"] == "T1056.001"
    assert out[1]["matched_fragment"] in ("xmrig", "miner")
    assert out[1]["attack_technique"]["id"] == "T1496"


def test_harvest_from_boundary_block_cloud_metadata() -> None:
    output = json.dumps(
        {
            "error": "blocked at agent->tool boundary",
            "blocked_value_preview": "http://169.254.169.254/latest/meta-data",
        }
    )
    techs = _harvest_attacks("vol_pslist", {"image_path": "..."}, output)
    ids = [t[0] for t in techs]
    assert "T1552.005" in ids


def test_harvest_from_sift_classify_with_etc_passwd() -> None:
    output = json.dumps(
        {
            "recommendation": "BLOCK",
            "risk_score": 0.83,
            "flags": [
                {"gate": "path_traversal", "detected": True, "confidence": 0.83},
            ],
        }
    )
    techs = _harvest_attacks(
        "sift_classify", {"text": "GET /api/v1/files?name=../../../../etc/passwd"}, output
    )
    ids = [t[0] for t in techs]
    assert "T1083" in ids


def test_harvest_skips_undetected_flags() -> None:
    """A FLAG-only or BLOCK overall with no detected==True flags → no attribution."""
    output = json.dumps(
        {
            "recommendation": "FLAG",
            "risk_score": 0.65,
            "flags": [
                {"gate": "injection_sql", "detected": False, "confidence": 0.55},
                {"gate": "injection_cmd", "detected": False, "confidence": 0.59},
            ],
        }
    )
    techs = _harvest_attacks("sift_classify", {"text": "ambiguous"}, output)
    # No detected flags + no value-substring match → no attributions
    assert techs == []


def test_harvest_from_vol_pslist_keylogger() -> None:
    output = json.dumps(
        {
            "plugin": "windows.pslist",
            "row_count": 33,
            "suspicious_processes": [
                {
                    "PID": 280,
                    "ImageFileName": "ToolKeylogger.exe",
                    "matched_fragment": "keylog",
                    "attack_technique": {"id": "T1056.001", "name": "Input Capture: Keylogging"},
                }
            ],
            "rows": [],
        }
    )
    techs = _harvest_attacks("vol_pslist", {"image_path": "x.vmem"}, output)
    ids = [t[0] for t in techs]
    assert "T1056.001" in ids


def test_harvest_handles_empty_output() -> None:
    assert _harvest_attacks("vol_pslist", {}, "") == []
    assert _harvest_attacks("vol_pslist", {}, "not json") == []


@pytest.mark.parametrize(
    "fragment,expected_id",
    [
        ("mimikatz", "T1003.001"),
        ("xmrig", "T1496"),
        ("cobaltstrike", "T1219"),
        ("rootkit", "T1014"),
    ],
)
def test_attack_for_various_iocs(fragment: str, expected_id: str) -> None:
    a = _attack_for_ioc_fragment(fragment)
    assert a is not None
    assert a["id"] == expected_id
