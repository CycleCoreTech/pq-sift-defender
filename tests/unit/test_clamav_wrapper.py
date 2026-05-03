"""Unit tests for ClamAVClient (mocked subprocess)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pq_sift_defender.sift_tools.clamav_wrapper import (
    ClamAVClient,
    ClamAVFailed,
    ClamAVNotInstalled,
)


def _proc(stdout: str = "", returncode: int = 0, stderr: str = "") -> MagicMock:
    p = MagicMock()
    p.stdout = stdout
    p.stderr = stderr
    p.returncode = returncode
    return p


CLEAN_OUTPUT = """\
/tmp/file1.txt: OK
/tmp/file2.txt: OK
----------- SCAN SUMMARY -----------
Known viruses: 8623917
Engine version: 1.4.4
Scanned directories: 1
Scanned files: 2
Infected files: 0
Data scanned: 0.01 MB
Time: 1.234 sec
"""

INFECTED_OUTPUT = """\
/tmp/eicar.txt: Eicar-Test-Signature FOUND
----------- SCAN SUMMARY -----------
Known viruses: 8623917
Engine version: 1.4.4
Scanned directories: 1
Scanned files: 1
Infected files: 1
Data scanned: 0.00 MB
"""


def test_raises_if_binary_missing() -> None:
    with patch("pq_sift_defender.sift_tools.clamav_wrapper.shutil.which", return_value=None):
        with pytest.raises(ClamAVNotInstalled):
            ClamAVClient()


def test_scan_clean(tmp_path) -> None:
    target = tmp_path / "x.txt"
    target.write_text("ok")
    with (
        patch(
            "pq_sift_defender.sift_tools.clamav_wrapper.shutil.which",
            return_value="/usr/bin/clamscan",
        ),
        patch(
            "pq_sift_defender.sift_tools.clamav_wrapper.subprocess.run",
            return_value=_proc(stdout=CLEAN_OUTPUT, returncode=0),
        ),
    ):
        r = ClamAVClient().scan(target)
    assert r.infected_count == 0
    assert r.scanned_files == 2
    assert r.infections == []


def test_scan_infected(tmp_path) -> None:
    target = tmp_path / "eicar.txt"
    target.write_text("X5O!")
    with (
        patch(
            "pq_sift_defender.sift_tools.clamav_wrapper.shutil.which",
            return_value="/usr/bin/clamscan",
        ),
        patch(
            "pq_sift_defender.sift_tools.clamav_wrapper.subprocess.run",
            return_value=_proc(stdout=INFECTED_OUTPUT, returncode=1),
        ),
    ):
        r = ClamAVClient().scan(target)
    assert r.infected_count == 1
    assert len(r.infections) == 1
    assert r.infections[0]["signature"] == "Eicar-Test-Signature"


def test_target_not_found(tmp_path) -> None:
    with (
        patch(
            "pq_sift_defender.sift_tools.clamav_wrapper.shutil.which",
            return_value="/usr/bin/clamscan",
        ),
        pytest.raises(ClamAVFailed, match="target not found"),
    ):
        ClamAVClient().scan(tmp_path / "missing")


def test_engine_error_raises(tmp_path) -> None:
    target = tmp_path / "x.txt"
    target.write_text("ok")
    with (
        patch(
            "pq_sift_defender.sift_tools.clamav_wrapper.shutil.which",
            return_value="/usr/bin/clamscan",
        ),
        patch(
            "pq_sift_defender.sift_tools.clamav_wrapper.subprocess.run",
            return_value=_proc(stdout="", returncode=2, stderr="bad signature db"),
        ),
        pytest.raises(ClamAVFailed, match="clamscan errored"),
    ):
        ClamAVClient().scan(target)


def test_version_parse() -> None:
    with (
        patch(
            "pq_sift_defender.sift_tools.clamav_wrapper.shutil.which",
            return_value="/usr/bin/clamscan",
        ),
        patch(
            "pq_sift_defender.sift_tools.clamav_wrapper.subprocess.run",
            return_value=_proc(stdout="ClamAV 1.4.4/27990/Sun May  3 02:24:58 2026\n"),
        ),
    ):
        v = ClamAVClient().version()
    assert v["engine"] == "ClamAV 1.4.4"
    assert v["signature_db"] == "27990"
