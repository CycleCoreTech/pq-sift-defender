"""Unit tests for SleuthKitClient (mocked subprocess)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pq_sift_defender.sift_tools.sleuthkit_wrapper import (
    SleuthKitClient,
    SleuthKitFailed,
    SleuthKitNotInstalled,
)


def _proc(stdout: str = "", returncode: int = 0, stderr: str = "") -> MagicMock:
    p = MagicMock()
    p.stdout = stdout
    p.stderr = stderr
    p.returncode = returncode
    return p


MMLS_OUTPUT = """\
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0009621503   0009619456   NTFS / exFAT (0x07)
003:  -------   0009621504   0009629695   0000008192   Unallocated
"""

FLS_OUTPUT = """\
d/d 64-144-1:   System Volume Information
r/r 65-128-1:   $LogFile
r/r * 100-128-1:    deleted_secrets.txt
d/d 200-144-1:  Users
"""


def test_raises_if_binary_missing() -> None:
    with patch("pq_sift_defender.sift_tools.sleuthkit_wrapper.shutil.which", return_value=None):
        with pytest.raises(SleuthKitNotInstalled):
            SleuthKitClient()


def test_mmls_parse(tmp_path) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"x")
    with (
        patch(
            "pq_sift_defender.sift_tools.sleuthkit_wrapper.shutil.which",
            return_value="/usr/bin/mmls",
        ),
        patch(
            "pq_sift_defender.sift_tools.sleuthkit_wrapper.subprocess.run",
            return_value=_proc(stdout=MMLS_OUTPUT),
        ),
    ):
        table = SleuthKitClient().mmls(image)
    # Should parse 4 rows (Meta + Unallocated + NTFS + Unallocated)
    assert len(table.partitions) == 4
    ntfs = [p for p in table.partitions if "NTFS" in p.description]
    assert len(ntfs) == 1
    assert ntfs[0].start_sector == 2048


def test_fls_parse(tmp_path) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"x")
    with (
        patch(
            "pq_sift_defender.sift_tools.sleuthkit_wrapper.shutil.which",
            return_value="/usr/bin/fls",
        ),
        patch(
            "pq_sift_defender.sift_tools.sleuthkit_wrapper.subprocess.run",
            return_value=_proc(stdout=FLS_OUTPUT),
        ),
    ):
        listing = SleuthKitClient().fls(image, offset=2048)
    assert len(listing.entries) == 4
    deleted = [e for e in listing.entries if e.is_deleted]
    assert len(deleted) == 1
    assert deleted[0].name == "deleted_secrets.txt"
    dirs = [e for e in listing.entries if e.is_dir]
    assert len(dirs) == 2


def test_image_not_found(tmp_path) -> None:
    with (
        patch(
            "pq_sift_defender.sift_tools.sleuthkit_wrapper.shutil.which",
            return_value="/usr/bin/mmls",
        ),
        pytest.raises(SleuthKitFailed, match="image not found"),
    ):
        SleuthKitClient().mmls(tmp_path / "missing.raw")


def test_nonzero_exit_raises(tmp_path) -> None:
    image = tmp_path / "disk.raw"
    image.write_bytes(b"x")
    with (
        patch(
            "pq_sift_defender.sift_tools.sleuthkit_wrapper.shutil.which",
            return_value="/usr/bin/mmls",
        ),
        patch(
            "pq_sift_defender.sift_tools.sleuthkit_wrapper.subprocess.run",
            return_value=_proc(returncode=1, stderr="not a disk image"),
        ),
        pytest.raises(SleuthKitFailed, match="mmls exited 1"),
    ):
        SleuthKitClient().mmls(image)
