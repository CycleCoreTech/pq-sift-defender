"""Unit tests for VolatilityClient (mocked subprocess)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from pq_sift_defender.sift_tools.volatility_wrapper import (
    VolatilityClient,
    VolatilityFailed,
    VolatilityNotInstalled,
)


def _proc(stdout: str = "[]", returncode: int = 0, stderr: str = "") -> MagicMock:
    p = MagicMock()
    p.stdout = stdout
    p.stderr = stderr
    p.returncode = returncode
    return p


def test_raises_if_binary_missing(tmp_path) -> None:
    with patch("pq_sift_defender.sift_tools.volatility_wrapper.shutil.which", return_value=None):
        with pytest.raises(VolatilityNotInstalled):
            VolatilityClient()


def test_run_parses_json_array(tmp_path) -> None:
    image = tmp_path / "memdump.raw"
    image.write_bytes(b"x")
    rows = [{"PID": 4, "ImageFileName": "System"}, {"PID": 100, "ImageFileName": "svchost.exe"}]
    with (
        patch(
            "pq_sift_defender.sift_tools.volatility_wrapper.shutil.which",
            return_value="/usr/local/bin/vol",
        ),
        patch(
            "pq_sift_defender.sift_tools.volatility_wrapper.subprocess.run",
            return_value=_proc(stdout=json.dumps(rows)),
        ),
    ):
        client = VolatilityClient()
        result = client.run(image, "windows.pslist")
    assert result.plugin == "windows.pslist"
    assert len(result.rows) == 2
    assert result.rows[0]["PID"] == 4


def test_run_image_not_found(tmp_path) -> None:
    with patch(
        "pq_sift_defender.sift_tools.volatility_wrapper.shutil.which",
        return_value="/usr/local/bin/vol",
    ):
        client = VolatilityClient()
        with pytest.raises(VolatilityFailed, match="image not found"):
            client.run(tmp_path / "missing.raw", "windows.pslist")


def test_run_nonzero_exit_raises(tmp_path) -> None:
    image = tmp_path / "memdump.raw"
    image.write_bytes(b"x")
    with (
        patch(
            "pq_sift_defender.sift_tools.volatility_wrapper.shutil.which",
            return_value="/usr/local/bin/vol",
        ),
        patch(
            "pq_sift_defender.sift_tools.volatility_wrapper.subprocess.run",
            return_value=_proc(returncode=1, stderr="bad image"),
        ),
    ):
        client = VolatilityClient()
        with pytest.raises(VolatilityFailed, match="vol exited 1"):
            client.run(image, "windows.pslist")


def test_pslist_convenience(tmp_path) -> None:
    image = tmp_path / "memdump.raw"
    image.write_bytes(b"x")
    with (
        patch(
            "pq_sift_defender.sift_tools.volatility_wrapper.shutil.which",
            return_value="/usr/local/bin/vol",
        ),
        patch(
            "pq_sift_defender.sift_tools.volatility_wrapper.subprocess.run",
            return_value=_proc(stdout="[]"),
        ) as run_mock,
    ):
        client = VolatilityClient()
        client.pslist(image)
    cmd = run_mock.call_args.args[0]
    assert "windows.pslist" in cmd
    assert "-r" in cmd and "json" in cmd
