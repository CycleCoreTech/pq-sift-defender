"""Unit tests for PlasoClient (mocked subprocess)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pq_sift_defender.sift_tools.plaso_wrapper import (
    PlasoClient,
    PlasoFailed,
    PlasoNotInstalled,
)


def _proc(stdout: str = "", returncode: int = 0, stderr: str = "") -> MagicMock:
    p = MagicMock()
    p.stdout = stdout
    p.stderr = stderr
    p.returncode = returncode
    return p


SAMPLE_PSORT_CSV = (
    "datetime,timestamp_desc,source,source_long,message\n"
    "2026-05-03T10:00:00+00:00,Creation Time,LOG,Syslog,sshd: accepted publickey for alice\n"
    "2026-05-03T10:00:01+00:00,Modification Time,LOG,Syslog,sshd: session opened for user alice\n"
)


def test_raises_if_log2timeline_missing() -> None:
    with (
        patch(
            "pq_sift_defender.sift_tools.plaso_wrapper.shutil.which",
            side_effect=lambda _: None,
        ),
        pytest.raises(PlasoNotInstalled),
    ):
        PlasoClient()


def test_raises_if_psort_missing() -> None:
    def which(name: str) -> str | None:
        return "/usr/bin/log2timeline" if name == "log2timeline" else None

    with patch("pq_sift_defender.sift_tools.plaso_wrapper.shutil.which", side_effect=which):
        with pytest.raises(PlasoNotInstalled, match="psort"):
            PlasoClient()


def test_extract_target_not_found(tmp_path) -> None:
    with (
        patch(
            "pq_sift_defender.sift_tools.plaso_wrapper.shutil.which",
            return_value="/usr/bin/x",
        ),
        pytest.raises(PlasoFailed, match="target not found"),
    ):
        PlasoClient().extract(tmp_path / "missing.log")


def test_extract_failure_propagates(tmp_path) -> None:
    target = tmp_path / "x.log"
    target.write_text("hello")
    with (
        patch(
            "pq_sift_defender.sift_tools.plaso_wrapper.shutil.which",
            return_value="/usr/bin/x",
        ),
        patch(
            "pq_sift_defender.sift_tools.plaso_wrapper.subprocess.run",
            return_value=_proc(returncode=1, stderr="parser explosion"),
        ),
        pytest.raises(PlasoFailed, match="log2timeline failed"),
    ):
        PlasoClient().extract(target)


def test_sort_parses_csv(tmp_path) -> None:
    storage = tmp_path / "timeline.plaso"
    storage.write_bytes(b"\x00")
    with (
        patch(
            "pq_sift_defender.sift_tools.plaso_wrapper.shutil.which",
            return_value="/usr/bin/x",
        ),
        patch(
            "pq_sift_defender.sift_tools.plaso_wrapper.subprocess.run",
            return_value=_proc(stdout=SAMPLE_PSORT_CSV, returncode=0),
        ),
    ):
        r = PlasoClient().sort(storage)
    assert r.event_count == 2
    assert r.events[0].source == "LOG"
    assert "publickey" in r.events[0].message
    assert r.events[1].timestamp_desc == "Modification Time"


def test_sort_storage_missing(tmp_path) -> None:
    with (
        patch(
            "pq_sift_defender.sift_tools.plaso_wrapper.shutil.which",
            return_value="/usr/bin/x",
        ),
        pytest.raises(PlasoFailed, match="storage file not found"),
    ):
        PlasoClient().sort(tmp_path / "missing.plaso")


def test_sort_max_events_caps_results(tmp_path) -> None:
    storage = tmp_path / "timeline.plaso"
    storage.write_bytes(b"\x00")
    big_csv = "datetime,timestamp_desc,source,source_long,message\n" + "\n".join(
        f"2026-05-03T10:00:{i:02d}+00:00,X,LOG,Syslog,event-{i}" for i in range(50)
    )
    with (
        patch(
            "pq_sift_defender.sift_tools.plaso_wrapper.shutil.which",
            return_value="/usr/bin/x",
        ),
        patch(
            "pq_sift_defender.sift_tools.plaso_wrapper.subprocess.run",
            return_value=_proc(stdout=big_csv, returncode=0),
        ),
    ):
        r = PlasoClient().sort(storage, max_events=10)
    assert r.event_count == 10
