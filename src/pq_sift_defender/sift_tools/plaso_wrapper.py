"""Wrapper for the Plaso log timeline analysis suite (log2timeline + psort).

Two-stage pipeline: `log2timeline` extracts events from a target into a
plaso storage file; `psort` reads the storage file and emits a sorted
timeline (default: dynamic CSV).
"""

from __future__ import annotations

import csv
import io
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

DEFAULT_LOG2TIMELINE = "log2timeline"
DEFAULT_PSORT = "psort"
DEFAULT_TIMEOUT_S = 1800.0


class PlasoNotInstalled(RuntimeError):
    pass


class PlasoFailed(RuntimeError):
    pass


@dataclass
class TimelineEvent:
    datetime: str
    timestamp_desc: str
    source: str
    source_long: str
    message: str


@dataclass
class TimelineReport:
    target: str
    storage_path: str
    event_count: int
    events: list[TimelineEvent]
    extraction_stderr: str
    sort_stderr: str


class PlasoClient:
    """Pipeline wrapper for log2timeline + psort."""

    def __init__(
        self,
        log2timeline_binary: str = DEFAULT_LOG2TIMELINE,
        psort_binary: str = DEFAULT_PSORT,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        if shutil.which(log2timeline_binary) is None:
            raise PlasoNotInstalled(
                f"`{log2timeline_binary}` not on PATH. Install with: pip install plaso"
            )
        if shutil.which(psort_binary) is None:
            raise PlasoNotInstalled(
                f"`{psort_binary}` not on PATH. Install with: pip install plaso"
            )
        self._l2t = log2timeline_binary
        self._psort = psort_binary
        self._timeout_s = timeout_s

    def extract(
        self,
        target: str | Path,
        storage_path: str | Path | None = None,
        parsers: str | None = None,
    ) -> Path:
        """Run log2timeline against `target`, writing a .plaso storage file.

        Returns the storage file path.
        """
        target = str(target)
        if not Path(target).exists():
            raise PlasoFailed(f"target not found: {target}")
        if storage_path is None:
            storage_path = Path(tempfile.mkdtemp(prefix="plaso-")) / "timeline.plaso"
        storage_path = Path(storage_path)
        cmd = [self._l2t, "--quiet", "--unattended"]
        if parsers:
            cmd += ["--parsers", parsers]
        cmd += ["--storage_file", str(storage_path), target]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self._timeout_s, check=False
            )
        except subprocess.TimeoutExpired as e:
            raise PlasoFailed(f"log2timeline timeout after {self._timeout_s}s") from e
        if proc.returncode != 0:
            raise PlasoFailed(
                f"log2timeline failed (rc={proc.returncode}): {proc.stderr.strip()[:300]}"
            )
        if not storage_path.exists():
            raise PlasoFailed(f"log2timeline produced no storage file at {storage_path}")
        return storage_path

    def sort(
        self,
        storage_path: str | Path,
        max_events: int = 500,
    ) -> TimelineReport:
        """Run psort on a .plaso storage file and parse the resulting CSV timeline."""
        storage_path = str(storage_path)
        if not Path(storage_path).exists():
            raise PlasoFailed(f"storage file not found: {storage_path}")
        cmd = [self._psort, "-o", "dynamic", str(storage_path)]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self._timeout_s, check=False
            )
        except subprocess.TimeoutExpired as e:
            raise PlasoFailed(f"psort timeout after {self._timeout_s}s") from e
        if proc.returncode != 0:
            raise PlasoFailed(f"psort failed (rc={proc.returncode}): {proc.stderr.strip()[:300]}")
        events = self._parse_csv(proc.stdout, max_events=max_events)
        return TimelineReport(
            target=storage_path,
            storage_path=storage_path,
            event_count=len(events),
            events=events,
            extraction_stderr="",
            sort_stderr=proc.stderr,
        )

    def timeline(
        self,
        target: str | Path,
        parsers: str | None = None,
        max_events: int = 500,
    ) -> TimelineReport:
        """End-to-end: extract events from `target`, sort, return parsed timeline."""
        storage_path = self.extract(target, parsers=parsers)
        return self.sort(storage_path, max_events=max_events)

    @staticmethod
    def _parse_csv(stdout: str, max_events: int) -> list[TimelineEvent]:
        reader = csv.DictReader(io.StringIO(stdout))
        out: list[TimelineEvent] = []
        for row in reader:
            out.append(
                TimelineEvent(
                    datetime=row.get("datetime", ""),
                    timestamp_desc=row.get("timestamp_desc", ""),
                    source=row.get("source", ""),
                    source_long=row.get("source_long", ""),
                    message=row.get("message", "")[:500],
                )
            )
            if len(out) >= max_events:
                break
        return out
