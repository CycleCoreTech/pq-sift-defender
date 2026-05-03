"""Wrapper for the ClamAV antivirus engine.

Shells out to the `clamscan` CLI and parses the summary output.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_BINARY = "clamscan"
DEFAULT_TIMEOUT_S = 300.0


class ClamAVNotInstalled(RuntimeError):
    pass


class ClamAVFailed(RuntimeError):
    pass


@dataclass
class ScanReport:
    target: str
    infected_count: int
    scanned_files: int
    scanned_data_mb: float
    infections: list[dict[str, str]]
    raw_output: str


class ClamAVClient:
    """Thin shell wrapper around the `clamscan` CLI."""

    def __init__(self, binary: str = DEFAULT_BINARY, timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
        if shutil.which(binary) is None:
            raise ClamAVNotInstalled(
                f"`{binary}` not on PATH. Install with: sudo apt install clamav"
            )
        self._binary = binary
        self._timeout_s = timeout_s

    def scan(self, target: str | Path, recursive: bool = True) -> ScanReport:
        """Scan a file or directory. Returns parsed summary."""
        target = str(target)
        if not Path(target).exists():
            raise ClamAVFailed(f"target not found: {target}")
        cmd = [self._binary, "--no-summary=no"]
        if recursive and Path(target).is_dir():
            cmd.append("-r")
        cmd.append(target)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise ClamAVFailed(f"timeout after {self._timeout_s}s") from e
        # clamscan exits 0 = clean, 1 = found, 2 = error
        if proc.returncode == 2:
            raise ClamAVFailed(f"clamscan errored: {proc.stderr.strip()[:300]}")
        return self._parse(proc.stdout, target)

    @staticmethod
    def _parse(stdout: str, target: str) -> ScanReport:
        infections: list[dict[str, str]] = []
        infected_count = 0
        scanned_files = 0
        scanned_data_mb = 0.0
        for line in stdout.splitlines():
            line = line.strip()
            if line.endswith("FOUND"):
                # Format: <path>: <signature> FOUND
                match = re.match(r"^(.*?):\s+(.*?)\s+FOUND$", line)
                if match:
                    infections.append({"file": match.group(1), "signature": match.group(2)})
            elif line.startswith("Infected files:"):
                infected_count = int(line.split(":", 1)[1].strip())
            elif line.startswith("Scanned files:"):
                scanned_files = int(line.split(":", 1)[1].strip())
            elif line.startswith("Data scanned:"):
                # "Data scanned: 1.23 MB"
                match = re.search(r"([\d.]+)\s*MB", line)
                if match:
                    scanned_data_mb = float(match.group(1))
        return ScanReport(
            target=target,
            infected_count=infected_count,
            scanned_files=scanned_files,
            scanned_data_mb=scanned_data_mb,
            infections=infections,
            raw_output=stdout,
        )

    def version(self) -> dict[str, Any]:
        """Get ClamAV engine + signature database version."""
        proc = subprocess.run(
            [self._binary, "--version"], capture_output=True, text=True, timeout=10.0, check=False
        )
        # Format: "ClamAV 1.4.4/27990/Sun May  3 02:24:58 2026"
        line = proc.stdout.strip()
        parts = line.split("/")
        return {
            "engine": parts[0].strip() if len(parts) > 0 else line,
            "signature_db": parts[1].strip() if len(parts) > 1 else "",
            "db_date": parts[2].strip() if len(parts) > 2 else "",
        }
