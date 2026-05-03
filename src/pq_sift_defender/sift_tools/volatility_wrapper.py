"""Wrapper for the Volatility 3 memory forensics framework.

Shells out to the `vol` CLI (volatility3 PyPI package) and parses the
JSON-rendered output. Tested against Volatility 3 v2.x.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_BINARY = "vol"
DEFAULT_TIMEOUT_S = 120.0


class VolatilityNotInstalled(RuntimeError):
    pass


class VolatilityFailed(RuntimeError):
    pass


@dataclass
class PluginResult:
    plugin: str
    image: str
    rows: list[dict[str, Any]]
    raw_stdout: str


class VolatilityClient:
    """Thin shell wrapper around the `vol` CLI."""

    def __init__(self, binary: str = DEFAULT_BINARY, timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
        if shutil.which(binary) is None:
            raise VolatilityNotInstalled(
                f"`{binary}` not on PATH. Install with: pip install volatility3"
            )
        self._binary = binary
        self._timeout_s = timeout_s

    def run(
        self, image: str | Path, plugin: str, plugin_args: list[str] | None = None
    ) -> PluginResult:
        """Run a Volatility plugin and return parsed rows."""
        image = str(image)
        if not Path(image).is_file():
            raise VolatilityFailed(f"image not found: {image}")
        cmd = [self._binary, "-q", "-r", "json", "-f", image, plugin]
        if plugin_args:
            cmd.extend(plugin_args)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise VolatilityFailed(f"timeout after {self._timeout_s}s") from e
        if proc.returncode != 0:
            raise VolatilityFailed(f"vol exited {proc.returncode}: {proc.stderr.strip()[:300]}")
        rows = self._parse_json(proc.stdout)
        return PluginResult(plugin=plugin, image=image, rows=rows, raw_stdout=proc.stdout)

    @staticmethod
    def _parse_json(stdout: str) -> list[dict[str, Any]]:
        stdout = stdout.strip()
        if not stdout:
            return []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return [{"_raw": line} for line in stdout.splitlines() if line.strip()]
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            return [data]
        return []

    # --- common-plugin convenience methods ---

    def imageinfo(self, image: str | Path) -> PluginResult:
        """Identify the OS profile of a memory image."""
        return self.run(image, "windows.info")

    def pslist(self, image: str | Path) -> PluginResult:
        """Process list (Windows)."""
        return self.run(image, "windows.pslist")

    def dlllist(self, image: str | Path, pid: int | None = None) -> PluginResult:
        """DLL list (Windows). Optionally filter by PID."""
        args = ["--pid", str(pid)] if pid is not None else None
        return self.run(image, "windows.dlllist", args)

    def netscan(self, image: str | Path) -> PluginResult:
        """Network connections (Windows)."""
        return self.run(image, "windows.netscan")
