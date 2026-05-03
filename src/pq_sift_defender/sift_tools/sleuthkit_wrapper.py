"""Wrapper for The Sleuth Kit (TSK) filesystem-forensics tools.

Shells out to `mmls` (partition table), `fls` (filesystem listing), and
`istat` (inode metadata). Operates against raw disk images.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TIMEOUT_S = 60.0


class SleuthKitNotInstalled(RuntimeError):
    pass


class SleuthKitFailed(RuntimeError):
    pass


@dataclass
class Partition:
    slot: str
    start_sector: int
    end_sector: int
    length_sectors: int
    description: str


@dataclass
class FileEntry:
    inode: str
    name: str
    is_dir: bool
    is_deleted: bool


@dataclass
class PartitionTable:
    image: str
    partitions: list[Partition]
    raw_output: str


@dataclass
class DirectoryListing:
    image: str
    offset: int
    entries: list[FileEntry]
    raw_output: str


class SleuthKitClient:
    """Thin shell wrapper around mmls / fls / istat."""

    def __init__(self, timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
        for binary in ("mmls", "fls", "istat"):
            if shutil.which(binary) is None:
                raise SleuthKitNotInstalled(
                    f"`{binary}` not on PATH. Install with: sudo apt install sleuthkit"
                )
        self._timeout_s = timeout_s

    def mmls(self, image: str | Path) -> PartitionTable:
        """List partitions in a disk image."""
        image = str(image)
        if not Path(image).is_file():
            raise SleuthKitFailed(f"image not found: {image}")
        proc = self._run(["mmls", image])
        partitions: list[Partition] = []
        for line in proc.stdout.splitlines():
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue
            try:
                slot, start, end, length = parts[0], int(parts[2]), int(parts[3]), int(parts[4])
                partitions.append(
                    Partition(
                        slot=slot,
                        start_sector=start,
                        end_sector=end,
                        length_sectors=length,
                        description=parts[5],
                    )
                )
            except ValueError:
                continue
        return PartitionTable(image=image, partitions=partitions, raw_output=proc.stdout)

    def fls(self, image: str | Path, offset: int = 0, inode: str | None = None) -> DirectoryListing:
        """List directory entries (and deleted files) in a filesystem."""
        image = str(image)
        if not Path(image).is_file():
            raise SleuthKitFailed(f"image not found: {image}")
        cmd = ["fls", "-o", str(offset), image]
        if inode is not None:
            cmd.append(inode)
        proc = self._run(cmd)
        entries: list[FileEntry] = []
        for line in proc.stdout.splitlines():
            # Format: "r/r * 12345-128-1: filename"  ('*' = deleted)
            line = line.strip()
            if not line:
                continue
            is_deleted = "*" in line.split(":", 1)[0]
            tokens = line.replace("*", "").split()
            if len(tokens) < 3:
                continue
            type_marker = tokens[0]
            inode_field = tokens[1].rstrip(":")
            name = " ".join(tokens[2:])
            entries.append(
                FileEntry(
                    inode=inode_field,
                    name=name,
                    is_dir=type_marker.startswith("d/"),
                    is_deleted=is_deleted,
                )
            )
        return DirectoryListing(image=image, offset=offset, entries=entries, raw_output=proc.stdout)

    def _run(self, cmd: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise SleuthKitFailed(f"{cmd[0]} timeout after {self._timeout_s}s") from e
        if proc.returncode != 0:
            raise SleuthKitFailed(f"{cmd[0]} exited {proc.returncode}: {proc.stderr.strip()[:300]}")
        return proc
