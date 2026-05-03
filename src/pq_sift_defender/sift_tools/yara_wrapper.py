"""Wrapper for YARA malware-signature matching.

Uses the `yara-python` library directly (no subprocess). Compiles rule
strings or rule files; matches against file paths or in-memory bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yara


class YARAFailed(RuntimeError):
    pass


@dataclass
class YARAMatch:
    rule: str
    namespace: str
    tags: list[str]
    meta: dict[str, str | int]
    strings_matched: int


@dataclass
class ScanReport:
    target: str
    match_count: int
    matches: list[YARAMatch]


class YARAClient:
    """Compile + match interface around yara-python."""

    def __init__(self) -> None:
        self._compiled: yara.Rules | None = None

    # --- compilation ---

    def compile_source(self, rule_text: str) -> None:
        """Compile rules from a single source string."""
        try:
            self._compiled = yara.compile(source=rule_text)
        except yara.SyntaxError as e:
            raise YARAFailed(f"YARA syntax error: {e}") from e

    def compile_files(self, rule_files: dict[str, str]) -> None:
        """Compile rules from {namespace: filepath} mapping."""
        try:
            self._compiled = yara.compile(filepaths=rule_files)
        except yara.SyntaxError as e:
            raise YARAFailed(f"YARA syntax error: {e}") from e
        except yara.Error as e:
            raise YARAFailed(f"YARA compile error: {e}") from e

    # --- matching ---

    def scan_file(self, target: str | Path) -> ScanReport:
        """Match compiled rules against a file."""
        if self._compiled is None:
            raise YARAFailed("no rules compiled — call compile_source/compile_files first")
        target = str(target)
        if not Path(target).is_file():
            raise YARAFailed(f"target not found: {target}")
        try:
            raw_matches = self._compiled.match(target)
        except yara.Error as e:
            raise YARAFailed(f"YARA match error: {e}") from e
        return self._wrap(target, raw_matches)

    def scan_data(self, data: bytes, label: str = "<bytes>") -> ScanReport:
        """Match compiled rules against in-memory bytes."""
        if self._compiled is None:
            raise YARAFailed("no rules compiled — call compile_source/compile_files first")
        try:
            raw_matches = self._compiled.match(data=data)
        except yara.Error as e:
            raise YARAFailed(f"YARA match error: {e}") from e
        return self._wrap(label, raw_matches)

    @staticmethod
    def _wrap(target: str, raw: list) -> ScanReport:
        matches: list[YARAMatch] = []
        for m in raw:
            matches.append(
                YARAMatch(
                    rule=m.rule,
                    namespace=getattr(m, "namespace", "default"),
                    tags=list(getattr(m, "tags", [])),
                    meta=dict(getattr(m, "meta", {})),
                    strings_matched=len(getattr(m, "strings", [])),
                )
            )
        return ScanReport(target=target, match_count=len(matches), matches=matches)
