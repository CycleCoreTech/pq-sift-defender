"""Microsecond pre-filter for agent inputs and tool outputs.

Sits in front of the agent's reasoning loop and after each tool call:
- Scans the alert payload entering the agent (defends against
  prompt-injection-driven attacks via the input itself)
- Scans tool inputs the agent generates (defends against the agent
  being manipulated into emitting attack payloads to downstream tools)

Backed by the public CycleCore SecurityGates API.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pq_sift_defender.clients.sg_client import ScanResult, SGClient


@dataclass
class FilterDecision:
    allow: bool
    scan: ScanResult


class SiftPrefilter:
    """Microsecond pre-filter wrapping SGClient."""

    def __init__(self, sg: SGClient) -> None:
        self._sg = sg

    def check_text(self, text: str) -> FilterDecision:
        """Check a raw text input. Block on BLOCK; allow PASS and FLAG."""
        result = self._sg.scan_text(text)
        return FilterDecision(allow=result.recommendation != "BLOCK", scan=result)

    def check_dict(self, payload: dict[str, Any]) -> FilterDecision:
        """Recursively scan all string values in a dict payload."""
        text = " ".join(_extract_strings(payload))
        return self.check_text(text)


def _extract_strings(obj: Any, depth: int = 0, max_depth: int = 10) -> list[str]:
    if depth > max_depth:
        return []
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        out: list[str] = []
        for v in obj.values():
            out.extend(_extract_strings(v, depth + 1, max_depth))
        return out
    if isinstance(obj, list | tuple):
        out = []
        for v in obj:
            out.extend(_extract_strings(v, depth + 1, max_depth))
        return out
    return []
