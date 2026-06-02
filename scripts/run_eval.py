"""End-to-end evaluation: run the agent against every sample alert.

Captures verdicts, audit chains, and timing. Writes a markdown accuracy
report to docs/accuracy.md. Writes raw execution logs to agent_logs/.

Usage:
    python scripts/run_eval.py
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from dotenv import load_dotenv

from pq_sift_defender.agent.core import IRAgent, Verdict
from pq_sift_defender.audit.chain import IRChain
from pq_sift_defender.clients.pq_client import PQClient
from pq_sift_defender.clients.sg_client import SGClient
from pq_sift_defender.sift.prefilter import SiftPrefilter

REPO = Path(__file__).resolve().parent.parent
SAMPLES_DIR = REPO / "samples"
LOGS_DIR = REPO / "agent_logs"
DOCS_DIR = REPO / "docs"

# Each sample's expected verdict shape — used to grade reasoning quality.
EXPECTED_VERDICT = {
    "ssrf_sqli_probe.json": "BLOCK",
    "path_traversal.json": "BLOCK",
    "command_injection.json": "BLOCK",
    "benign_login_alert.json": "PASS",
    "malware_memory_dump.json": "BLOCK",
    "prompt_injection_alert.json": "BLOCK",
    "cloud_metadata_ssrf.json": "BLOCK",
    "multi_vector_attack.json": "BLOCK",
    "shadow_file_read.json": "BLOCK",
    "clean_health_check.json": "PASS",
}


class StubChain:
    """In-memory chain stub used when /v1/attest is unavailable.

    Records the same shape of entries as the real IRChain so accuracy
    reporting and execution-log capture work identically.
    """

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []
        self.chain_id = f"local-{int(time.time())}"

    def append(self, action_type: str, payload: dict[str, Any]) -> SimpleNamespace:
        self.entries.append(
            {
                "action_type": action_type,
                "ts": datetime.now(timezone.utc).isoformat(),
                "payload": payload,
            }
        )
        return SimpleNamespace(
            chain_id=self.chain_id,
            entry_index=len(self.entries) - 1,
            entry_hash=f"local-h{len(self.entries)}",
        )


_VERDICT_LINE = re.compile(r"^\s*Verdict:\s*(BLOCK|FLAG|PASS)\b", re.IGNORECASE | re.MULTILINE)


def _extract_verdict(verdict_text: str) -> str | None:
    """Parse the canonical 'Verdict: <X>' line. Return BLOCK / FLAG / PASS / None."""
    match = _VERDICT_LINE.search(verdict_text)
    if match:
        return match.group(1).upper()
    return None


def _grade(verdict_text: str, expected: str) -> str:
    parsed = _extract_verdict(verdict_text)
    if parsed is not None:
        if expected == "BLOCK":
            return "OK" if parsed in ("BLOCK", "FLAG") else "WEAK"
        if expected == "PASS":
            return "OK" if parsed == "PASS" else "OVERREACTION"
        return "?"
    # Fallback: substring match for verdicts that didn't follow format.
    upper = verdict_text.upper()
    if expected == "BLOCK":
        positive_signals = ("BLOCK", "MALICIOUS", "ATTACK", "INCIDENT", "FLAG", "INVESTIGATE")
        return "OK" if any(s in upper for s in positive_signals) else "WEAK"
    if expected == "PASS":
        negative_signals = (" BLOCK", "MALICIOUS", "ATTACK", "INCIDENT")
        return "OK" if not any(s in upper for s in negative_signals) else "OVERREACTION"
    return "?"


def _serialize(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    if hasattr(obj, "__dict__"):
        return {k: _serialize(v) for k, v in obj.__dict__.items() if not k.startswith("_")}
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [_serialize(v) for v in obj]
    if isinstance(obj, str | int | float | bool) or obj is None:
        return obj
    return str(obj)


def _build_chain(use_live: bool) -> Any:
    """Return an IRChain backed by /v1/attest, or a StubChain fallback."""
    if not use_live:
        return StubChain()
    try:
        return IRChain(pq=PQClient())
    except Exception as e:
        print(f"  ! IRChain unavailable ({e}); falling back to StubChain")
        return StubChain()


def _chain_index(chain: Any) -> list[dict[str, Any]]:
    """Return a serializable view of the chain's local index."""
    if isinstance(chain, StubChain):
        return chain.entries
    return [
        {
            "entry_index": e.entry_index,
            "action_type": e.action_type,
            "entry_hash": e.entry_hash,
            "ts": e.timestamp,
        }
        for e in chain._index
    ]


def run_one(alert_path: Path, use_live_chain: bool) -> dict[str, Any]:
    alert = json.loads(alert_path.read_text())
    expected = EXPECTED_VERDICT.get(alert_path.name, "?")
    with SGClient(timeout_s=10.0) as sg:
        sift = SiftPrefilter(sg)
        chain = _build_chain(use_live_chain)
        agent = IRAgent(sift=sift, chain=chain)
        t0 = time.time()
        try:
            verdict: Verdict = agent.investigate(alert)
            elapsed = time.time() - t0
            grade = _grade(verdict.text, expected)
            error = None
        except Exception as e:
            elapsed = time.time() - t0
            verdict = Verdict(text=f"(error: {e})", chain_id=None, tool_calls=0, blocked_inputs=0)
            grade = "ERROR"
            error = str(e)
    entries = _chain_index(chain)
    return {
        "alert": alert_path.name,
        "expected": expected,
        "elapsed_s": round(elapsed, 1),
        "tool_calls": verdict.tool_calls,
        "blocked_inputs": verdict.blocked_inputs,
        "prompt_tokens": verdict.prompt_tokens,
        "completion_tokens": verdict.completion_tokens,
        "attack_techniques": verdict.attack_techniques,
        "verdict_text": verdict.text,
        "verdict_text_truncated": verdict.text[:200],
        "grade": grade,
        "chain_id": chain.chain_id,
        "chain_backend": "IRChain" if isinstance(chain, IRChain) else "StubChain",
        "audit_chain_length": len(entries),
        "audit_chain": entries,
        "transcript": _serialize(verdict.transcript),
        "error": error,
    }


def write_accuracy_report(results: list[dict[str, Any]]) -> Path:
    ok = sum(1 for r in results if r["grade"] == "OK")
    weak = sum(1 for r in results if r["grade"] == "WEAK")
    overreact = sum(1 for r in results if r["grade"] == "OVERREACTION")
    error = sum(1 for r in results if r["grade"] == "ERROR")
    avg_elapsed = sum(r["elapsed_s"] for r in results) / max(1, len(results))
    avg_tool_calls = sum(r["tool_calls"] for r in results) / max(1, len(results))

    model = os.environ.get("LLM_MODEL", "qwen2.5:1.5b")
    md = [
        "# Accuracy Report",
        "",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
        f"**Model:** `{model}` (CPU-only)",
        "",
        "## Summary",
        "",
        f"- Cases run: **{len(results)}**",
        f"- Correct verdicts (OK): **{ok}** ({ok / max(1, len(results)) * 100:.0f}%)",
        f"- Weak (failed to identify threat): **{weak}**",
        f"- Overreactions (false alarms): **{overreact}**",
        f"- Errors: **{error}**",
        f"- Average elapsed: **{avg_elapsed:.1f}s** per case",
        f"- Average tool calls per case: **{avg_tool_calls:.1f}**",
        "",
        "## Per-case results",
        "",
        "| Case | Expected | Grade | Tool calls | Elapsed | ATT&CK |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        attacks = r.get("attack_techniques") or []
        attack_cell = ", ".join(a.get("id", "?") for a in attacks) if attacks else "—"
        md.append(
            f"| `{r['alert']}` | {r['expected']} | {r['grade']} | "
            f"{r['tool_calls']} | {r['elapsed_s']}s | {attack_cell} |"
        )
    backends = sorted({r.get("chain_backend", "StubChain") for r in results})
    chain_note = (
        "live `/v1/attest` (ML-DSA-65 server-signed entries)"
        if backends == ["IRChain"]
        else f"audit chain backend: {', '.join(backends)}"
    )
    md.extend(
        [
            "",
            "## Methodology",
            "",
            "Each case is a synthetic alert payload from `samples/`. The agent runs",
            "to verdict using the configured Ollama-served model (CPU-only) with the",
            f"SecurityGates pre-filter active and {chain_note}.",
            "",
            "Grading parses the canonical `Verdict: BLOCK | FLAG | PASS` line from",
            "the agent's final message:",
            "",
            "- `OK` — verdict matches expectation (`BLOCK` or `FLAG` for incidents,",
            "  `PASS` for benign).",
            "- `WEAK` — incident expected but verdict said `PASS`.",
            "- `OVERREACTION` — benign expected but verdict said `BLOCK` or `FLAG`.",
            "- `ERROR` — agent loop raised.",
            "",
            "If the agent's message lacks the canonical line, grading falls back to",
            "substring matching for tolerance.",
        ]
    )
    out = DOCS_DIR / "accuracy.md"
    out.write_text("\n".join(md))
    return out


def write_execution_logs(results: list[dict[str, Any]]) -> Path:
    LOGS_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = LOGS_DIR / f"eval-{ts}.jsonl"
    with out.open("w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")
    return out


def main() -> None:
    load_dotenv()
    use_live = os.environ.get("PQ_AUDIT_BACKEND", "live").lower() != "stub"
    backend_label = "live IRChain (/v1/attest)" if use_live else "StubChain"
    # Only run files that are real alert samples — not artifacts that happen
    # to live in samples/ (e.g. audit_chain_export.json is the proof artifact).
    samples = sorted(p for p in SAMPLES_DIR.glob("*.json") if p.name in EXPECTED_VERDICT)
    print(f"Running {len(samples)} cases against {backend_label}...\n")
    results: list[dict[str, Any]] = []
    for path in samples:
        print(f"  → {path.name} ... ", end="", flush=True)
        result = run_one(path, use_live_chain=use_live)
        print(
            f"{result['grade']:<14} ({result['elapsed_s']}s, "
            f"{result['tool_calls']} tool call{'' if result['tool_calls'] == 1 else 's'}, "
            f"{result['audit_chain_length']} chain entries)"
        )
        results.append(result)
    accuracy_path = write_accuracy_report(results)
    logs_path = write_execution_logs(results)
    print(f"\nReports written:\n  {accuracy_path}\n  {logs_path}")


if __name__ == "__main__":
    main()
