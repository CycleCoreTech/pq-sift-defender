"""CLI entry point: pq-sift-defender <command>."""

from __future__ import annotations

import contextlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

import typer
from dotenv import load_dotenv

from pq_sift_defender import __version__
from pq_sift_defender.agent.core import IRAgent
from pq_sift_defender.audit.chain import IRChain
from pq_sift_defender.clients.pq_client import PQClient
from pq_sift_defender.clients.sg_client import SGClient
from pq_sift_defender.sift.prefilter import SiftPrefilter

app = typer.Typer(help="AI-powered IR triage with PQ-signed audit trail.")


# --- ANSI styling helpers (no rich dependency required) ---

_ISATTY = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"{code}{text}\033[0m" if _ISATTY else text


def cyan(t: str) -> str:
    return _c("\033[36m", t)


def bold(t: str) -> str:
    return _c("\033[1m", t)


def dim(t: str) -> str:
    return _c("\033[2m", t)


def green(t: str) -> str:
    return _c("\033[32m", t)


def yellow(t: str) -> str:
    return _c("\033[33m", t)


def red(t: str) -> str:
    return _c("\033[31m", t)


# Visual style: cyan ══ banner boxes for major scene changes (top, verdict,
# audit chain verified). Bracketed [ caps ] markers for inline sub-sections.
# Verdict line gets full state color + bold; reasoning prose dim'd as fine
# print so the hierarchy is visible at any reading speed.

RULE_CHAR = "═"
RULE = RULE_CHAR * 58


def title_banner(title: str) -> None:
    """Top banner: cyan rule, indented bold title, cyan rule."""
    print(cyan(RULE))
    print(f"  {bold(title)}")
    print(cyan(RULE))
    print()


def scene_banner(title: str) -> None:
    """Major scene change: full cyan ═══ banner box."""
    print()
    print(cyan(RULE))
    print(f"  {bold(title)}")
    print(cyan(RULE))
    print()


def section(name: str) -> None:
    """Inline sub-section marker in cyan: `[ NAME ]`."""
    print()
    print(cyan(f"[ {name} ]"))


def closing_box() -> None:
    """Closing brand box — bordered, version + URLs."""
    rule_top = "┌" + "─" * 58 + "┐"
    rule_bot = "└" + "─" * 58 + "┘"
    blank = "│" + " " * 58 + "│"
    print()
    print(cyan(rule_top))
    print(cyan(blank))
    print(_box_row(bold(f"pq-sift-defender v{__version__}")))
    print(_box_row(dim("github.com/CycleCoreTech/pq-sift-defender")))
    print(_box_row(dim("cyclecore.ai")))
    print(cyan(blank))
    print(cyan(rule_bot))
    print()


def _box_row(content: str) -> str:
    """Box row with ANSI-aware width padding."""
    visible = len(re.sub(r"\033\[[0-9;]*m", "", content))
    pad = max(0, 56 - visible)
    return cyan("│  ") + content + " " * pad + cyan("│")


def _verdict_color(verdict_line: str) -> str:
    m = re.search(r"Verdict:\s*(BLOCK|FLAG|PASS)\b", verdict_line, re.IGNORECASE)
    if not m:
        return verdict_line
    state = m.group(1).upper()
    color = {"BLOCK": red, "FLAG": yellow, "PASS": green}[state]
    return verdict_line.replace(m.group(0), bold(color(m.group(0))), 1)


_STATE_COLOR = {"PASS": green, "FLAG": yellow, "BLOCK": red}


def _kv(label: str, value: str, width: int = 14) -> str:
    """Right-padded label + value, canonical CycleCore `Name: value` row."""
    return f"  {label:<{width}} {value}"


def _make_progress_printer() -> Any:
    """Return a callback that prints each agent event during investigation."""

    def cb(event: str, data: dict[str, Any]) -> None:
        if event == "ingest":
            rec = data.get("gate_recommendation", "?")
            risk = data.get("gate_risk_score", 0.0)
            lat = data.get("gate_latency_us", 0.0)
            color = _STATE_COLOR.get(rec, yellow)
            section("INGEST")
            print(_kv("pre-filter:", f"{color(rec)} (risk {risk:.2f}, {lat:.1f} µs)"))
            # chain_signed for ingest will print on the next event
        elif event == "tool_call":
            i = data.get("index", "?")
            name = data.get("name", "?")
            args = data.get("args") or {}
            arg_preview = ", ".join(f"{k}={str(v)[:40]}" for k, v in list(args.items())[:2])
            if i == 1:
                section("INVESTIGATE")
            print()
            label = f"[{i}] {name}"
            print(_kv(label, dim(f"({arg_preview})") if arg_preview else ""))
        elif event == "tool_result":
            summary = data.get("output_summary", "")
            elapsed = data.get("elapsed_s", 0.0)
            if "blocked at agent->tool boundary" in summary:
                marker = bold(red("!! BLOCKED at agent -> tool boundary !!"))
                print(f"      {marker}  {dim(f'({elapsed:.2f}s)')}")
                print(f"      {dim(summary)}")
            else:
                print(f"      {yellow('->')} {summary}  {dim(f'({elapsed:.2f}s)')}")
        elif event == "chain_signed":
            action = data.get("action_type", "?")
            indent = "      " if action != "ingest" else "  "
            print(f"{indent}{green('+')} {dim(f'chain entry signed [{action}]')}")
        elif event == "verdict":
            elapsed = data.get("elapsed_s", 0.0)
            tc = data.get("tool_calls", 0)
            print()
            print(_kv("elapsed:", f"{elapsed:.1f} s"))
            print(_kv("tool calls:", str(tc)))

    return cb


# --- commands ---


def _print_attacks(attacks: list[dict[str, str]]) -> None:
    """Render any MITRE ATT&CK techniques attributed during the investigation."""
    if not attacks:
        return
    print()
    print(f"  {bold(cyan('ATT&CK techniques'))}")
    for a in attacks:
        tid = a.get("id", "?")
        name = a.get("name", "?")
        source = a.get("source", "")
        print(f"  {bold(tid):<14} {name}  {dim(f'({source})') if source else ''}")


def _print_verdict(verdict_text: str, brief: bool) -> None:
    """Render the verdict with visual hierarchy.

    - First line (the canonical `Verdict: <STATE> — ...`): full color, bold.
    - Subsequent reasoning prose: dim'd gray, marked as fine print with a
      thin left rail. Skipped entirely when `brief=True`.
    """
    if not verdict_text:
        return
    lines = verdict_text.splitlines()
    first = lines[0]
    print(f"  {_verdict_color(first)}")
    if brief:
        return
    rest = [ln.rstrip() for ln in lines[1:]]
    while rest and not rest[0]:
        rest.pop(0)
    while rest and not rest[-1]:
        rest.pop()
    if not rest:
        return
    print()
    fine_print_label = "— reasoning · · · · fine print, agent's own words · · · ·"
    print(f"  {dim(fine_print_label)}")
    for line in rest:
        if line:
            print(f"  {cyan('│')} {dim(line)}")
        else:
            print(f"  {cyan('│')}")


@app.command()
def investigate(
    alert_file: Path = typer.Argument(..., help="Path to alert JSON."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress live progress output."),
    brief: bool = typer.Option(
        False,
        "--brief",
        "-b",
        help="Executive summary: only the verdict line, skip the reasoning prose.",
    ),
    thorough: bool = typer.Option(
        False,
        "--thorough",
        "-T",
        help="Require at least one DFIR tool call before accepting a verdict.",
    ),
) -> None:
    """Investigate an alert and print the verdict + audit chain summary."""
    load_dotenv()
    alert = json.loads(alert_file.read_text())

    print()
    title_banner(f"pq-sift-defender v{__version__}")
    sev = alert.get("severity", "?")
    print(f"  alert: {alert_file.name}  {dim(f'(severity: {sev})')}")

    on_progress = None if quiet else _make_progress_printer()
    with SGClient() as sg, PQClient() as pq:
        sift = SiftPrefilter(sg)
        chain = IRChain(pq=pq)
        agent = IRAgent(sift=sift, chain=chain, on_progress=on_progress)
        verdict = agent.investigate(alert, thorough=thorough)

    scene_banner("Verdict")
    _print_verdict(verdict.text, brief=brief)
    _print_attacks(verdict.attack_techniques)

    print()
    print(_kv("chain_id:", str(verdict.chain_id)))
    print(_kv("tool calls:", str(verdict.tool_calls)))
    print(_kv("blocks:", str(verdict.blocked_inputs)))
    print()


@app.command()
def audit_verify(chain_id: str) -> None:
    """Verify a chain's signature integrity via the public attestation API."""
    load_dotenv()
    with PQClient() as pq:
        result = pq.attest_verify(chain_id)
    valid = getattr(result, "valid", None)
    chain_length = getattr(result, "chain_length", None)
    latency_us = getattr(result, "latency_us", None)

    scene_banner("Audit chain verified")
    print(_kv("chain_id:", chain_id))
    state = bold(green("True")) if valid is True else bold(red(str(valid)))
    print(_kv("valid:", state))
    print(_kv("chain_length:", f"{chain_length} entries"))
    if latency_us is not None:
        print(_kv("latency:", f"{latency_us:.1f} µs"))
    print()
    callout = ">>> SIGNED WITH ML-DSA-65 (FIPS 204) — VERIFIABLE OFFLINE <<<"
    print(f"  {bold(cyan(callout))}")
    print()
    print(f"  {dim('any third party can repeat this verification with the chain_id')}")
    if valid is not True:
        raise typer.Exit(code=1)


@app.command()
def audit_export(
    chain_id: str,
    out: Path | None = typer.Option(
        None, "--out", "-o", help="Write JSON to this file (default: stdout)."
    ),
) -> None:
    """Export a chain to JSON via the public attestation API."""
    load_dotenv()
    with PQClient() as pq:
        result = pq.attest_export(chain_id)
    payload = {
        "chain_id": getattr(result, "chain_id", chain_id),
        "chain_length": getattr(result, "chain_length", None),
        "latency_us": getattr(result, "latency_us", None),
        "entries": getattr(result, "entries", None),
    }
    if isinstance(payload["entries"], str):
        with contextlib.suppress(json.JSONDecodeError):
            payload["entries"] = json.loads(payload["entries"])
    text = json.dumps(payload, indent=2, sort_keys=True)
    if out is None:
        print(text)
    else:
        out.write_text(text)
        section("AUDIT CHAIN EXPORT")
        entries = payload.get("entries") or []
        n = len(entries) if isinstance(entries, list) else "?"
        print(_kv("file:", str(out)))
        print(_kv("size:", f"{len(text):,} bytes"))
        print(_kv("entries:", str(n)))
        print(f"  {dim('one entry per IR action -- ingest, each tool call, verdict')}")
        print()


@app.command()
def demo(
    sample: Path = typer.Option(
        Path("samples/path_traversal.json"),
        "--sample",
        "-s",
        help="Sample alert to investigate.",
    ),
    timeout_s: int = typer.Option(
        300,
        "--timeout",
        "-t",
        help="LLM call timeout in seconds. Higher than default for stable recording.",
    ),
    brief: bool = typer.Option(
        False,
        "--brief",
        "-b",
        help="Skip the agent's reasoning prose; show only the verdict line.",
    ),
) -> None:
    """Curated end-to-end walkthrough — investigate, verify, export.

    Runs a full sample investigation, then verifies the resulting audit
    chain. Designed for screen recording / asciinema.
    """
    load_dotenv()
    alert = json.loads(sample.read_text())

    from ollama import Client as _OllamaClient

    from pq_sift_defender.agent.core import _env

    ollama_host = _env("LLM_HOST", "http://localhost:11434")

    print()
    title_banner(f"pq-sift-defender v{__version__}")
    sev = alert.get("severity", "?")
    print(f"  alert: {sample.name}  {dim(f'(severity: {sev})')}")
    time.sleep(1)

    with SGClient() as sg, PQClient() as pq:
        sift = SiftPrefilter(sg)
        chain = IRChain(pq=pq)
        ollama_client = _OllamaClient(host=ollama_host, timeout=float(timeout_s))
        agent = IRAgent(
            sift=sift,
            chain=chain,
            ollama_client=ollama_client,
            on_progress=_make_progress_printer(),
        )
        verdict = agent.investigate(alert)
        time.sleep(2)

        scene_banner("Verdict")
        _print_verdict(verdict.text, brief=brief)
        _print_attacks(verdict.attack_techniques)
        print()
        print(_kv("chain_id:", str(verdict.chain_id)))
        print(_kv("tool calls:", str(verdict.tool_calls)))
        time.sleep(3)

        scene_banner("Audit chain verified")
        v = pq.attest_verify(verdict.chain_id) if verdict.chain_id else None
        valid = getattr(v, "valid", None)
        cl = getattr(v, "chain_length", None)
        lat = getattr(v, "latency_us", None)
        state = bold(green("True")) if valid is True else bold(red(str(valid)))
        print(_kv("chain_id:", str(verdict.chain_id)))
        print(_kv("valid:", state))
        print(_kv("chain_length:", f"{cl} entries  {dim('(ingest · tool · verdict)')}"))
        if lat is not None:
            print(_kv("latency:", f"{lat:.1f} µs"))
        print()
        callout = ">>> SIGNED WITH ML-DSA-65 (FIPS 204) — VERIFIABLE OFFLINE <<<"
        print(f"  {bold(cyan(callout))}")
        time.sleep(3)

    closing_box()


if __name__ == "__main__":
    app()
