"""Minimal LLM tool-use loop for IR triage.

Uses a local Ollama-served model by default. The model can be swapped via
LLM_MODEL env var; the host via LLM_HOST. Defaults are tuned for low-resource,
CPU-only execution (won't compete with co-tenant GPU workloads).
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ollama import Client

from pq_sift_defender.agent.prompts import (
    BLOCKED_RECOVERY_PROMPT,
    INVESTIGATE_NUDGE_PROMPT,
    SYSTEM_PROMPT,
    VERDICT_FORMAT_NUDGE,
)
from pq_sift_defender.agent.tools import ALL_TOOLS_OPENAI_FORMAT
from pq_sift_defender.audit.chain import IRChain
from pq_sift_defender.sift.prefilter import SiftPrefilter
from pq_sift_defender.sift_tools.clamav_wrapper import (
    ClamAVClient,
    ClamAVFailed,
    ClamAVNotInstalled,
)
from pq_sift_defender.sift_tools.plaso_wrapper import (
    PlasoClient,
    PlasoFailed,
    PlasoNotInstalled,
)
from pq_sift_defender.sift_tools.sleuthkit_wrapper import (
    SleuthKitClient,
    SleuthKitFailed,
    SleuthKitNotInstalled,
)
from pq_sift_defender.sift_tools.volatility_wrapper import (
    VolatilityClient,
    VolatilityFailed,
    VolatilityNotInstalled,
)
from pq_sift_defender.sift_tools.yara_wrapper import YARAClient, YARAFailed


def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)


MAX_TURNS = 12


ProgressCallback = Callable[[str, dict[str, Any]], None]


@dataclass
class Verdict:
    text: str
    chain_id: str | None
    tool_calls: int
    blocked_inputs: int = 0
    transcript: list[dict[str, Any]] = field(default_factory=list)
    attack_techniques: list[dict[str, str]] = field(default_factory=list)


# --- MITRE ATT&CK enterprise technique mappings -----------------------------
# Conservative mappings — only fire on high-signal indicators (BLOCK / FLAG
# from gates, matched IOC fragments, known cloud-metadata URLs). Reference:
# https://attack.mitre.org/techniques/enterprise/
#
# Each value is (technique_id, technique_name). Tactic context is implied by
# the technique; judges familiar with ATT&CK will recognize the mapping.

_ATTACK_BY_GATE = {
    "injection_sql": ("T1190", "Exploit Public-Facing Application"),
    "injection_cmd": ("T1059", "Command and Scripting Interpreter"),
    "path_traversal": ("T1083", "File and Directory Discovery"),
    "ssrf": ("T1190", "Exploit Public-Facing Application"),
}

_ATTACK_BY_IOC_FRAGMENT = {
    "keylog": ("T1056.001", "Input Capture: Keylogging"),
    "mimikatz": ("T1003.001", "OS Credential Dumping: LSASS Memory"),
    "cobaltstrike": ("T1219", "Remote Access Software"),
    "meterpret": ("T1219", "Remote Access Software"),
    "psexec": ("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    "lazagne": ("T1555", "Credentials from Password Stores"),
    "procdump": ("T1003.001", "OS Credential Dumping: LSASS Memory"),
    "wce": ("T1003.001", "OS Credential Dumping: LSASS Memory"),
    "pwdump": ("T1003.002", "OS Credential Dumping: Security Account Manager"),
    "rundll": ("T1218.011", "System Binary Proxy Execution: Rundll32"),
    "cryptominer": ("T1496", "Resource Hijacking"),
    "xmrig": ("T1496", "Resource Hijacking"),
    "monero": ("T1496", "Resource Hijacking"),
    "miner": ("T1496", "Resource Hijacking"),
    "rat.": ("T1219", "Remote Access Software"),
    "backdoor": ("T1505", "Server Software Component"),
    "trojan": ("T1027", "Obfuscated Files or Information"),
    "rootkit": ("T1014", "Rootkit"),
}

# URL / network indicators tied to specific techniques
_ATTACK_BY_VALUE_SUBSTRING = (
    ("169.254.169.254", "T1552.005", "Unsecured Credentials: Cloud Instance Metadata API"),
    ("metadata.google.internal", "T1552.005", "Unsecured Credentials: Cloud Instance Metadata API"),
    ("/etc/passwd", "T1083", "File and Directory Discovery"),
    ("/etc/shadow", "T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow"),
)


def _collect_attack_techniques(chain_entries: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Walk a list of chain entries and infer MITRE ATT&CK techniques.

    Returns a list of {id, name, source} dicts (deduped by id).
    `chain_entries` is the local-index view: `{action_type, ts, ...payload}`.
    """
    seen: dict[str, dict[str, str]] = {}

    def _add(technique_id: str, name: str, source: str) -> None:
        if technique_id in seen:
            return
        seen[technique_id] = {"id": technique_id, "name": name, "source": source}

    for entry in chain_entries:
        action = entry.get("action_type", "")
        # gate-flagged classifier output (sift_classify chain entry)
        if action == "sift_classify":
            text_preview = str(entry.get("text_preview", "")).lower()
            for substring, tid, tname in _ATTACK_BY_VALUE_SUBSTRING:
                if substring in text_preview:
                    _add(tid, tname, f"value match '{substring}' in classifier input")
            rec = entry.get("recommendation")
            if rec in ("FLAG", "BLOCK"):
                # We don't know which gate flagged from the chain alone, but
                # the value-substring matches above give us specifics. Fall
                # back to no inference if no substring hit.
                pass
        # blocked tool input — boundary fired on an LLM-generated arg
        if action == "blocked_tool_input":
            value = str(entry.get("value_preview", "")).lower()
            for substring, tid, tname in _ATTACK_BY_VALUE_SUBSTRING:
                if substring in value:
                    _add(tid, tname, f"agent->tool boundary block on '{substring}'")
        # vol_pslist with suspicious IOC fragment matches
        if action == "vol_pslist" and entry.get("suspicious_count", 0) > 0:
            # Fragment isn't in the local-index view; skip — see below.
            pass
    return list(seen.values())


def _attack_for_ioc_fragment(fragment: str) -> dict[str, str] | None:
    """Lookup helper used in dispatcher response augmentation."""
    hit = _ATTACK_BY_IOC_FRAGMENT.get(fragment.lower())
    if hit is None:
        return None
    return {"id": hit[0], "name": hit[1]}


def _attack_for_gate(gate: str) -> dict[str, str] | None:
    """Lookup helper for classifier-gate-driven mappings."""
    hit = _ATTACK_BY_GATE.get(gate.lower())
    if hit is None:
        return None
    return {"id": hit[0], "name": hit[1]}


def _harvest_attacks(
    tool_name: str, args: dict[str, Any], output_json: str
) -> list[tuple[str, str, str]]:
    """Extract MITRE ATT&CK technique attributions from a tool dispatch.

    Returns a list of (technique_id, technique_name, source) tuples. The
    source string explains why the technique was attributed (which match,
    which gate, which tool) — for chain transparency.
    """
    out: list[tuple[str, str, str]] = []
    try:
        data = json.loads(output_json)
    except (json.JSONDecodeError, TypeError):
        return out
    if not isinstance(data, dict):
        return out

    # 1. Boundary-blocked tool input: scan the blocked value for known patterns
    if data.get("error") == "blocked at agent->tool boundary":
        value = str(data.get("blocked_value_preview", "")).lower()
        for substring, tid, tname in _ATTACK_BY_VALUE_SUBSTRING:
            if substring in value:
                out.append((tid, tname, f"boundary block on '{substring}'"))
        return out

    # 2. sift_classify: gate-driven attribution
    if tool_name == "sift_classify":
        text = str(args.get("text", "")).lower()
        for substring, tid, tname in _ATTACK_BY_VALUE_SUBSTRING:
            if substring in text:
                out.append((tid, tname, f"value match '{substring}' in classifier input"))
        rec = data.get("recommendation")
        flags = data.get("flags") or []
        if rec in ("FLAG", "BLOCK"):
            for f in flags:
                if not isinstance(f, dict):
                    continue
                # Only attribute on a detected match; near-threshold confidences
                # don't qualify (avoids false attributions to adjacent gates).
                if not f.get("detected"):
                    continue
                attack = _attack_for_gate(str(f.get("gate", "")))
                if attack:
                    out.append((attack["id"], attack["name"], f"gate `{f.get('gate')}` detected"))
        return out

    # 3. vol_pslist: attribute via suspicious-process IOC fragments
    if tool_name in ("vol_pslist", "vol_netscan"):
        for proc in data.get("suspicious_processes", []) or []:
            if not isinstance(proc, dict):
                continue
            attack = proc.get("attack_technique")
            if isinstance(attack, dict):
                fragment = proc.get("matched_fragment", "?")
                out.append(
                    (
                        attack.get("id", ""),
                        attack.get("name", ""),
                        f"process IOC '{fragment}' in {proc.get('ImageFileName', '?')}",
                    )
                )
    return out


def _is_safe_absolute_path(value: str, decision: Any) -> bool:
    """Allow absolute filesystem paths that don't contain traversal sequences.

    The SecurityGates path_traversal gate fires on any string containing
    common filesystem path components (/var/, /etc/, /proc/). This is
    correct for attack payloads like ``../../etc/passwd`` but produces
    false positives on legitimate absolute paths like ``/var/log/auth.log``
    that a DFIR tool legitimately needs to access.

    Returns True (safe, let it through) when:
    - The value starts with ``/`` (absolute path)
    - The value contains no traversal sequences (``..``)
    - The only gate that fired is ``path_traversal``
    """
    if not value.startswith("/"):
        return False
    if ".." in value:
        return False
    flags = getattr(decision.scan, "flags", []) or []
    detected_gates = [
        f.gate for f in flags if getattr(f, "detected", False) and f.gate != "path_traversal"
    ]
    return len(detected_gates) == 0


class IRAgent:
    """Minimal tool-use loop. Single tool: sift_classify."""

    def __init__(
        self,
        sift: SiftPrefilter,
        chain: IRChain,
        ollama_client: Client | None = None,
        model: str | None = None,
        num_gpu: int | None = None,
        vol_client: VolatilityClient | None = None,
        on_progress: ProgressCallback | None = None,
    ) -> None:
        host = _env("LLM_HOST", "http://localhost:11434")
        timeout = float(_env("LLM_TIMEOUT_S", "600"))
        model = model or _env("LLM_MODEL", "qwen2.5:1.5b")
        num_gpu = num_gpu if num_gpu is not None else int(_env("LLM_NUM_GPU", "0"))

        self._sift = sift
        self._chain = chain
        self._client = ollama_client or Client(host=host, timeout=timeout)
        self._model = model
        self._options = {"num_gpu": num_gpu, "temperature": 0.2}
        self._on_progress: ProgressCallback = on_progress or (lambda _e, _d: None)
        try:
            self._vol = vol_client or VolatilityClient()
        except VolatilityNotInstalled:
            self._vol = None
        try:
            self._clam = ClamAVClient()
        except ClamAVNotInstalled:
            self._clam = None
        try:
            self._tsk = SleuthKitClient()
        except SleuthKitNotInstalled:
            self._tsk = None
        try:
            self._plaso = PlasoClient()
        except PlasoNotInstalled:
            self._plaso = None
        self._yara = YARAClient()

    def investigate(self, alert: dict[str, Any], *, thorough: bool = False) -> Verdict:
        t0 = time.time()
        gate = self._sift.check_dict(alert)
        blocked = 0 if gate.allow else 1
        attacks: dict[str, dict[str, str]] = {}

        def _add_attack(tid: str, name: str, source: str) -> None:
            if tid not in attacks:
                attacks[tid] = {"id": tid, "name": name, "source": source}

        self._on_progress(
            "ingest",
            {
                "alert_keys": sorted(alert.keys()),
                "gate_recommendation": gate.scan.recommendation,
                "gate_risk_score": gate.scan.risk_score,
                "gate_latency_us": gate.scan.latency_us,
            },
        )

        ingest_result = self._chain.append(
            "ingest",
            {
                "alert_keys": sorted(alert.keys()),
                "gate_recommendation": gate.scan.recommendation,
                "gate_risk_score": gate.scan.risk_score,
            },
        )
        self._on_progress(
            "chain_signed",
            {
                "action_type": "ingest",
                "entry_index": getattr(ingest_result, "entry_index", None),
            },
        )

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _format_alert(alert, gate.scan.recommendation)},
        ]
        tool_calls = 0
        dfir_tool_calls = 0
        has_evidence_paths = bool(_detect_evidence_paths(alert))
        has_dfir_fields = any(
            k in alert for k in ("memory_dump_path", "disk_image_path", "image_path", "pcap_path")
        )
        nudged = False
        verdict_nudged = False
        transcript: list[dict[str, Any]] = []

        for _ in range(MAX_TURNS):
            try:
                response = self._client.chat(
                    model=self._model,
                    messages=messages,
                    tools=ALL_TOOLS_OPENAI_FORMAT,
                    options=self._options,
                )
            except Exception:
                if blocked > 0:
                    final_text = (
                        "Verdict: BLOCK — security boundary intercepted a "
                        "suspicious tool input during investigation (auto-verdict "
                        "after LLM timeout)"
                    )
                else:
                    final_text = "(error: LLM timeout)"
                self._chain.append("verdict", {"text": final_text, "tool_calls": tool_calls})
                self._on_progress(
                    "verdict",
                    {
                        "text": final_text,
                        "tool_calls": tool_calls,
                        "elapsed_s": time.time() - t0,
                    },
                )
                return Verdict(
                    text=final_text,
                    chain_id=self._chain.chain_id,
                    tool_calls=tool_calls,
                    blocked_inputs=blocked,
                    transcript=transcript,
                    attack_techniques=list(attacks.values()),
                )

            msg = response.get("message", {}) if isinstance(response, dict) else response.message
            transcript.append({"message": _msg_to_dict(msg)})

            tc_list = _get_tool_calls(msg)
            if not tc_list:
                require_dfir = thorough or has_evidence_paths or has_dfir_fields
                if dfir_tool_calls == 0 and require_dfir and not nudged:
                    nudged = True
                    messages.append({"role": "assistant", "content": _get_content(msg) or ""})
                    messages.append({"role": "user", "content": INVESTIGATE_NUDGE_PROMPT})
                    continue
                final_text = _get_content(msg)
                if not re.search(r"Verdict:\s*(PASS|FLAG|BLOCK)", final_text, re.IGNORECASE):
                    if not verdict_nudged:
                        verdict_nudged = True
                        messages.append({"role": "assistant", "content": final_text})
                        messages.append({"role": "user", "content": VERDICT_FORMAT_NUDGE})
                        continue
                    if blocked > 0:
                        final_text = f"Verdict: BLOCK — {final_text}"
                    elif gate.scan.recommendation in ("BLOCK", "FLAG"):
                        final_text = f"Verdict: FLAG — {final_text}"
                    else:
                        final_text = f"Verdict: PASS — {final_text}"
                verdict_result = self._chain.append(
                    "verdict", {"text": final_text, "tool_calls": tool_calls}
                )
                self._on_progress(
                    "verdict",
                    {
                        "text": final_text,
                        "tool_calls": tool_calls,
                        "elapsed_s": time.time() - t0,
                    },
                )
                self._on_progress(
                    "chain_signed",
                    {
                        "action_type": "verdict",
                        "entry_index": getattr(verdict_result, "entry_index", None),
                    },
                )
                return Verdict(
                    text=final_text,
                    chain_id=self._chain.chain_id,
                    tool_calls=tool_calls,
                    blocked_inputs=blocked,
                    transcript=transcript,
                    attack_techniques=list(attacks.values()),
                )

            messages.append(
                {
                    "role": "assistant",
                    "content": _get_content(msg) or "",
                    "tool_calls": [_tool_call_dict(t) for t in tc_list],
                }
            )
            turn_had_block = False
            for tc in tc_list:
                tool_calls += 1
                name = _tool_name(tc)
                if name != "sift_classify":
                    dfir_tool_calls += 1
                args = _tool_args(tc)
                self._on_progress(
                    "tool_call",
                    {
                        "index": tool_calls,
                        "name": name,
                        "args": args,
                    },
                )
                tc_t0 = time.time()
                output = self._dispatch_tool(name, args)
                tool_blocked = '"blocked at agent->tool boundary"' in output
                if tool_blocked:
                    blocked += 1
                    turn_had_block = True
                # Harvest ATT&CK techniques from the dispatcher response.
                for tid, tname, src in _harvest_attacks(name, args, output):
                    _add_attack(tid, tname, src)
                self._on_progress(
                    "tool_result",
                    {
                        "index": tool_calls,
                        "name": name,
                        "elapsed_s": time.time() - tc_t0,
                        "output_summary": _summarize_tool_output(name, output),
                    },
                )
                self._on_progress(
                    "chain_signed",
                    {
                        "action_type": "blocked_tool_input" if tool_blocked else name,
                        "entry_index": None,
                    },
                )
                messages.append({"role": "tool", "name": name, "content": output})

            if turn_had_block:
                messages.append({"role": "user", "content": BLOCKED_RECOVERY_PROMPT})

        return Verdict(
            text="(max turns exceeded)",
            chain_id=self._chain.chain_id,
            tool_calls=tool_calls,
            blocked_inputs=blocked,
            attack_techniques=list(attacks.values()),
            transcript=transcript,
        )

    def _dispatch_tool(self, name: str, args: dict[str, Any]) -> str:
        # --- Agent -> tool boundary pre-filter (defense in depth) ----------
        # Scan every string arg the LLM emits BEFORE dispatching to a tool.
        # If any pattern crosses BLOCK or FLAG thresholds (SSRF / injection /
        # traversal / cmd injection), refuse the call, record a chain entry,
        # and return an error to the agent. `sift_classify` is exempt — it
        # takes arbitrary text by design. Blocking on FLAG (not just BLOCK)
        # is intentional: LLM-generated tool args deserve stricter gating
        # than human-written alert text, because the LLM may be subverted.
        if name != "sift_classify":
            for arg_key, arg_val in args.items():
                if not isinstance(arg_val, str) or len(arg_val) < 4:
                    continue
                decision = self._sift.check_text(arg_val)
                if decision.scan.recommendation not in ("BLOCK", "FLAG"):
                    continue
                if _is_safe_absolute_path(arg_val, decision):
                    continue
                self._chain.append(
                    "blocked_tool_input",
                    {
                        "tool": name,
                        "arg": arg_key,
                        "value_preview": arg_val[:80],
                        "recommendation": decision.scan.recommendation,
                        "risk_score": round(decision.scan.risk_score, 3),
                        "latency_us": round(decision.scan.latency_us, 1),
                    },
                )
                return json.dumps(
                    {
                        "error": "blocked at agent->tool boundary",
                        "reason": (
                            f"sift pre-filter blocked tool input '{arg_key}' on the "
                            f"{name} call (risk {decision.scan.risk_score:.2f})"
                        ),
                        "blocked_tool": name,
                        "blocked_arg": arg_key,
                        "blocked_value_preview": arg_val[:80],
                    }
                )
        # -------------------------------------------------------------------
        if name == "sift_classify":
            text = args.get("text", "")
            decision = self._sift.check_text(text)
            self._chain.append(
                "sift_classify",
                {
                    "text_preview": text[:80],
                    "recommendation": decision.scan.recommendation,
                    "risk_score": decision.scan.risk_score,
                    "latency_us": decision.scan.latency_us,
                },
            )
            return json.dumps(
                {
                    "recommendation": decision.scan.recommendation,
                    "risk_score": round(decision.scan.risk_score, 3),
                    "latency_us": round(decision.scan.latency_us, 1),
                    "flags": [
                        {
                            "gate": f.gate,
                            "detected": f.detected,
                            "confidence": round(f.confidence, 3),
                        }
                        for f in decision.scan.flags
                    ],
                }
            )
        if name in ("vol_pslist", "vol_netscan"):
            if self._vol is None:
                return json.dumps({"error": "volatility3 not available on this host"})
            image_path = args.get("image_path", "")
            try:
                if name == "vol_pslist":
                    result = self._vol.pslist(image_path)
                else:
                    result = self._vol.netscan(image_path)
            except VolatilityFailed as e:
                return json.dumps({"error": str(e)})
            suspicious = _scan_processes_for_iocs(result.rows) if name == "vol_pslist" else []
            self._chain.append(
                name,
                {
                    "image_path": image_path,
                    "row_count": len(result.rows),
                    "suspicious_count": len(suspicious),
                },
            )
            return json.dumps(
                {
                    "plugin": result.plugin,
                    "row_count": len(result.rows),
                    "suspicious_processes": suspicious,
                    "rows": result.rows[:25],
                }
            )
        if name == "clamav_scan":
            if self._clam is None:
                return json.dumps({"error": "clamav not available on this host"})
            target_path = args.get("target_path", "")
            try:
                report = self._clam.scan(target_path)
            except ClamAVFailed as e:
                return json.dumps({"error": str(e)})
            self._chain.append(
                "clamav_scan",
                {
                    "target": target_path,
                    "infected_count": report.infected_count,
                    "scanned_files": report.scanned_files,
                },
            )
            return json.dumps(
                {
                    "infected_count": report.infected_count,
                    "scanned_files": report.scanned_files,
                    "infections": report.infections[:10],
                }
            )
        if name in ("tsk_mmls", "tsk_fls"):
            if self._tsk is None:
                return json.dumps({"error": "sleuthkit not available on this host"})
            image_path = args.get("image_path", "")
            try:
                if name == "tsk_mmls":
                    table = self._tsk.mmls(image_path)
                    self._chain.append(
                        "tsk_mmls",
                        {"image": image_path, "partition_count": len(table.partitions)},
                    )
                    return json.dumps(
                        {
                            "partition_count": len(table.partitions),
                            "partitions": [
                                {
                                    "slot": p.slot,
                                    "start": p.start_sector,
                                    "length": p.length_sectors,
                                    "description": p.description,
                                }
                                for p in table.partitions
                            ],
                        }
                    )
                offset = int(args.get("offset", 0))
                listing = self._tsk.fls(image_path, offset=offset)
                self._chain.append(
                    "tsk_fls",
                    {"image": image_path, "offset": offset, "entry_count": len(listing.entries)},
                )
                return json.dumps(
                    {
                        "entry_count": len(listing.entries),
                        "deleted_count": sum(1 for e in listing.entries if e.is_deleted),
                        "entries": [
                            {
                                "inode": e.inode,
                                "name": e.name,
                                "is_dir": e.is_dir,
                                "is_deleted": e.is_deleted,
                            }
                            for e in listing.entries[:25]
                        ],
                    }
                )
            except SleuthKitFailed as e:
                return json.dumps({"error": str(e)})
        if name == "plaso_timeline":
            if self._plaso is None:
                return json.dumps({"error": "plaso not available on this host"})
            target_path = args.get("target_path", "")
            parsers = args.get("parsers")
            max_events = int(args.get("max_events", 100))
            try:
                report = self._plaso.timeline(target_path, parsers=parsers, max_events=max_events)
            except PlasoFailed as e:
                return json.dumps({"error": str(e)})
            self._chain.append(
                "plaso_timeline",
                {"target": target_path, "event_count": report.event_count},
            )
            return json.dumps(
                {
                    "event_count": report.event_count,
                    "events": [
                        {
                            "datetime": e.datetime,
                            "timestamp_desc": e.timestamp_desc,
                            "source": e.source,
                            "message": e.message[:200],
                        }
                        for e in report.events[:25]
                    ],
                }
            )
        if name == "yara_match":
            rule_source = args.get("rule_source", "")
            target_text = args.get("target_text")
            file_path = args.get("file_path")
            try:
                self._yara.compile_source(rule_source)
                if file_path:
                    report = self._yara.scan_file(file_path)
                elif target_text is not None:
                    report = self._yara.scan_data(target_text.encode("utf-8"))
                else:
                    return json.dumps({"error": "must provide target_text or file_path"})
            except YARAFailed as e:
                return json.dumps({"error": str(e)})
            self._chain.append(
                "yara_match",
                {"target": report.target, "match_count": report.match_count},
            )
            return json.dumps(
                {
                    "match_count": report.match_count,
                    "matches": [
                        {"rule": m.rule, "tags": m.tags, "meta": m.meta} for m in report.matches
                    ],
                }
            )
        return json.dumps({"error": f"unknown tool: {name}"})


def _summarize_tool_output(name: str, output_json: str) -> str:
    """One-line human-readable summary of a tool result for streaming output."""
    try:
        data = json.loads(output_json)
    except (json.JSONDecodeError, TypeError):
        return output_json[:80] if isinstance(output_json, str) else ""
    if not isinstance(data, dict):
        return str(data)[:80]
    if "error" in data:
        return f"error: {data['error']}"
    if name == "sift_classify":
        rec = data.get("recommendation", "?")
        risk = data.get("risk_score", 0)
        return f"{rec} (risk {risk:.2f})" if isinstance(risk, int | float) else f"{rec}"
    if name in ("vol_pslist", "vol_netscan"):
        rows = data.get("row_count", 0)
        suspicious = len(data.get("suspicious_processes") or [])
        if suspicious:
            names = ", ".join(
                p.get("ImageFileName", "?") for p in data.get("suspicious_processes", [])[:3]
            )
            return f"{rows} rows, {suspicious} suspicious: {names}"
        return f"{rows} rows, 0 suspicious"
    if name == "clamav_scan":
        return f"{data.get('infected_count', 0)} infected of {data.get('scanned_files', 0)} scanned"
    if name == "tsk_mmls":
        return f"{data.get('partition_count', 0)} partitions"
    if name == "tsk_fls":
        return f"{data.get('entry_count', 0)} entries ({data.get('deleted_count', 0)} deleted)"
    if name == "yara_match":
        return f"{data.get('match_count', 0)} matches"
    if name == "plaso_timeline":
        return f"{data.get('event_count', 0)} timeline events"
    return json.dumps(data)[:80]


# --- helpers (handle both dict and ollama-typed responses) ---


_PATH_HINTS = (
    (
        re.compile(r"\b([\w./\-]+\.(?:vmem|mem|dmp|raw|lime|img|aff))\b", re.IGNORECASE),
        "memory image",
        "vol_pslist",
        "image_path",
    ),
    (
        re.compile(r"\b([\w./\-]+\.(?:e01|dd|iso))\b", re.IGNORECASE),
        "disk image",
        "tsk_mmls",
        "image_path",
    ),
    (
        re.compile(r"\b([\w./\-]+\.(?:log|evtx|syslog|json|csv))\b", re.IGNORECASE),
        "log file",
        "plaso_timeline",
        "target_path",
    ),
)


def _detect_evidence_paths(alert: dict[str, Any]) -> list[str]:
    """Find filesystem paths in the alert and return tool-call hints."""
    blob = json.dumps(alert)
    hints: list[str] = []
    seen: set[str] = set()
    for pattern, kind, tool, arg_name in _PATH_HINTS:
        for match in pattern.findall(blob):
            if match in seen:
                continue
            seen.add(match)
            hints.append(f'- {kind} at `{match}` → call `{tool}` with `{arg_name}="{match}"`')
    return hints


# Process name fragments commonly associated with malware / unauthorized tools.
# Conservative list — false positives on legitimate sysadmin tools are acceptable
# (the operator confirms the verdict). Each fragment is matched case-insensitively
# as a substring of `ImageFileName`.
_SUSPICIOUS_PROCESS_FRAGMENTS = (
    "keylog",
    "mimikatz",
    "cobaltstrike",
    "metasploit",
    "meterpret",
    "psexec",
    "lazagne",
    "procdump",
    "rundll",
    "wce",
    "pwdump",
    "cryptominer",
    "xmrig",
    "monero",
    "miner",
    "rat.",
    "backdoor",
    "trojan",
    "rootkit",
)


def _scan_processes_for_iocs(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Surface processes whose ImageFileName matches a known suspicious fragment.

    Deterministic IOC surfacing so the agent loop reliably notices what's
    interesting in the pslist output instead of relying on the LLM to read
    the whole table and judge.
    """
    out: list[dict[str, Any]] = []
    for row in rows:
        name = str(row.get("ImageFileName", "") or "").lower()
        for frag in _SUSPICIOUS_PROCESS_FRAGMENTS:
            if frag in name:
                match: dict[str, Any] = {
                    "PID": row.get("PID"),
                    "PPID": row.get("PPID"),
                    "ImageFileName": row.get("ImageFileName"),
                    "matched_fragment": frag,
                }
                attack = _attack_for_ioc_fragment(frag)
                if attack:
                    match["attack_technique"] = attack
                out.append(match)
                break
    return out


# Patterns that look like hostile payloads worth classifying individually.
_PAYLOAD_PATTERNS = (
    re.compile(r"'([^']{6,})'"),  # single-quoted payload
    re.compile(r'"([^"]{6,})"'),  # double-quoted payload
    re.compile(r"\$\(([^)]+)\)"),  # $(command-substitution)
    re.compile(r"`([^`]+)`"),  # backtick-substitution
    re.compile(r"(https?://[^\s'\"<>]+)"),  # URL
    re.compile(r"(\?[A-Za-z_][A-Za-z0-9_]*=[^\s'\"<>&]+)"),  # query-string fragment
    re.compile(r"((?:\.{2}/){1,}[^\s'\"]+)"),  # path traversal segment
)


def _extract_payloads(alert: dict[str, Any]) -> list[str]:
    """Pull candidate hostile payloads out of indicator-bearing alert fields.

    The 1.5B model struggles to extract a quoted value from prose. This helper
    surfaces the actual payloads as a list so the model can pass them through
    `sift_classify` directly.
    """
    candidates: list[str] = []
    for key in ("indicators", "indicator", "evidence", "details"):
        val = alert.get(key)
        if isinstance(val, list):
            candidates.extend(str(v) for v in val)
        elif isinstance(val, str):
            candidates.append(val)

    payloads: list[str] = []
    seen: set[str] = set()
    for text in candidates:
        for pattern in _PAYLOAD_PATTERNS:
            for match in pattern.findall(text):
                payload = match.strip()
                if len(payload) < 6 or payload in seen:
                    continue
                seen.add(payload)
                payloads.append(payload)
    return payloads


def _format_alert(alert: dict[str, Any], gate_recommendation: str) -> str:
    parts = [
        f"Alert payload (input pre-filter: {gate_recommendation}):",
        "",
        f"```\n{json.dumps(alert, indent=2)}\n```",
        "",
    ]
    hints = _detect_evidence_paths(alert)
    if hints:
        parts.append("Filesystem evidence detected — investigate by calling the indicated tool:")
        parts.extend(hints)
        parts.append("")

    payloads = _extract_payloads(alert)
    if payloads:
        parts.append(
            "Candidate hostile payloads extracted from the alert — call `sift_classify` on each:"
        )
        for p in payloads:
            preview = p if len(p) <= 100 else p[:97] + "..."
            parts.append(f"- `{preview}`")
        parts.append("")

    parts.append(
        "Investigate. If filesystem evidence is listed, call the indicated DFIR "
        "tool first. Then call `sift_classify` on each extracted payload above "
        "(one call per payload). Return your final verdict when confident."
    )
    return "\n".join(parts)


def _msg_to_dict(msg: Any) -> dict[str, Any]:
    if isinstance(msg, dict):
        return msg
    out: dict[str, Any] = {"role": getattr(msg, "role", "assistant")}
    if hasattr(msg, "content"):
        out["content"] = msg.content
    if hasattr(msg, "tool_calls") and msg.tool_calls:
        out["tool_calls"] = [_tool_call_dict(t) for t in msg.tool_calls]
    return out


def _get_content(msg: Any) -> str:
    if isinstance(msg, dict):
        return msg.get("content", "") or ""
    return getattr(msg, "content", "") or ""


_TOOL_NAMES = frozenset(
    [
        "sift_classify",
        "vol_pslist",
        "vol_netscan",
        "clamav_scan",
        "tsk_mmls",
        "tsk_fls",
        "plaso_timeline",
        "yara_match",
    ]
)


def _parse_raw_tool_call(content: str) -> list[dict[str, Any]]:
    """Parse tool calls from raw JSON in message content.

    The fine-tuned model emits {"name": ..., "arguments": {...}} directly
    rather than using Ollama's <tool_call> XML wrapper.
    """
    if not content:
        return []
    text = content.strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(obj, dict) and obj.get("name") in _TOOL_NAMES and "arguments" in obj:
        return [{"function": {"name": obj["name"], "arguments": obj["arguments"]}}]
    return []


def _get_tool_calls(msg: Any) -> list[Any]:
    if isinstance(msg, dict):
        tc = msg.get("tool_calls") or []
    else:
        tc = getattr(msg, "tool_calls", None) or []
    if tc:
        return tc
    content = _get_content(msg)
    return _parse_raw_tool_call(content)


def _tool_name(tc: Any) -> str:
    if isinstance(tc, dict):
        return tc.get("function", {}).get("name", "")
    return tc.function.name


def _tool_args(tc: Any) -> dict[str, Any]:
    if isinstance(tc, dict):
        raw = tc.get("function", {}).get("arguments", {})
    else:
        raw = tc.function.arguments
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_raw": raw}
    return dict(raw) if raw else {}


def _tool_call_dict(tc: Any) -> dict[str, Any]:
    if isinstance(tc, dict):
        return tc
    return {
        "function": {
            "name": tc.function.name,
            "arguments": tc.function.arguments,
        }
    }
