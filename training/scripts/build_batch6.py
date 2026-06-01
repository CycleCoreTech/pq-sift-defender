#!/usr/bin/env python3
"""Build batch_6_benign_hard_pass.jsonl from Grok-provided hard PASS scenarios.

Converts 3-turn Grok samples into proper 5-turn format matching existing batches:
  system → human (alert) → gpt (tool call) → human (tool response) → gpt (verdict)

Also generates realistic sift_classify PASS responses with slightly elevated
risk scores (these are "looks suspicious but benign" cases).
"""

import json
import random

random.seed(42)

SYSTEM_PLACEHOLDER = "You are pq-sift-defender, an autonomous incident response triage agent."

FOUR_GATES = ["ssrf", "injection_cmd", "injection_sql", "path_traversal"]


def make_tool_call(alert_text: str) -> str:
    return json.dumps({"name": "sift_classify", "arguments": {"text": alert_text}})


def make_pass_response(alert_text: str, elevated: bool = False) -> str:
    """Generate a realistic PASS tool response. Elevated = higher scores but still clean."""
    base = 0.18 if not elevated else 0.32
    flags = []
    for gate in FOUR_GATES:
        conf = round(random.uniform(0.02, 0.25) if not elevated else random.uniform(0.15, 0.45), 2)
        flags.append({"gate": gate, "detected": False, "confidence": conf})
    risk = round(random.uniform(0.05, 0.28) if not elevated else random.uniform(0.22, 0.42), 2)
    summary_options = [
        "No malicious patterns detected across all gates.",
        "All security gates returned clean.",
        "Input classified as benign by all analyzers.",
        "No injection, traversal, or SSRF indicators found.",
        "Classification complete. No threats identified.",
    ]
    return json.dumps(
        {
            "recommendation": "PASS",
            "risk_score": risk,
            "flags": flags,
            "summary": random.choice(summary_options),
        }
    )


def make_sample(
    alert: str, verdict_reason: str, quality: str = "A", elevated: bool = False
) -> dict:
    return {
        "conversations": [
            {"from": "system", "value": SYSTEM_PLACEHOLDER},
            {"from": "human", "value": alert},
            {"from": "gpt", "value": make_tool_call(alert)},
            {"from": "human", "value": make_pass_response(alert, elevated=elevated)},
            {"from": "gpt", "value": f"Verdict: PASS — {verdict_reason}"},
        ],
        "quality": quality,
    }


# ── Hard PASS samples from Grok (looks suspicious but benign) ──────────────

SAMPLES = [
    # Set 1: First batch of hard PASS scenarios
    (
        "Memory dump detected: /tmp/prod-forensic-2026-06-01.vmem (size 2.1GB). Process: esxi-collector. Indicators: large .vmem file, recent creation. Summary: Potential live memory extraction.",
        "Legitimate scheduled memory capture for internal DR testing.",
        "A",
        True,
    ),
    (
        "PowerShell execution: cmdline='powershell -enc JABjAG8AbgBmAGkAZwA9AEcAZQB0AC0AQwBvAG4AdABlAG4AdAAgACIAYwA6AFwAcwBlAGMAcgBlAHQALgB0AHgAdAAiAA=='. Parent: jenkins-agent. Hash: benign internal script.",
        "Expected Jenkins CI/CD PowerShell step, internal only.",
        "A",
        True,
    ),
    (
        "Outbound connection to 104.16.85.12:443 (cloudflare). Process: updater.bin. Indicators: unusual user-agent, 14MB transfer. Summary: Possible C2 beacon.",
        "Legitimate software update check via CDN.",
        "A",
        True,
    ),
    (
        "WAF blocked request: /admin/../etc/passwd with base64 payload. Source: internal 10.20.30.40 (monitoring server). Action: logged only.",
        "Scheduled internal WAF penetration test, known benign.",
        "A",
        True,
    ),
    (
        "vol_pslist shows unknown process 'dumpit.exe' PID 1337. Path: /opt/tools/dumpit.exe. Memory: 47MB. Command line contains -f flag.",
        "Authorized IR tooling execution in lab environment.",
        "A",
        True,
    ),
    (
        "EDR alert: Base64 encoded string in registry key HKLM\\Software\\Backup\\Config. Value length 8KB. Looks like obfuscated payload.",
        "Normal Veeam backup configuration storage.",
        "A",
        True,
    ),
    (
        "File created: /var/tmp/0xdeadbeef.tmp with permissions 777. Owner: root. SHA256 matches known malicious sample in old threat intel (false positive match).",
        "Benign temporary file from web server maintenance, old threat intel hash collision.",
        "A",
        True,
    ),
    (
        "rsync from internal host 192.168.77.22:/data/* to /backup/archive/ with --delete flag. 18GB transferred. SSH key used: service-backup.",
        "Routine internal rsync backup job completed successfully.",
        "A",
        False,
    ),
    (
        "ClamAV detected 'Heuristics.Packed' in /opt/scanner/test/eicar.com.txt during weekly scan. Scan ID #48291.",
        "Expected test signature during AV self-test.",
        "A",
        True,
    ),
    (
        "Zabbix trigger: High CPU on database server. Root cause: logrotate on 42GB transaction log. Resolved after rotation.",
        "Resolved performance transient from routine maintenance.",
        "A",
        False,
    ),
    (
        "Suspicious child process: curl -k https://10.0.0.1/internal-health -o /dev/null from cron daemon. Exit code 0.",
        "Standard internal monitoring probe via cron.",
        "A",
        True,
    ),
    (
        "Kernel module loaded: suspicious.ko. Path: /lib/modules/6.8.0/extra/test-module.ko. Signed with internal CA.",
        "Authorized internal kernel module for diagnostics.",
        "A",
        True,
    ),
    (
        "Failed login attempts from service-account@internal.company.corp (expected 240 failures). Source: backup-orchestrator service.",
        "Normal service account retry loop in backup workflow.",
        "B",
        True,
    ),
    (
        "Prometheus alert: node_memory_Active_bytes high. Related: memdump job completed 3 minutes prior. Path /var/lib/forensics/dump-20260601-1245.vmem.",
        "Expected transient from scheduled memory dump.",
        "A",
        True,
    ),
    (
        "WAF logged SQLi-like string in POST to /api/v2/ingest. Payload contains '1=1'. Source IP in corporate VPN range.",
        "Legitimate internal ETL pipeline test.",
        "A",
        True,
    ),
    (
        "Unusual parent: svchost.exe spawning rundll32.exe with argument pointing to /tmp/defender-plugin.dll. Context: Windows update cycle.",
        "Normal Windows Update / Defender maintenance activity.",
        "A",
        True,
    ),
    (
        "Log entry: 'rm -rf /var/cache/apt/*' executed by apt-daily user at 03:14. No anomalies in context.",
        "Routine system cache maintenance by apt-daily.",
        "A",
        False,
    ),
    (
        "EDR flagged large outbound transfer (1.8GB) to s3.us-east-1.amazonaws.com from process 'backup-agent'. Bucket: company-internal-backups-2026.",
        "Successful scheduled S3 backup upload.",
        "A",
        True,
    ),
    (
        "vol_malfind found injected code in explorer.exe. Injection source: legitimate antivirus update service. Context: AV definition push.",
        "Authorized AV engine performing memory update.",
        "A",
        True,
    ),
    (
        "Scheduled task 'HealthCheck-Daily' ran successfully. Command: /opt/tools/run-sift-test.sh --mode=full. Exit status 0. Generated test alerts intentionally.",
        "Controlled internal health-check and pipeline test.",
        "A",
        False,
    ),
    (
        "File /etc/cron.d/backup rotated to /etc/cron.d/backup.1. Contains '0 2 * * * rsync ...'. No modification to active jobs.",
        "Routine cron configuration log rotation.",
        "A",
        False,
    ),
    (
        "Internal scanner reported 'Suspicious entropy' in config.json (entropy 7.8). File is encrypted service credential store.",
        "Normal encrypted configuration file.",
        "A",
        True,
    ),
    # Set 2: Continuation — even harder cases
    (
        "Memory dump path: /var/lib/forensics/live-dump-20260601-1250.vmem (4.2GB). Created by process 'ir-collector'. Indicators: sudden large file, root owner, no parent process visible.",
        "Authorized periodic memory capture for disaster recovery testing.",
        "A",
        True,
    ),
    (
        "PowerShell: powershell.exe -NoP -NonI -W Hidden -Enc JAB0AGgAcgBlAGEAZAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACAAJAB0AGgAcgBlAGEAZAAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAIgBoAHQAdABwAHM6AC8ALwBjAG8AbgBmAGkAZwAuAGkAbgB0AGUAcgBuAGEAbAAiACkA. Parent: task-scheduler.",
        "Scheduled internal config sync via Task Scheduler.",
        "A",
        True,
    ),
    (
        "Outbound TLS connection to 151.101.0.0/22 (Fastly CDN) on 443. Process: cdn-updater. 87MB downloaded. User-agent contains 'internal-build-pipeline'.",
        "Legitimate CDN-based dependency update for build pipeline.",
        "A",
        True,
    ),
    (
        "WAF alert: Path traversal attempt /api/../config/secrets.yaml. Source IP 172.16.5.10 (VPN). Request contained encoded dots.",
        "Authorized internal security compliance scan.",
        "A",
        True,
    ),
    (
        "vol_pslist detected process 'mimikatz.exe' PID 4242. Path: /opt/ir-tools/mimikatz.exe. Command line: --dump --quiet. Context: IR lab VM.",
        "Authorized IR tooling in controlled lab environment.",
        "A",
        True,
    ),
    (
        "EDR registry alert: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\BackupEntry contains long base64 blob (12KB). Looks like persistence.",
        "Normal backup agent registry configuration.",
        "A",
        True,
    ),
    (
        "File created: /tmp/evil-payload.sh with mode 777 and content starting with '#!/bin/bash\\ncurl -k https://...'. Owner: cron.",
        "Routine monitoring script execution by cron health-check.",
        "B",
        True,
    ),
    (
        "rsync --delete --exclude=.snapshot /data/prod to rsync://192.168.200.50/backup. 2.4TB transferred overnight.",
        "Scheduled large-scale internal data replication.",
        "A",
        False,
    ),
    (
        "ClamAV: 'Win.Trojan.Generic' detected in /var/lib/test/eicar_2.com during scheduled test scan. Scan result intentionally triggered.",
        "Expected test signature in AV health check.",
        "A",
        True,
    ),
    (
        "Zabbix alert: 'Process crash' on service 'sift-triage'. Resolved in 14 seconds. Restarted via systemd.",
        "Normal self-healing restart of internal service.",
        "A",
        False,
    ),
    (
        "curl -s -k -H 'Authorization: Bearer internal-token' https://10.100.0.1:8443/healthz from cron. Exit code 0, returned 'OK'.",
        "Standard internal service health probe.",
        "A",
        True,
    ),
    (
        "Kernel module: /lib/modules/6.8.0/custom-diag.ko loaded via modprobe. Signed with company-internal CA.",
        "Authorized diagnostic kernel module.",
        "A",
        True,
    ),
    (
        "Failed logins (312 attempts) from 'svc-backup@corp.local' to storage API. All within 5-minute backup window.",
        "Normal backup service authentication retries.",
        "B",
        True,
    ),
    (
        "Prometheus: node_disk_io_time_seconds high. Correlates exactly with completed S3 backup job writing 940GB.",
        "Expected IO from scheduled backup workload.",
        "A",
        False,
    ),
    (
        "WAF: SQL injection pattern 'OR 1=1--' in JSON payload to /api/internal/metrics. Source: 10.10.10.55 (metrics pipeline).",
        "Controlled internal metrics pipeline test.",
        "A",
        True,
    ),
    (
        "svchost.exe spawning powershell.exe with argument '-File C:\\ProgramData\\Microsoft\\Windows Defender\\MpCmdRun.ps1'. Context: update cycle.",
        "Normal Windows Defender maintenance activity.",
        "A",
        True,
    ),
    (
        "Log: 'rm -rf /var/tmp/*' executed by systemd-tmpfiles-clean service at 04:00 daily.",
        "Routine system temporary file maintenance.",
        "A",
        False,
    ),
    (
        "Large outbound transfer (3.1GB) to s3.us-west-2.amazonaws.com/bucket/internal-archive-2026. Process: backup-orchestrator.",
        "Completed scheduled archival backup to S3.",
        "A",
        True,
    ),
    (
        "vol_malfind: injected memory region in svchost.exe. Source: Windows Update service (wuauclt.exe).",
        "Authorized Windows Update memory operation.",
        "A",
        True,
    ),
    (
        "Scheduled task 'Pipeline-Validation' executed /opt/tools/synthetic-alert-generator.sh --type=benign. Generated 18 test alerts.",
        "Internal synthetic testing and pipeline validation job.",
        "A",
        False,
    ),
    (
        "High entropy (7.92) detected in /etc/config/credentials.enc. File size 64KB.",
        "Standard encrypted credential store.",
        "A",
        True,
    ),
    (
        "vol_file: /evidence/old-test-dump.vmem not found. Referenced only in archived lab documentation.",
        "Stale reference from retired lab configuration.",
        "A",
        False,
    ),
    # Set 3: Original simpler PASS (from Grok Option 2) — still useful for diversity
    (
        "Alert: Log rotation completed successfully on /var/log/auth.log to /var/log/auth.log.1",
        "Routine log rotation by system daemon, expected behavior.",
        "A",
        False,
    ),
    (
        "Scheduled backup completed: /proc/kcore to /backup/safe-dump-2026-06-01.vmem. SHA256 verified. No anomalies.",
        "Legitimate scheduled memory dump backup, verified clean.",
        "A",
        False,
    ),
    (
        "Zabbix agent heartbeat to 192.168.10.55:10050 successful. Standard internal monitoring.",
        "Expected internal monitoring traffic.",
        "A",
        False,
    ),
    (
        "vol_pslist failed: image file not found at /evidence/nonexistent.vmem. Path appears in scheduled task config.",
        "File not present because this is a configuration alert, not active compromise.",
        "A",
        False,
    ),
    (
        "ClamAV scan completed on /var/www/uploads. 0 threats found. 1243 files scanned.",
        "Routine antivirus scan, clean result.",
        "A",
        False,
    ),
    (
        "Prometheus node exporter collecting metrics from /proc/. Standard internal operation.",
        "Normal system metrics collection.",
        "A",
        False,
    ),
]


def main():
    out_path = "/home/rain/pq-sift-defender/training/data/batch_6_benign_hard_pass.jsonl"
    with open(out_path, "w") as f:
        for alert, reason, quality, elevated in SAMPLES:
            sample = make_sample(alert, reason, quality, elevated)
            f.write(json.dumps(sample) + "\n")
    print(f"Wrote {len(SAMPLES)} samples to {out_path}")

    # Quality breakdown
    quals = {}
    for _, _, q, _ in SAMPLES:
        quals[q] = quals.get(q, 0) + 1
    print(f"Quality: {quals}")

    elevated_count = sum(1 for _, _, _, e in SAMPLES if e)
    print(f"Elevated risk scores: {elevated_count}/{len(SAMPLES)}")


if __name__ == "__main__":
    main()
