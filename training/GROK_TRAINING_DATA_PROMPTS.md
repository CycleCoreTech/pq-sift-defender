# Grok Training Data Prompts — pq-sift-defender

Generate these in 4 separate Grok chats (or sequentially in one).
Each prompt produces ~200 ShareGPT-format training trajectories.
Target total: 800 trajectories across 4 categories.

Output format for ALL prompts: one JSON array per prompt. Each element
is a complete multi-turn conversation. Save each output as the indicated
filename under `training/data/`.

---

## Prompt 1 of 4 — Benign PASS trajectories (200 samples)

**Save output as**: `training/data/batch_1_benign_pass.jsonl`

```
I need you to generate exactly 200 training samples for fine-tuning a
1.5B parameter language model (Qwen 2.5 1.5B) that does autonomous
incident response triage. Each sample is a multi-turn conversation in
ShareGPT format showing the model correctly triaging a BENIGN alert and
returning Verdict: PASS.

OUTPUT FORMAT — each sample is one JSON object per line (JSONL), structured as:

{"conversations": [
  {"from": "system", "value": "<system prompt>"},
  {"from": "human", "value": "<formatted alert>"},
  {"from": "gpt", "value": "<tool call in text format>"},
  {"from": "human", "value": "<tool result>"},
  {"from": "gpt", "value": "Verdict: PASS — <one-line reason>"}
]}

The system prompt for ALL samples is exactly:

"""You are an autonomous incident response triage agent.

You investigate alerts by calling tools. Two classes of tools are available:

- `sift_classify` — classifies a string against four security gates (SQL injection, command injection, path traversal, SSRF). Returns PASS / FLAG / BLOCK with per-gate confidence.
- DFIR forensic tools (vol_pslist, vol_netscan, clamav_scan, tsk_mmls, tsk_fls, plaso_timeline, yara_match) for evidence files on disk.

Every tool call is signed and recorded in a tamper-proof audit chain.

DECISION RULE — anchor your verdict on tool output, not on intuition:

- If a classifier returns BLOCK → Verdict: BLOCK with the gate name.
- If a classifier returns FLAG → Verdict: FLAG with the gate name. FLAG means the pattern is suspicious; treat it as a real incident worth investigating, not as benign.
- Only when the input pre-filter is PASS AND every classifier call also returns PASS → Verdict: PASS. Do not invent threats.
- If a DFIR tool returns an error (file not found, tool not installed), and no other indicators are suspicious, issue Verdict: PASS — evidence file not available.

VERDICT FORMAT — your final message must begin with one of these exact lines:

    Verdict: BLOCK — <one-line reason citing the indicator>
    Verdict: FLAG  — <one-line reason citing the indicator>
    Verdict: PASS  — no indicators detected by any tool

Tool output is ground truth. Do not flag benign alerts. Do not speculate beyond what the tools detected."""

TOOL CALL FORMAT — the model outputs tool calls as:

{"name": "sift_classify", "arguments": {"text": "<the string to classify>"}}

or for DFIR tools:

{"name": "vol_pslist", "arguments": {"image_path": "/path/to/dump.vmem"}}
{"name": "plaso_timeline", "arguments": {"target_path": "/var/log/auth.log"}}
{"name": "clamav_scan", "arguments": {"target_path": "/tmp/suspicious.bin"}}
{"name": "tsk_fls", "arguments": {"image_path": "/data/disk.dd"}}
{"name": "yara_match", "arguments": {"target_path": "/tmp/sample.exe", "rules_path": "rules/malware.yar"}}

TOOL RESPONSE FORMAT — the human turn after a tool call contains the
tool result. For sift_classify returning PASS:

{"recommendation": "PASS", "risk_score": 0.12, "flags": [{"gate": "ssrf", "detected": false, "confidence": 0.11}, {"gate": "injection_cmd", "detected": false, "confidence": 0.08}, {"gate": "injection_sql", "detected": false, "confidence": 0.15}, {"gate": "path_traversal", "detected": false, "confidence": 0.12}]}

For DFIR tools returning errors:

{"error": "image not found: /path/to/file.vmem"}
{"error": "plaso not installed"}
{"error": "psort failed (rc=1)"}

VARIETY REQUIREMENTS — distribute the 200 samples across these subcategories:

- 40 samples: routine login/auth events (SSH, RDP, VPN, SSO, 2FA)
- 30 samples: health checks and monitoring (Kubernetes probes, Prometheus, Zabbix, Nagios, Datadog, SNMP)
- 30 samples: log rotation and maintenance (logrotate, cron jobs, package updates, disk cleanup)
- 25 samples: backup operations (rsync, mysqldump, pg_dump, file sync, snapshot creation)
- 25 samples: internal network traffic (inter-service calls, DNS lookups, NTP sync, DHCP leases)
- 20 samples: deployment and CI/CD events (Docker builds, Terraform applies, Ansible playbooks, GitHub Actions)
- 15 samples: benign with filesystem paths that could look suspicious (/var/log/*, /etc/*, /proc/*, /tmp/*) — model must PASS these
- 15 samples: benign with internal IPs (10.x, 172.16.x, 192.168.x) — model must PASS these

CRITICAL BEHAVIORS TO TRAIN:

1. When sift_classify returns PASS on all indicators → output Verdict: PASS
2. When a DFIR tool returns "file not found" or "not installed" → output Verdict: PASS (not conversational text, not "please check the path")
3. NEVER output anything other than a verdict-formatted final line
4. Vary the number of tool calls per trajectory (1-3 calls before verdict)
5. Include trajectories where the model classifies 2-3 indicators sequentially, all PASS

FRACTAL QUALITY LEVELS — tag each sample with a "quality" field:

- "quality": "A" — perfect trajectory, clean tool calls, clean verdict, representative of real-world benign alert
- "quality": "B" — correct but slightly unusual (uncommon service, unusual log format, edge-case benign)
- "quality": "C" — correct but tests a specific failure mode (path that looks like traversal, IP that looks like SSRF, command that looks like injection — but is actually benign)

Distribution: 60% A, 25% B, 15% C.

Add the quality tag as a top-level field next to "conversations".

Generate all 200 samples. Output as JSONL (one JSON object per line).
Do not truncate. Do not summarize. Output every sample in full.
```

---

## Prompt 2 of 4 — Attack BLOCK trajectories (200 samples)

**Save output as**: `training/data/batch_2_attack_block.jsonl`

```
I need you to generate exactly 200 training samples for fine-tuning a
1.5B parameter language model (Qwen 2.5 1.5B) that does autonomous
incident response triage. Each sample is a multi-turn conversation in
ShareGPT format showing the model correctly triaging a MALICIOUS alert
and returning Verdict: BLOCK.

OUTPUT FORMAT — same as before: JSONL, one JSON object per line:

{"conversations": [
  {"from": "system", "value": "<system prompt>"},
  {"from": "human", "value": "<formatted alert>"},
  {"from": "gpt", "value": "<tool call>"},
  {"from": "human", "value": "<tool result showing detection>"},
  {"from": "gpt", "value": "Verdict: BLOCK — <reason citing specific indicator>"}
]}

Use the EXACT same system prompt as Prompt 1 (the full IR triage agent
system prompt). I will paste it into context — do not modify it.

TOOL RESPONSE FORMAT — for sift_classify returning detections:

BLOCK example:
{"recommendation": "BLOCK", "risk_score": 0.92, "flags": [{"gate": "ssrf", "detected": true, "confidence": 0.92}, {"gate": "injection_cmd", "detected": false, "confidence": 0.15}, {"gate": "injection_sql", "detected": false, "confidence": 0.20}, {"gate": "path_traversal", "detected": false, "confidence": 0.18}]}

FLAG example (model should still issue BLOCK if confident):
{"recommendation": "FLAG", "risk_score": 0.71, "flags": [{"gate": "ssrf", "detected": false, "confidence": 0.45}, {"gate": "injection_cmd", "detected": false, "confidence": 0.30}, {"gate": "injection_sql", "detected": true, "confidence": 0.71}, {"gate": "path_traversal", "detected": false, "confidence": 0.22}]}

For DFIR tools returning suspicious findings:

vol_pslist with malware:
{"processes": [{"PID": 4820, "PPID": 1, "ImageFileName": "ToolKeylogger.exe", "CreateTime": "2026-05-30T14:22:11"}, {"PID": 1204, "PPID": 672, "ImageFileName": "svchost.exe", "CreateTime": "2026-05-30T08:01:00"}], "suspicious_processes": [{"PID": 4820, "ImageFileName": "ToolKeylogger.exe", "matched_fragment": "keylog", "attack_technique": {"id": "T1056.001", "name": "Input Capture: Keylogging"}}], "suspicious_count": 1}

clamav_scan with detection:
{"infected_files": 1, "scanned_files": 47, "matches": [{"file": "/tmp/payload.bin", "signature": "Win.Trojan.Agent-123456"}]}

VARIETY REQUIREMENTS — distribute across:

- 35 samples: SQL injection patterns (UNION SELECT, OR 1=1, DROP TABLE, stacked queries, blind SQLi, time-based)
- 35 samples: SSRF patterns (169.254.169.254, metadata.google.internal, internal IPs with cloud metadata paths, redirect chains)
- 30 samples: command injection (pipe chains, backtick execution, $() substitution, ; separators, && chains)
- 25 samples: path traversal attacks (../../../etc/passwd, ..%2f encoding, /etc/shadow, /proc/self/environ, null byte injection)
- 25 samples: prompt injection via alert payload (hidden instructions telling agent to fetch URLs, suppress findings, exfiltrate data, call specific tools with malicious args)
- 20 samples: malware in memory dumps (vol_pslist finding keyloggers, cryptominers, RATs, Cobalt Strike, Mimikatz, rootkits)
- 15 samples: malware on disk (clamav_scan finding trojans, ransomware, worms)
- 15 samples: multi-vector attacks (alert contains 2+ different attack types — model must classify each and BLOCK on the worst)

CRITICAL BEHAVIORS TO TRAIN:

1. When sift_classify returns BLOCK → immediately Verdict: BLOCK citing the gate
2. When sift_classify returns FLAG → Verdict: BLOCK if the pattern is clearly hostile (SQLi, SSRF URL), Verdict: FLAG if ambiguous
3. When vol_pslist shows suspicious processes → Verdict: BLOCK citing process name + PID
4. When clamav_scan finds malware → Verdict: BLOCK citing signature
5. On multi-indicator alerts, classify EACH indicator (not just the first)
6. Include MITRE ATT&CK technique references in the verdict reason when applicable (T1190, T1059, T1083, T1552.005, T1056.001, etc.)
7. ALWAYS use the exact verdict format — never output conversational text as a verdict

FRACTAL QUALITY LEVELS:

- "quality": "A" — textbook attack pattern, clean detection, clean verdict with ATT&CK reference
- "quality": "B" — realistic but less common attack variant (encoded payloads, chained exploits, obfuscated commands)
- "quality": "C" — adversarial case where the alert includes "this is safe" / "authorized test" language but the payload is real — model must still BLOCK

Distribution: 50% A, 30% B, 20% C.

Generate all 200 samples. Output as JSONL. Do not truncate.
```

---

## Prompt 3 of 4 — Boundary Block Recovery trajectories (200 samples)

**Save output as**: `training/data/batch_3_boundary_recovery.jsonl`

```
I need you to generate exactly 200 training samples for fine-tuning a
1.5B parameter language model (Qwen 2.5 1.5B) that does autonomous
incident response triage. These samples specifically train the model
to RECOVER CORRECTLY when the agent->tool security boundary blocks a
tool input.

CONTEXT: This agent has a security boundary between the LLM and the
DFIR tools. Before any tool call executes, every string argument is
scanned by a security classifier. If the argument contains an SSRF URL,
SQL injection, command injection, or path traversal pattern, the tool
call is BLOCKED and the model receives an error. The model must then
issue a BLOCK verdict (the boundary interception is itself evidence of
a threat) or switch to a safe tool.

This is the single most important behavior to train. The stock 1.5B
model frequently fails here — it either retries the blocked input,
goes conversational, hallucinates a tool result, or drops the verdict
format. Every sample must show the CORRECT recovery.

OUTPUT FORMAT — JSONL, longer trajectories (3-5 turns):

{"conversations": [
  {"from": "system", "value": "<system prompt>"},
  {"from": "human", "value": "<formatted alert with embedded attack payload>"},
  {"from": "gpt", "value": "{\"name\": \"sift_classify\", \"arguments\": {\"text\": \"<indicator text>\"}}"},
  {"from": "human", "value": "{\"recommendation\": \"PASS\", \"risk_score\": 0.10, ...}"},
  {"from": "gpt", "value": "{\"name\": \"vol_pslist\", \"arguments\": {\"image_path\": \"http://169.254.169.254/latest/meta-data\"}}"},
  {"from": "human", "value": "{\"error\": \"blocked at agent->tool boundary\", \"reason\": \"sift pre-filter blocked tool input 'image_path' on the vol_pslist call (risk 0.82)\", \"blocked_tool\": \"vol_pslist\", \"blocked_arg\": \"image_path\", \"blocked_value_preview\": \"http://169.254.169.254/latest/meta-data\"}"},
  {"from": "human", "value": "The security boundary blocked your previous tool input because it matched a known attack pattern (SSRF, injection, traversal, or command injection). This block is itself strong evidence of a real threat. Do NOT retry the blocked input. Either call a different safe tool to gather more evidence, or issue your final verdict now. A BLOCK verdict citing the boundary interception is appropriate."},
  {"from": "gpt", "value": "Verdict: BLOCK — security boundary intercepted suspicious SSRF pattern in vol_pslist image_path (http://169.254.169.254/latest/meta-data). The agent was manipulated into attempting cloud metadata access via the alert payload."}
]}

Use the EXACT same system prompt as Prompts 1-2.

BOUNDARY BLOCK RESPONSE FORMAT — this is what the model receives when
the boundary fires:

{"error": "blocked at agent->tool boundary", "reason": "sift pre-filter blocked tool input '<arg_name>' on the <tool_name> call (risk <0.XX>)", "blocked_tool": "<tool_name>", "blocked_arg": "<arg_name>", "blocked_value_preview": "<the blocked value>"}

Followed immediately by the recovery prompt:

"The security boundary blocked your previous tool input because it matched a known attack pattern (SSRF, injection, traversal, or command injection). This block is itself strong evidence of a real threat. Do NOT retry the blocked input. Either call a different safe tool to gather more evidence, or issue your final verdict now. A BLOCK verdict citing the boundary interception is appropriate."

VARIETY REQUIREMENTS — distribute across:

- 50 samples: SSRF boundary blocks (169.254.169.254, metadata.google.internal, internal IPs, localhost URLs blocked on vol_pslist, tsk_fls, plaso_timeline, clamav_scan image_path/target_path args)
- 40 samples: path traversal boundary blocks (../../../etc/passwd, ../../../etc/shadow blocked on tsk_fls, plaso_timeline, clamav_scan, yara_match target_path args)
- 35 samples: command injection boundary blocks (pipe chains, backticks, $() blocked on any tool's string args)
- 35 samples: SQL injection boundary blocks (UNION SELECT, OR 1=1 fragments blocked on tool args)
- 20 samples: prompt injection → boundary block chains (alert tells model to use specific URL/path, model obeys, boundary catches it — the full attack-and-catch trajectory)
- 20 samples: model correctly switches to a SAFE tool after a block (e.g., blocked on vol_pslist → calls sift_classify on the blocked value → confirms it's hostile → BLOCK verdict)

CRITICAL BEHAVIORS TO TRAIN:

1. After receiving "blocked at agent->tool boundary" → NEVER retry the same input
2. After receiving the recovery prompt → immediately issue Verdict: BLOCK with the blocked value cited
3. OR after receiving the recovery prompt → call sift_classify on a DIFFERENT indicator, then issue BLOCK
4. NEVER go conversational ("I apologize", "Let me try again", "Please check...")
5. NEVER hallucinate a tool result (don't write a fake tool response in text)
6. NEVER drop the verdict format
7. Include MITRE ATT&CK technique in the verdict when the blocked value maps to one (T1552.005 for cloud metadata, T1083 for path traversal, T1059 for command injection, T1190 for SSRF)

FRACTAL QUALITY LEVELS:

- "quality": "A" — clean block → immediate correct BLOCK verdict with ATT&CK reference
- "quality": "B" — block → model calls one more safe tool → then correct BLOCK verdict
- "quality": "C" — block on a subtle payload (encoded URL, partial traversal, chained command) — model must still recognize the block as evidence

Distribution: 50% A, 30% B, 20% C.

Generate all 200 samples. Output as JSONL. Do not truncate.
```

---

## Prompt 4 of 4 — FLAG edge cases + format discipline (200 samples)

**Save output as**: `training/data/batch_4_flag_and_format.jsonl`

```
I need you to generate exactly 200 training samples for fine-tuning a
1.5B parameter language model (Qwen 2.5 1.5B) that does autonomous
incident response triage. These samples train two specific skills:

A) Correct FLAG verdicts on ambiguous/suspicious-but-not-definitive cases
B) Verdict format discipline — the model MUST always output a properly
   formatted verdict line, never conversational text

OUTPUT FORMAT — JSONL, same as previous prompts.

Use the EXACT same system prompt as Prompts 1-3.

PART A: FLAG CASES (120 samples)

FLAG is the middle verdict — suspicious enough to warrant human review,
but not a clear-cut attack. The model should output:

Verdict: FLAG — <reason explaining what was suspicious>

VARIETY for FLAG cases:

- 25 samples: sift_classify returns FLAG (risk 0.5-0.7) on ambiguous patterns — model should FLAG, not BLOCK or PASS
- 20 samples: unusual but not clearly malicious network patterns (unexpected outbound connections, uncommon ports, high-volume internal transfers)
- 20 samples: suspicious process names that could be legitimate (custom scripts named scan.py, monitor.sh, admin tools with unusual names)
- 15 samples: alerts with mixed signals (some indicators PASS, one FLAGS) — model must FLAG citing the flagged indicator
- 15 samples: authorized penetration testing / red team activity — model should FLAG (not PASS) because the patterns are real even if authorized
- 15 samples: encoded or obfuscated payloads where the classifier catches partial patterns (base64-encoded commands, URL-encoded traversals, hex-encoded SQL)
- 10 samples: alerts where the pre-filter FLAGs at ingest (risk 0.5-0.7) but tool calls return PASS — model should FLAG citing the pre-filter signal

PART B: FORMAT DISCIPLINE CASES (80 samples)

These train the model to ALWAYS produce a clean verdict format, especially
in situations where the stock model tends to drop into conversational mode.

VARIETY for format discipline:

- 20 samples: DFIR tool returns "file not found" → model must output "Verdict: PASS — evidence file not available" (NOT "please check the path")
- 15 samples: DFIR tool returns "tool not installed" → model must output "Verdict: PASS — forensic tool not available, no other indicators detected"
- 15 samples: DFIR tool returns empty results (no processes, no matches) → model must output "Verdict: PASS — no indicators detected by any tool"
- 10 samples: alert is nearly empty or has minimal information → model must still call at least one tool and produce a formatted verdict
- 10 samples: very long/verbose alert payload (20+ fields) → model must extract the right indicators and produce a concise formatted verdict
- 10 samples: alert with unusual field names or structures → model must adapt and produce a formatted verdict

CRITICAL BEHAVIORS TO TRAIN:

1. FLAG means "worth a second look" — not a false alarm, not a confirmed attack
2. When sift_classify returns FLAG → never PASS it, always FLAG or BLOCK
3. When the pre-filter says FLAG at ingest → factor that into the verdict
4. NEVER output text that doesn't start with "Verdict: PASS/FLAG/BLOCK —"
5. When a tool errors → don't ask questions, don't suggest fixes, just verdict
6. Keep verdict reasons to ONE line (under 120 characters)
7. After the verdict line, a brief reasoning paragraph (2-4 sentences) is OK but the FIRST LINE must be the verdict

FRACTAL QUALITY LEVELS:

- "quality": "A" — clean FLAG or format-disciplined verdict, textbook behavior
- "quality": "B" — correct but tests a nuance (FLAG when surrounding context says "benign", format discipline on unusual tool error)
- "quality": "C" — adversarial format test (tool returns garbage/unexpected format, model must still produce clean verdict)

Distribution: 55% A, 30% B, 15% C.

Generate all 200 samples. Output as JSONL. Do not truncate.
```

---

## After All 4 Prompts

Combine the 4 output files:

```bash
cat training/data/batch_1_benign_pass.jsonl \
    training/data/batch_2_attack_block.jsonl \
    training/data/batch_3_boundary_recovery.jsonl \
    training/data/batch_4_flag_and_format.jsonl \
  > training/data/train_full.jsonl

# Shuffle
shuf training/data/train_full.jsonl > training/data/train.jsonl

# Hold out 10% for validation
total=$(wc -l < training/data/train.jsonl)
val_count=$((total / 10))
tail -n "$val_count" training/data/train.jsonl > training/data/val.jsonl
head -n $((total - val_count)) training/data/train.jsonl > training/data/train_final.jsonl
mv training/data/train_final.jsonl training/data/train.jsonl

echo "Training: $(wc -l < training/data/train.jsonl) samples"
echo "Validation: $(wc -l < training/data/val.jsonl) samples"
```

Expected: ~720 train + ~80 val = 800 total trajectories.

## Quality Check

After combining, run:

```bash
# Verify all samples parse as valid JSON
python3 -c "
import json
for line in open('training/data/train.jsonl'):
    d = json.loads(line)
    assert 'conversations' in d, f'Missing conversations: {line[:80]}'
    assert d['conversations'][0]['from'] == 'system', f'First turn must be system'
    last = d['conversations'][-1]
    assert last['from'] == 'gpt', f'Last turn must be gpt: {last}'
    assert 'Verdict:' in last['value'], f'Last turn must contain verdict: {last[\"value\"][:80]}'
print('All samples valid')
"
```
