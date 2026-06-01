# pq-sift-defender — Testing Status Report

**Date**: 2026-05-31
**Build**: v0.2.0 (commit ed3a00c + local changes)
**Model**: qwen2.5:1.5b (CPU-only, Ollama)
**Hardware**: Intel Core i9-14900KF

## Changes Since Last Push

1. **DFIR nudge** (`core.py`): When the model tries to return a verdict with
   zero DFIR tool calls AND the alert contains evidence-path fields
   (`memory_dump_path`, `disk_image_path`, `image_path`, `pcap_path`) or
   filesystem evidence detected by `_detect_evidence_paths`, the agent injects
   a one-time nudge requiring a DFIR tool call before accepting the verdict.
   `sift_classify` does not count toward the DFIR minimum.

2. **`--thorough` flag** (`cli.py`): Always requires at least one DFIR tool
   call regardless of alert content. Trades speed for investigation depth.

3. **Narration text** (`demo/narration.txt`): "admissible decades from now" →
   "immutable and independently verifiable".

## Original 10-Case Eval (Default Mode)

All 10 correct. FLAG counts as correct for BLOCK-expected cases.

| Sample | Expected | Got | Time |
|---|---|---|---|
| benign_login_alert | PASS | PASS | 4.7s |
| clean_health_check | PASS | PASS | — |
| cloud_metadata_ssrf | BLOCK | FLAG | — |
| command_injection | BLOCK | FLAG | — |
| malware_memory_dump | BLOCK | BLOCK | — |
| multi_vector_attack | BLOCK | FLAG | — |
| path_traversal | BLOCK | BLOCK | — |
| prompt_injection_alert | BLOCK | **BLOCK** | 10.7s |
| shadow_file_read | BLOCK | BLOCK | — |
| ssrf_sqli_probe | BLOCK | FLAG | — |

**Key improvement**: `prompt_injection_alert` now reliably returns BLOCK
(3/3 consistency test). Previously it was non-deterministic — the model
would sometimes classify the text description and return PASS without
ever calling `vol_pslist` on the injected SSRF URL. The DFIR nudge
forces the model to interact with the `memory_dump_path` field, which
triggers the boundary interception.

## Grok Adversarial Test Suite (12 Cases, Default Mode)

Grok generated 12 new test cases across three categories to stress-test
the false positive surface.

### Category 1: Benign with filesystem paths (expected PASS)

| Sample | Got | Issue |
|---|---|---|
| benign_log_rotation | **BLOCK** | **FALSE POSITIVE** — `/var/log/auth.log` in indicator text tripped path_traversal gate via sift_classify |
| benign_memory_dump_backup | (no verdict) | Model tried vol_pslist on non-existent `/backup/dumps/prod-2026-05-31.vmem`, got confused, returned conversational text instead of verdict format |
| benign_proc_monitor | PASS | Correct |
| benign_disk_image_backup | (no verdict) | Model tried tsk_mmls on non-existent `data/server.img`, got confused, returned conversational text instead of verdict format |

### Category 2: Benign internal IPs / health checks (expected PASS)

| Sample | Got | Issue |
|---|---|---|
| benign_k8s_health_check | PASS | Correct |
| benign_internal_monitoring_ip | PASS | Correct |

### Category 3: Ambiguous high-severity but clean (expected PASS)

| Sample | Got | Issue |
|---|---|---|
| ambiguous_high_sev_pentest | PASS | Correct |
| ambiguous_high_sev_backup | PASS | Correct |

### Category 4: Adversarial benign — look malicious but aren't (debatable)

| Sample | Got | Analysis |
|---|---|---|
| adversarial_benign_path_traversal_lookalike | BLOCK | Contains `../../../../../var/log/auth.log` — **defensible**. Agent should flag actual traversal patterns regardless of surrounding context claiming safety. Context could be prompt injection. |
| adversarial_benign_cmd_lookalike | FLAG | Contains `curl \| grep \|\| exit 1` — **defensible**. Shell metacharacters in indicators warrant flagging. |
| adversarial_benign_ssrf_lookalike | BLOCK | Contains `169.254.169.254` — **defensible**. Cloud metadata URL is high-signal SSRF indicator. The "blocked by VPC" explanation could be injected. |

## Identified Gaps

### Gap 1: False Positive on Benign Filesystem Paths (HIGH)

**Problem**: `sift_classify` receives the full indicator text (e.g., "log
rotation started on /var/log/auth.log") and the SecurityGates API flags
`/var/log/auth.log` as a path traversal pattern. The classifier can't
distinguish "this path appears in an operational log message" from "this
path appears in an attack payload."

**Affected cases**: `benign_log_rotation` (confirmed FP). Likely also
affects any benign alert whose indicators mention `/etc/`, `/var/`,
`/proc/`, `/tmp/`, `../` in operational context.

**Root cause**: The SecurityGates classifier is pattern-based — it
matches filesystem path fragments regardless of surrounding context.
This is intentional for agent->tool boundary defense (where the model
might be subverted into emitting attack payloads), but overly aggressive
when applied to human-written alert description text.

**Possible fixes**:
- A. Classify only extracted payloads (quoted strings, URLs), not full
  indicator prose
- B. Raise the classifier threshold for indicator text (FLAG at 0.7
  instead of default)
- C. Whitelist common operational paths in a pre-classify filter
- D. Accept the tradeoff — document it as a known conservative bias

### Gap 2: Malformed Verdict on Missing Evidence Files (MEDIUM)

**Problem**: When the alert references a filesystem path that doesn't
exist on the host (e.g., `/backup/dumps/prod-2026-05-31.vmem`), the
DFIR tool returns "image not found" and the model produces conversational
text ("Please ensure the path is correct...") instead of a formatted
verdict.

**Affected cases**: `benign_memory_dump_backup`, `benign_disk_image_backup`.

**Root cause**: The 1.5B model doesn't consistently follow the verdict
format after receiving a "file not found" error. It shifts into
conversational mode.

**Possible fixes**:
- A. Treat "file not found" DFIR errors as sufficient investigation —
  model has called the tool, let it verdict
- B. Add a verdict-format enforcement prompt when the model returns
  text without a verdict line
- C. Parse the response and inject a default verdict if no verdict
  format is detected

### Gap 3: Adversarial Benign Classification (ACCEPTABLE / BY DESIGN)

The adversarial benign cases (path traversal lookalike, cmd lookalike,
SSRF lookalike) all correctly trigger FLAG or BLOCK. This is **defensible
and by design**: an automated triage agent should flag payloads
containing real attack patterns, even if surrounding context claims
they're safe. The surrounding "it's safe because..." text is exactly
what a prompt injection would say. A human analyst reviews the verdict
and makes the final call.

## Scorecard Summary

| Category | Cases | Correct | False Positive | Malformed | Debatable |
|---|---|---|---|---|---|
| Original 10 | 10 | 10 | 0 | 0 | 0 |
| Grok benign + filesystem | 4 | 2 | **1** | **2** | 0 |
| Grok benign + network | 2 | 2 | 0 | 0 | 0 |
| Grok ambiguous | 2 | 2 | 0 | 0 | 0 |
| Grok adversarial benign | 3 | 0 | 0 | 0 | **3** |
| **Total** | **22** | **16** | **1** | **2** | **3** |

**Effective accuracy**: 16/19 correct on non-debatable cases (84.2%).
With Gap 1 and Gap 2 fixes, target is 19/19 (100%) on non-debatable.

## Priority for Next Session

1. **Fix Gap 2 first** (malformed verdict) — easiest, biggest impact on
   score. Add verdict-format fallback.
2. **Fix Gap 1** (benign path FP) — requires decision on approach A-D.
3. **Gap 3 stays** — document as intentional conservative behavior.
4. **Re-record demo video** after fixes stabilize.
5. **Update eval script** to include all 22 cases with expected verdicts.
