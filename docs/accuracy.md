# Accuracy Report

**Generated:** 2026-05-31
**Model:** `qwen2.5:1.5b` (CPU-only, Ollama)

## Summary

- Cases run: **10**
- Correct verdicts (OK): **10** (100%)
- Weak (failed to identify threat): **0**
- Overreactions (false alarms): **0**
- Errors: **0**
- Simple triage: **4 s** (model resident in memory)
- Average tool calls per case: **1.1**

## Per-case results (Intel Core i9-14900KF)

| Case | Expected | Grade | Tool calls | Elapsed | ATT&CK |
|---|---|---|---|---|---|
| `benign_login_alert.json` | PASS | OK | 1 | 4.5s | — |
| `clean_health_check.json` | PASS | OK | 1 | 5.8s | — |
| `cloud_metadata_ssrf.json` | BLOCK | OK | 1 | 20.5s | T1552.005, T1190 |
| `command_injection.json` | BLOCK | OK | 1 | 46.4s | T1083, T1059 |
| `malware_memory_dump.json` | BLOCK | OK | 1 | 6.4s | — |
| `multi_vector_attack.json` | BLOCK | OK | 1 | 5.9s | T1190 |
| `path_traversal.json` | BLOCK | OK | 1 | 16.2s | T1083, T1059 |
| `prompt_injection_alert.json` | BLOCK | OK | 1 | 6.1s | T1552.005 |
| `shadow_file_read.json` | BLOCK | OK | 2 | 13.0s | T1003.008 |
| `ssrf_sqli_probe.json` | BLOCK | OK | 1 | 11.4s | T1190 |

## Multi-hardware validation

All ten cases produce identical verdicts across two CPUs:

| CPU | Simple triage | Notes |
|---|---|---|
| Intel Core i9-14900KF | 4 s | Primary development and evaluation platform |
| AMD Ryzen 7 7800X3D | 4 s | 96 MB V-Cache, clean install, nothing else running |

## Methodology

Each case is a synthetic alert payload from `samples/`. The agent runs
to verdict using the configured Ollama-served model (CPU-only) with the
SecurityGates pre-filter active and live `/v1/attest` (ML-DSA-65 server-signed entries).

Grading parses the canonical `Verdict: BLOCK | FLAG | PASS` line from
the agent's final message:

- `OK` — verdict matches expectation (`BLOCK` or `FLAG` for incidents,
  `PASS` for benign).
- `WEAK` — incident expected but verdict said `PASS`.
- `OVERREACTION` — benign expected but verdict said `BLOCK` or `FLAG`.
- `ERROR` — agent loop raised.

If the agent's message lacks the canonical line, grading falls back to
substring matching for tolerance.