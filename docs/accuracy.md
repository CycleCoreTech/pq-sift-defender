# Accuracy Report

**Generated:** 2026-06-01
**Model:** QLoRA fine-tuned Qwen2.5-1.5B-Instruct, Q4_K_M quantization (CPU-only, Ollama)
**Pre-built GGUF:** [HuggingFace](https://huggingface.co/CycleCoreTechnologies/pq-sift-defender-Q4_K_M)

## Summary

- Held-out samples: **136**
- Overall accuracy: **96.3%** (131/136)
- BLOCK accuracy: **100%** (72/72)
- FLAG accuracy: **75%** (6/8)
- PASS accuracy: **94.6%** (53/56)
- Triage time: **under 10 s** (fine-tuned model, CPU-only)

## Per-verdict breakdown

| Verdict | Correct | Total | Accuracy | Notes |
|---|---|---|---|---|
| BLOCK | 72 | 72 | 100% | Zero missed attacks |
| FLAG | 6 | 8 | 75% | Small sample; tool-call format leakage on 2 edge cases |
| PASS | 53 | 56 | 94.6% | 3 failures on adversarial quality-C edge cases |

## Sample categories

The 136 held-out samples span:

- Benign system events (login alerts, health checks, log rotation, monitoring)
- SSRF (cloud metadata endpoints, internal IP probes)
- SQL injection (inline and DNS-channel)
- Command injection (shell metacharacters in process exec)
- Path traversal (directory traversal in file parameters)
- Prompt injection (payload directs agent to SSRF endpoint)
- CVE-grounded attacks (Log4Shell, ProxyShell, etc. from CISA KEV catalog)
- Boundary recovery (agent manipulated, security boundary catches and blocks)
- Malware memory dumps (Volatility 3 analysis targets)
- Adversarial benign (look suspicious but are legitimate)

## Multi-hardware validation

| CPU | Triage time | GPU required |
|---|---|---|
| Intel Core i9-14900KF | 5-8 s | No |
| AMD Ryzen 7 7800X3D | 5-8 s | No |

The base `qwen2.5:1.5b` is faster (~4 s) but less consistent on boundary
recovery and format adherence. The fine-tuned model is shipped for accuracy.

## Methodology

The fine-tuned model was evaluated against 136 held-out samples not used during
training. Each sample is a multi-turn ShareGPT-format conversation with an
expected verdict (PASS / FLAG / BLOCK). The model generates a response and the
verdict is extracted and compared to the expected outcome.

Grading:
- `OK` -- verdict matches expectation
- `WEAK` -- incident expected but verdict said PASS
- `OVERREACTION` -- benign expected but verdict said BLOCK or FLAG
- `ERROR` -- agent loop raised or no verdict produced

For live agent evaluation, each case runs through the full investigate pipeline:
alert ingestion, SecurityGates pre-filter, LLM tool-call loop, DFIR tool
dispatch, and PQ-signed audit chain. The `agent_logs/` directory contains
structured JSONL logs with tool calls, timestamps, verdicts, chain IDs,
and full agent transcripts.

## Known limitations

1. **False positive on benign filesystem paths**: The SecurityGates classifier
   flags common system paths (`/var/log/auth.log`) as path traversal. This is
   conservative by design -- the classifier protects against agent manipulation,
   where the surrounding "it's safe" context could be injected.

2. **Adversarial benign cases**: Alerts containing real attack patterns
   (traversal strings, SSRF URLs, shell metacharacters) with benign
   explanations are classified as threats. This is intentional -- an automated
   triage agent should flag actual attack patterns regardless of surrounding
   context claiming safety. Human analysts review the verdict.

## Static proof artifact

[`samples/audit_chain_export.json`](../samples/audit_chain_export.json) contains
a real signed audit chain from a real investigation: `verify.valid=True`, three
entries, each with a 3,309-byte ML-DSA-65 signature, hash-linked.
