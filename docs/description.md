# pq-sift-defender

**An AI incident-response triage agent with a microsecond pre-filter and a
post-quantum-signed audit trail.**

## What it does

`pq-sift-defender` reads a security alert (EDR record, WAF log, IDS event,
phishing report) and runs an autonomous DFIR investigation against it. The
agent reasons about the alert with a small local LLM (Ollama-served
`qwen2.5:1.5b`, CPU-only) and decides which forensic tools to call —
Volatility 3, The Sleuth Kit, ClamAV, YARA, Plaso, plus a string classifier
for OWASP-class injection patterns. It returns a verdict (PASS / FLAG /
BLOCK) and a signed, append-only chain of every action it took.

## Why it's interesting

Two security boundaries that are usually missing from agentic IR tools are
present here by construction:

1. **Defense against prompt injection through the alert payload.** Every
   string in the alert and every tool input the agent generates is
   classified by a public security-gates API at microsecond latency. If the
   agent is manipulated into emitting an SSRF or SQL-injection payload, the
   pre-filter blocks it before it reaches a downstream tool.

2. **Forensic disputability is a non-issue.** Every dispatched tool call and
   every verdict is appended to an audit chain backed by a public
   post-quantum signing API (Dilithium3 / ML-DSA-65, NIST FIPS 204). The
   chain is exportable as JSON and verifiable offline against the public
   key. ML-DSA-65 signatures resist quantum cryptanalysis, so the audit
   trail remains admissible decades from now.

## How it's built

The entire agent layer is Apache-2.0 licensed and runs locally — including
on older servers without a GPU. The reasoning model is a 1.5B-parameter
open-weight model on CPU, so triage happens where the incident is, not
after the bytes ship to a SOC.

The agent calls two public CycleCore APIs as backend services
(`sg-api.cyclecore.ai/docs`, `pq-api.cyclecore.ai/openapi.json`); both have
unauthenticated demo tiers. For airgapped or compliance-restricted
environments, both base URLs can be repointed at a local-instance or
appliance-served compatible deployment — set `CYCLECORE_SG_BASE_URL` and
`CYCLECORE_PQ_BASE_URL`. DFIR tools are the standard SANS SIFT toolchain.

## Try it

```bash
pip install -e .
ollama pull qwen2.5:1.5b
pq-sift-defender investigate samples/ssrf_sqli_probe.json
```

Source: `https://github.com/CycleCoreTech/pq-sift-defender`
