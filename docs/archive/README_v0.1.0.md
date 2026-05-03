# pq-sift-defender

Autonomous incident response agent extending Protocol SIFT with post-quantum
signed audit trails and microsecond-latency security pre-filtering.

## What it does

- Extends [Protocol SIFT](https://www.sans.org/blog/protocol-sift-experimental-research-initiative-ai-assisted-dfir)
  with an autonomous AI agent for incident response triage
- Pre-filters suspicious inputs through a microsecond-latency security
  classifier (calls a public CycleCore API as backend)
- Signs every IR action with post-quantum cryptography (ML-DSA-65) at
  sub-100µs per signature, building a tamper-proof audit trail

## Quick start

```bash
pip install -e ".[dev]"
cp .env.example .env  # defaults to local Ollama; override LLM_MODEL if needed
ollama pull qwen2.5:1.5b   # any small tool-use-capable model works
pq-sift-defender investigate samples/sample_alert.json
```

The agent runs against any Ollama-served model with tool-call support. Set
`LLM_HOST` for a remote Ollama instance, `LLM_MODEL` for a different tag.

## Backend services (public)

This agent integrates two public CycleCore APIs:

- [`sg-api.cyclecore.ai`](https://sg-api.cyclecore.ai/docs) — microsecond
  security classification (4 OWASP gates)
- [`pq-api.cyclecore.ai`](https://pq-api.cyclecore.ai/openapi.json) — post-quantum
  signing service (ML-DSA-65, ML-KEM-768)

Both APIs are publicly callable. The demo tier requires no API key.

## DFIR toolchain (host-installed)

The agent invokes standard forensics tools as subprocesses. Tested against
the SANS SIFT Workstation 2026.04 toolchain; works on any Linux with the
following installed:

```bash
sudo apt install -y sleuthkit clamav
pip install --user volatility3 plaso yara-python
```

Tools exposed via MCP-style function calls:

| Tool | Plugin / binary | Source |
|---|---|---|
| `vol_pslist` | `vol windows.pslist -f IMG` | volatility3 (PyPI) |
| `vol_netscan` | `vol windows.netscan -f IMG` | volatility3 (PyPI) |
| _additional wrappers in progress_ | | |

## Architecture

See `docs/architecture.md`.

## Submission

Built for the [SANS FIND EVIL!](https://findevil.devpost.com/) hackathon.

## License

Apache 2.0 — see `LICENSE`. Patent grant scope is clarified in `NOTICE`.
