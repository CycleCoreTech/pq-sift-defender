# Try it out

Full setup, end-to-end. Should take a fresh machine ~10 minutes.

## Prerequisites

- Linux (tested on Pop!_OS / Debian-derivative; should work on any modern
  distro with the SIFT toolchain available)
- Python 3.10+
- ~1 GB disk for the model + a few hundred MB for forensic tools
- Internet access (the agent calls two public CycleCore APIs)

## 1. Install the host DFIR toolchain

```bash
sudo apt install -y sleuthkit clamav
pip install --user volatility3 plaso yara-python
```

These give you `vol`, `mmls`, `fls`, `clamscan`, `log2timeline`, `psort`,
and the `yara` Python module. The agent shells out to or imports these
directly.

## 2. Install the agent

```bash
git clone https://github.com/CycleCoreTech/pq-sift-defender
cd pq-sift-defender
pip install -e ".[dev]"
```

`pip install -e .` registers the `pq-sift-defender` CLI on your PATH.

## 3. Get a CycleCore PQ API key (free tier)

The post-quantum signing API requires a key for the `/v1/sign` and
`/v1/attest` endpoints (1,000 ops/day on the free tier). The
SecurityGates API does not require a key on its demo endpoint.

```bash
curl -X POST https://pq-api.cyclecore.ai/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com"}'
```

Copy the returned `api_key` value. Then:

```bash
cp .env.example .env
# edit .env and set CYCLECORE_PQ_API_KEY=pq_live_xxxxxxxxx
```

## 4. Pull a tool-use-capable Ollama model

The agent uses Ollama for local inference. Any tool-call-capable model
works; the default is the smallest known-good option.

```bash
# install Ollama: https://ollama.com/download (one-shot installer)
ollama pull qwen2.5:1.5b
```

The default config runs CPU-only (`num_gpu=0`) so it doesn't compete with
co-tenant GPU workloads. Override `LLM_MODEL` in `.env` for a different
model; override `LLM_HOST` for a remote Ollama instance.

## 5. Run a sample investigation

```bash
pq-sift-defender investigate samples/path_traversal.json
```

Expected output (latency varies on CPU):

```
=== Verdict ===
Verdict: BLOCK — sift_classify reported FLAG on path traversal pattern
'?name=../../../../etc/passwd'

chain_id     : <some uuid>
tool_calls   : 1
blocked_inp  : 0
```

## 6. Verify the signed audit chain

```bash
pq-sift-defender audit-verify <chain_id from step 5>
```

Expected:

```
chain_id     : <uuid>
valid        : True
chain_length : 3
latency_us   : 1700.0
```

Export the full chain (every entry, signature, hash):

```bash
pq-sift-defender audit-export <chain_id> --out chain.json
```

The output JSON has 3 entries (`ingest`, `sift_classify`, `verdict`), each
with a 3309-byte ML-DSA-65 signature and a `prev_hash` link to the previous
entry. The chain is server-validated; any third party with the chain ID
can call `/v1/attest/verify` and confirm.

## 7. Run the full eval

```bash
python scripts/run_eval.py
```

Iterates all 10 samples in `samples/`, writes `docs/accuracy.md` and a
fresh execution log to `agent_logs/eval-<timestamp>.jsonl`. Each agent
session uses the live `/v1/attest` chain by default; set
`PQ_AUDIT_BACKEND=stub` to run with a local in-memory chain instead.

## 8. Live DFIR demo on a real memory image (optional)

For the M57-Patents memory dump sample (`samples/malware_memory_dump.json`),
fetch the public 510 MB memory image first:

```bash
curl -L -o /tmp/m57.zip \
  "https://digitalcorpora.s3.amazonaws.com/corpora/scenarios/2009-m57-patents/ram/pat-2009-12-05.winddramimage.zip"
unzip -p /tmp/m57.zip > evidence/pat-2009-12-05.vmem
```

Then:

```bash
pq-sift-defender investigate samples/malware_memory_dump.json
```

The agent will call `vol_pslist` against the image, the dispatcher will
surface processes whose names match known suspicious fragments
(`keylog`, `mimikatz`, `cobaltstrike`, `xmrig`, `meterpret`, etc.), and the
verdict will name `ToolKeylogger.exe` (PID 280) as the indicator.

This is real Volatility 3 work against a real public memory image, not a
mock. Expect ~60–90 s the first time (Volatility caches symbol tables on
first run) and ~2 s thereafter.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `PQ API key required` | `.env` missing or wrong key | Repeat step 3, confirm `CYCLECORE_PQ_API_KEY` is set |
| `volatility3 not available on this host` | `vol` binary missing from PATH | `pip install --user volatility3` and confirm `~/.local/bin` is on PATH |
| Agent loop appears to hang | Ollama stalling on a request | A 120 s timeout will fire and the loop will recover; override with `LLM_TIMEOUT_S` |
| `HTTP 429` from PQ API | Free-tier daily quota exceeded | Wait for the daily reset, or upgrade tier |
| `clamscan: error while loading shared libraries` | ClamAV signature DB not refreshed | `sudo freshclam` |

## Advanced: airgapped or on-prem deployment

The LLM and DFIR tools always run locally on the IR-investigation host.
The two CycleCore backend services (the SecurityGates pre-filter and the
post-quantum audit-chain signer) can each be repointed independently.

### Post-quantum audit chain (PQ Box, self-host, or offline)

Three options:

```bash
# Option 1: CycleCore PQ Box appliance — same OpenAPI surface as the
# cloud, deployable behind your own firewall.
CYCLECORE_PQ_BASE_URL=https://pq-box.your-network.local

# Option 2: any self-hosted server implementing the public OpenAPI spec
# at https://pq-api.cyclecore.ai/openapi.json
CYCLECORE_PQ_BASE_URL=https://your-pq-instance.example.local

# Option 3: fully offline — local in-memory hash-linked chain. Loses
# server-authoritative ML-DSA-65 signatures; keeps tamper-evident hash
# linking within an investigation.
PQ_AUDIT_BACKEND=stub
```

### SecurityGates pre-filter (self-host or third-party)

```bash
# any server implementing the public OpenAPI spec at
# https://sg-api.cyclecore.ai/openapi.json
CYCLECORE_SG_BASE_URL=https://your-sg-instance.example.local
```

Same wire format, same response shape — no client-side code change. The
agent's own logic is untouched: same DFIR tools, same verdict format,
same audit-chain entry structure.

## What's next

- See [`docs/architecture.md`](architecture.md) for component details and
  security boundaries.
- See [`docs/description.md`](description.md) for the FIND EVIL submission
  write-up.
- See [`samples/audit_chain_export.json`](../samples/audit_chain_export.json)
  for a static, server-verified proof artifact you can diff offline.
