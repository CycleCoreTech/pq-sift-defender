# pq-sift-defender

**Autonomous incident-response triage with defense-in-depth against prompt
injection and a post-quantum-signed audit trail.**

Apache 2.0. Runs a 1.5-billion-parameter open-weight model on CPU. No GPU required.

[![Submission video](https://img.shields.io/badge/submission-video-blue)](demo/submission-video.mp4)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)

![demo](demo/demo-1x.gif)

<sup>Two contrasting investigations at 1× speed, followed by independent audit-chain
verification against the public attestation API.
Full narrated walkthrough: <a href="demo/submission-video.mp4"><code>demo/submission-video.mp4</code></a></sup>

---

## What it does

pq-sift-defender reads a security alert — EDR record, WAF log, IDS event, phishing
report — and runs an autonomous DFIR investigation. The agent reasons about the alert
with a local LLM (Ollama-served `qwen2.5:1.5b`, CPU-only) and decides which forensic
tools to call: Volatility 3, The Sleuth Kit, ClamAV, YARA, Plaso, and a string
classifier for OWASP-class injection patterns. It returns a verdict (PASS / FLAG /
BLOCK) and a cryptographically signed, append-only chain of every action it took.

## Why this matters

Autonomous agents are powerful investigative tools, but they introduce a new class of
vulnerability: the agent itself becomes an attack surface. A crafted alert payload can
inject instructions that cause the agent to exfiltrate data, reach internal endpoints,
or suppress its own findings.

pq-sift-defender addresses both sides of this problem through two security boundaries
that are absent from conventional agentic IR tools.

### Agent-to-tool security boundary

Every string the agent generates as tool input is classified at microsecond latency by
a security-gates API before it reaches a downstream tool. If the agent is manipulated
into emitting an SSRF URL, a SQL injection payload, or a path-traversal string, the
boundary blocks the dispatch and records the interception as a signed entry on the
audit chain.

Concrete proof: [`samples/prompt_injection_alert.json`](samples/prompt_injection_alert.json)
plants a directive telling the agent to fetch `169.254.169.254` cloud metadata. The
1.5B model takes the bait. The security boundary catches it. The model was compromised;
the system was not.

### Post-quantum audit trail

Every dispatched tool call and every verdict is appended to an audit chain backed by a
public post-quantum signing API using ML-DSA-65 (NIST FIPS 204). The chain is exportable
as JSON and verifiable offline against the public key. ML-DSA-65 signatures resist quantum
cryptanalysis, so the audit trail remains verifiable and admissible decades from now. Any
third party can repeat the verification with just the chain ID.

## Architecture

![Architecture](docs/images/architecture.png)

See [`docs/architecture.md`](docs/architecture.md) for component details and
security boundaries.

## Deploy where the incident is

The agent runs on the affected server itself, including older hardware without a GPU.
Triage happens where the incident is occurring, not after evidence ships to a SOC. The
LLM, the DFIR tools, and the agent loop are all local.

| Resource | Requirement |
|---|---|
| RAM | 2-3 GB free |
| CPU | One modern x86_64 core |
| Disk | 5-10 GB |
| GPU | Not required |
| Python | 3.10+ |

## Evaluation

Ten sample alerts spanning benign logins, SSRF, SQL injection, command injection,
path traversal, prompt injection, and malware memory dumps. All ten produce correct
verdicts with zero false positives.

```
10/10 correct · 0 false positives · 4 s per triage · CPU-only · Apache 2.0
```

Tested on two CPUs with identical results:

| CPU | Simple triage | 10-case average |
|---|---|---|
| Intel Core i9-14900KF | 4 s | 14.5 s |
| AMD Ryzen 7 7800X3D | 4 s | — |

Full results: [`docs/accuracy.md`](docs/accuracy.md). A static proof artifact at
[`samples/audit_chain_export.json`](samples/audit_chain_export.json) shows a real
signed audit chain from a real investigation — `verify.valid=True`, three entries,
each with a 3,309-byte ML-DSA-65 signature, hash-linked.

## Model selection

We evaluated six model variants across the qwen2.5, qwen3, and qwen3.5 families.
The qwen2.5:1.5b consistently outperforms newer "thinking" models on this workload
because the task is structured tool-calling, not deep reasoning. Thinking-mode models
(qwen3, qwen3.5) generate extensive internal reasoning tokens that multiply CPU
latency by 5-17x and frequently produce false positives by overthinking benign alerts.
Smaller models (qwen2.5:0.5b) cannot reliably produce structured tool calls. The
1.5B parameter count is the floor for reliable function-calling on CPU.

## Try it out

See [`docs/try-it-out.md`](docs/try-it-out.md) for the full setup guide.

```bash
git clone https://github.com/CycleCoreTech/pq-sift-defender
cd pq-sift-defender
pip install -e ".[dev]"
cp .env.example .env  # add CYCLECORE_PQ_API_KEY (free tier — 1k ops/day)

ollama pull qwen2.5:1.5b
pq-sift-defender investigate samples/path_traversal.json
```

## Fully offline / air-gapped mode

The entire agent runs with zero network calls — no cloud APIs, no telemetry, no data
leaving the host:

```bash
PQ_AUDIT_BACKEND=stub pq-sift-defender investigate samples/path_traversal.json
```

The LLM and all DFIR tools already run locally. Setting `PQ_AUDIT_BACKEND=stub` switches
the audit chain to an in-memory hash-linked chain. For on-premises post-quantum signing
without the public cloud, deploy a PQ Box appliance or self-hosted instance behind your
firewall. See [`docs/try-it-out.md`](docs/try-it-out.md#advanced-airgapped-or-on-prem-deployment).

## Backend services

The agent integrates two public CycleCore APIs. Both have demo tiers that require no API
key, and free tiers (1,000 operations per day) that do.

| API | Endpoint | Purpose |
|---|---|---|
| SecurityGates | [`sg-api.cyclecore.ai/docs`](https://sg-api.cyclecore.ai/docs) | OWASP-class injection, traversal, and SSRF detection at microsecond latency |
| PQ Crypto | [`pq-api.cyclecore.ai/openapi.json`](https://pq-api.cyclecore.ai/openapi.json) | ML-DSA-65 signing and chain attestation |

Both APIs are separately replaceable. Point `CYCLECORE_SG_BASE_URL` or
`CYCLECORE_PQ_BASE_URL` at any server implementing the same OpenAPI spec.

## DFIR toolchain

Standard SANS SIFT Workstation 2026.04 toolchain. Compatible with any Linux that has
these tools available.

```bash
sudo apt install -y sleuthkit clamav
pip install --user volatility3 plaso yara-python
```

| Tool | Backing CLI / library |
|---|---|
| `vol_pslist`, `vol_netscan` | `vol` (PyPI `volatility3`) |
| `tsk_mmls`, `tsk_fls` | `mmls`, `fls` (apt `sleuthkit`) |
| `clamav_scan` | `clamscan` (apt `clamav`) |
| `yara_match` | `yara-python` |
| `plaso_timeline` | `log2timeline`, `psort` (PyPI `plaso`) |
| `sift_classify` | CycleCore SecurityGates API |

## Submission

Built for the [SANS FIND EVIL](https://findevil.devpost.com/) hackathon by
[CycleCore Technologies](https://cyclecore.ai).

## License

Apache 2.0 — see [`LICENSE`](LICENSE). Patent-grant scope is clarified in
[`NOTICE`](NOTICE).
