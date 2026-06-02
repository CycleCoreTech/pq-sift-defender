# Devpost Submission -- SANS FIND EVIL Hackathon

Use this as copy-paste source for the Devpost form fields.

---

## Project name

pq-sift-defender

## Tagline

The model was compromised. The system was not.

## Description

### Inspiration

Autonomous AI agents are transforming incident response, but they introduce a
vulnerability that most IR tools ignore: the agent itself is an attack surface. A
crafted alert payload can inject instructions that cause the agent to exfiltrate
data, reach internal endpoints, or suppress its own findings. We built
pq-sift-defender to demonstrate that an autonomous IR agent can defend against its
own manipulation -- and produce a forensically sound audit trail in the process.

### What it does

pq-sift-defender reads a security alert (EDR record, WAF log, IDS event) and runs
an autonomous DFIR investigation using a fine-tuned 1.5-billion-parameter
open-weight model running entirely on CPU. The agent decides which forensic tools
to call -- Volatility 3, The Sleuth Kit, ClamAV, YARA, Plaso -- and returns a
verdict (**PASS** / **FLAG** / **BLOCK**) with a cryptographically signed,
append-only chain of every action it took.

Two security boundaries that are absent from conventional agentic IR tools are
present here by construction:

1. **Agent-to-tool security boundary.** Every tool input the agent generates is
   classified at microsecond latency before it reaches a downstream tool. If the
   agent is manipulated into emitting an SSRF URL or injection payload, the boundary
   blocks the dispatch and records the interception on the audit chain. The 1.5B
   model takes the bait on prompt injection. The security boundary catches it. The
   model was compromised; the system was not.

2. **Post-quantum audit trail.** Every tool call and every verdict is signed with
   ML-DSA-65 (NIST FIPS 204) and appended to a tamper-proof chain. The signatures
   resist quantum cryptanalysis. The audit trail remains verifiable and admissible
   decades from now. Any third party can repeat the verification with just the chain
   ID.

### How we built it

The agent layer is Apache 2.0 licensed Python. The reasoning model is a QLoRA
fine-tuned Qwen2.5-1.5B-Instruct served by Ollama at Q4_K_M quantization on
CPU -- no GPU, no cloud inference. We evaluated seven model variants across the
qwen2.5, qwen3, and qwen3.5 families and found that the 2024 qwen2.5:1.5b
consistently outperforms newer thinking-mode models on this workload.
Thinking-mode models generate extensive internal reasoning tokens that multiply
CPU latency by 5-17x and frequently produce false positives.

Fine-tuning was performed with a config-driven training pipeline on 785 unique
ShareGPT-format samples across 7 source batches (benign PASS, attack BLOCK,
boundary recovery, FLAG + format, CVE-grounded, hard PASS, format edge). The
pipeline supports per-batch oversampling, quality-based loss scaling, hash-based
deduplication, and system prompt injection at prepare time.

The agent calls two public CycleCore APIs as backend services: SecurityGates for
microsecond injection detection and PQ Crypto for post-quantum signing. Both have
unauthenticated demo tiers and free tiers (1,000 ops/day). For air-gapped
environments, both can be replaced with self-hosted instances or a PQ Box hardware
appliance.

DFIR tools are the standard SANS SIFT Workstation 2026.04 toolchain.

### Challenges we ran into

Getting a 1.5-billion-parameter model to produce reliable structured tool calls on
CPU required careful prompt engineering, fine-tuning, and a recovery mechanism for
blocked inputs. When the security boundary blocks a tool call, the model needs to
recognize the interception as evidence of a real threat rather than stalling. We
solved this through training on boundary recovery examples where the model learns
to cite the interception in its verdict.

Non-determinism was another challenge: the same input could produce 1 or 4 tool
calls depending on sampling. We solved this with temperature=0.0 and a 512-token
generation cap, making the agent fully deterministic.

### Accomplishments that we're proud of

136 held-out samples. 96.3% accuracy. 100% on BLOCK verdicts -- zero missed
attacks. Under 10 seconds per triage on CPU. Tested on both Intel and AMD
processors with identical results. A fine-tuned model that costs nothing to run,
requires no cloud inference, and produces a forensically verifiable audit trail
signed with post-quantum cryptography.

The security boundary demonstration is the centerpiece: the model is deliberately
small enough to be manipulable, which proves that the defense works precisely
because it operates below the model's reasoning layer, not inside it.

### On autonomous execution and self-correction

The tiebreaker criterion asks whether the agent self-corrects. We built something
stronger: a system where self-correction is structurally unnecessary for the
threat class that matters most. The security boundary operates below the model's
reasoning layer, so the system never relies on the model to catch its own
mistakes. The model was compromised; the system was not. This is defense in depth,
not defense by hope.

A frontier model can self-correct, but it can also be talked out of
self-correcting. A 1.5B specialist doesn't need to design a hydroelectric
dam -- it needs to classify alerts fast and correctly. Pair that with an
architectural boundary that the model cannot reason around, and you get a system
where 100% of attacks are caught regardless of whether the model cooperates.
The slight conservative bias toward false positives is the right tradeoff for a
security tool -- every antivirus on the market has occasional false positives,
but zero missed attacks is non-negotiable.

### What we learned

Newer is not always better. We tested seven models including the latest qwen3 and
qwen3.5 families. The 2024 qwen2.5:1.5b outperformed all of them on this workload
because structured tool-calling does not require deep reasoning -- it requires
reliable function-call formatting and fast inference. Thinking-mode models
overthink benign alerts, generate excessive tool calls, and take 5-17x longer on
CPU.

Fine-tuning a 1.5B model on 785 domain-specific examples closed most of the
accuracy gap with larger models while keeping inference under 10 seconds on a
single CPU core. The model is a specialist: it does one job, on one class of
input, with one set of tools, and it does it well enough that the system around it
can be simple and auditable.

### What's next for pq-sift-defender

Production deployment as a continuously running security daemon. At under 10
seconds per triage with negligible CPU overhead, the agent can monitor alert
streams in real time on the affected server itself. Expanding the DFIR toolchain
to include cloud-native evidence sources (CloudTrail, GuardDuty, Kubernetes audit
logs) and integrating with SOAR platforms for automated escalation.

## Built with

Python, Ollama, Qwen2.5, QLoRA, Volatility 3, The Sleuth Kit, ClamAV, YARA,
Plaso, post-quantum cryptography, ML-DSA-65

## Try it out

https://github.com/CycleCoreTech/pq-sift-defender

## Links

- Repository: https://github.com/CycleCoreTech/pq-sift-defender
- Model: https://huggingface.co/CycleCoreTechnologies/pq-sift-defender-Q4_K_M
- Video: demo/submission-video.mp4
