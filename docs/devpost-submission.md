# Devpost Submission — SANS FIND EVIL Hackathon

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
own manipulation — and produce a forensically sound audit trail in the process.

### What it does

pq-sift-defender reads a security alert (EDR record, WAF log, IDS event) and runs
an autonomous DFIR investigation using a 1.5-billion-parameter open-weight model
running entirely on CPU. The agent decides which forensic tools to call —
Volatility 3, The Sleuth Kit, ClamAV, YARA, Plaso — and returns a verdict with a
cryptographically signed, append-only chain of every action it took.

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

The agent layer is Apache 2.0 licensed Python. The reasoning model is
`qwen2.5:1.5b` served by Ollama on CPU — no GPU, no cloud inference. We evaluated
seven model variants across the qwen2.5, qwen3, and qwen3.5 families and found that
the 2024 qwen2.5:1.5b consistently outperforms newer thinking-mode models on this
workload. Thinking-mode models generate extensive internal reasoning tokens that
multiply CPU latency by 5-17x and frequently produce false positives.

The agent calls two public CycleCore APIs as backend services: SecurityGates for
microsecond injection detection and PQ Crypto for post-quantum signing. Both have
unauthenticated demo tiers. For air-gapped environments, both can be replaced with
self-hosted instances or a PQ Box hardware appliance.

DFIR tools are the standard SANS SIFT Workstation 2026.04 toolchain.

### Challenges we ran into

Getting a 1.5-billion-parameter model to produce reliable structured tool calls on
CPU required careful prompt engineering and a recovery mechanism for blocked inputs.
When the security boundary blocks a tool call, the model needs to recognize the
interception as evidence of a real threat rather than stalling. We solved this with a
recovery prompt that redirects the model to issue a verdict citing the boundary
interception.

### Accomplishments that we're proud of

Ten sample cases. Ten correct verdicts. Zero false positives. Four seconds per
triage on CPU. Tested on both Intel and AMD processors with identical results. A
model that costs nothing to run, requires no cloud inference, and produces a
forensically verifiable audit trail signed with post-quantum cryptography.

The security boundary demonstration is the centerpiece: the model is deliberately
small enough to be manipulable, which proves that the defense works precisely because
it operates below the model's reasoning layer, not inside it.

### What we learned

Newer is not always better. We tested seven models including the latest qwen3 and
qwen3.5 families. The 2024 qwen2.5:1.5b outperformed all of them on this workload
because structured tool-calling does not require deep reasoning — it requires reliable
function-call formatting and fast inference. Thinking-mode models overthink benign
alerts, generate excessive tool calls, and take 5-17x longer on CPU.

### What's next for pq-sift-defender

Production deployment as a continuously running security daemon. At four seconds per
triage with negligible CPU overhead, the agent can monitor alert streams in real time
on the affected server itself. Expanding the DFIR toolchain to include
cloud-native evidence sources (CloudTrail, GuardDuty, Kubernetes audit logs) and
integrating with SOAR platforms for automated escalation.

## Built with

Python, Ollama, qwen2.5, Volatility 3, The Sleuth Kit, ClamAV, YARA, Plaso,
post-quantum cryptography, ML-DSA-65

## Try it out

https://github.com/CycleCoreTech/pq-sift-defender

## Video

demo/submission-video.mp4
(Upload to YouTube as unlisted, then paste the YouTube URL here)
