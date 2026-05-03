#!/usr/bin/env bash
# Shell-driven demo for asciinema recording.
#
# Pacing strategy: sleeps live in the SHELL between commands, never inside
# the agent. An IR analyst running `pq-sift-defender investigate` for real
# work sees zero added latency.
#
# Two contrasting cases:
#   1. Benign login alert in --brief mode  (executive summary)
#   2. Path traversal in default mode      (verdict + reasoning fine print)
# Followed by an independent audit-chain verification on case 2.
#
# Usage:
#   demo/run_demo.sh
#
# To record:
#   asciinema rec --command "demo/run_demo.sh" --cols 100 --rows 30 \
#                 --idle-time-limit 4 --overwrite demo/demo.cast

set -euo pipefail

INV2_OUT="$(mktemp)"
trap 'rm -f "$INV2_OUT"' EXIT

clear

# --- Title card (first frame = GIF/MP4 thumbnail) --------------------------
printf '\n'
printf '\033[36m══════════════════════════════════════════════════════════\033[0m\n'
printf '  \033[1mpq-sift-defender\033[0m\n'
printf '\033[36m══════════════════════════════════════════════════════════\033[0m\n'
printf '\n'
printf '  Autonomous IR triage agent\n'
printf '  \033[2m1.5B model · CPU-only · PQ-signed audit trail\033[0m\n'
printf '\n'
printf '  \033[2mSANS FIND EVIL Hackathon 2026 · cyclecore.ai\033[0m\n'
printf '\n'
sleep 3

clear

# --- 1. Benign case in BRIEF mode -------------------------------------------
pq-sift-defender investigate samples/benign_login_alert.json --brief
sleep 4

# --- 2. Block case in FULL mode (verdict + dim'd reasoning) -----------------
pq-sift-defender investigate samples/path_traversal.json | tee "$INV2_OUT"
sleep 5

CHAIN_ID="$(grep -oE '[0-9a-f]{32}' "$INV2_OUT" | head -1)"
if [ -z "${CHAIN_ID:-}" ]; then
  echo "ERROR: could not extract chain_id from second investigate run" >&2
  exit 1
fi

# --- 3. Audit chain verification on case 2 (climactic moment) ---------------
pq-sift-defender audit-verify "$CHAIN_ID"
sleep 4

# --- 4. Closing box ---------------------------------------------------------
printf '\n'
printf '\033[36m┌──────────────────────────────────────────────────────────┐\033[0m\n'
printf '\033[36m│                                                          │\033[0m\n'
printf '\033[36m│  \033[1mpq-sift-defender v0.2.0\033[0m\033[36m                                 │\033[0m\n'
printf '\033[36m│  \033[2mgithub.com/CycleCoreTech/pq-sift-defender\033[0m\033[36m               │\033[0m\n'
printf '\033[36m│  \033[2mcyclecore.ai\033[0m\033[36m                                            │\033[0m\n'
printf '\033[36m│                                                          │\033[0m\n'
printf '\033[36m└──────────────────────────────────────────────────────────┘\033[0m\n'
printf '\n'
sleep 2
