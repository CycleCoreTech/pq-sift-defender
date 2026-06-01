#!/usr/bin/env bash
# Recording script for the narrated Devpost submission video.
#
# Difference from run_demo.sh: uses prompt_injection_alert (the money
# shot — model takes the bait, boundary catches it) instead of
# path_traversal. Longer sleeps between scenes for voice-over pacing.
#
# Record with:
#   asciinema rec --command "demo/run_narrated_demo.sh" --cols 100 --rows 30 \
#                 --title "pq-sift-defender" --idle-time-limit 8 --overwrite \
#                 demo/narrated.cast

set -euo pipefail

INV2_OUT="$(mktemp)"
trap 'rm -f "$INV2_OUT"' EXIT

clear

# --- Title card — Scene 1 (audio: 48s) ------------------------------------
# Narration: problem statement + "Let me show you what that looks like."
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
sleep 48

clear

# --- Benign case — Scene 2 (audio: ~22s, agent ~4s) -----------------------
# Narration: "First, a baseline..." through "no GPU."
pq-sift-defender investigate samples/benign_login_alert.json --brief
sleep 28

# --- Prompt injection — Scene 3 (audio: ~62s, agent ~5s) -----------------
# Narration: "Now the case that matters..." — THE MONEY SHOT
script -q -c "pq-sift-defender investigate samples/prompt_injection_alert.json" "$INV2_OUT"
sleep 64

CHAIN_ID="$(grep -oE '[0-9a-f]{32}' "$INV2_OUT" | head -1)"
if [ -z "${CHAIN_ID:-}" ]; then
  echo "ERROR: could not extract chain_id from second investigate run" >&2
  exit 1
fi

# --- Audit verification — Scene 4 (audio: ~35s, verify ~2s) ---------------
# Narration: "Now we verify..." through "just the chain ID."
pq-sift-defender audit-verify "$CHAIN_ID"
sleep 37

# --- Closing — Scene 5 (audio: ~17s) --------------------------------------
# Narration: "Ten sample cases..." through "Links below."
printf '\n'
printf '\033[36m┌──────────────────────────────────────────────────────────┐\033[0m\n'
printf '\033[36m│                                                          │\033[0m\n'
printf '\033[36m│  \033[1mpq-sift-defender v0.2.0\033[0m\033[36m                                 │\033[0m\n'
printf '\033[36m│  \033[2m10/10 · 4s triage · CPU-only · Apache 2.0\033[0m\033[36m               │\033[0m\n'
printf '\033[36m│  \033[2mgithub.com/CycleCoreTech/pq-sift-defender\033[0m\033[36m               │\033[0m\n'
printf '\033[36m│                                                          │\033[0m\n'
printf '\033[36m└──────────────────────────────────────────────────────────┘\033[0m\n'
printf '\n'
sleep 20
