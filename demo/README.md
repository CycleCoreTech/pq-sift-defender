# Demo assets

| File | Format | Duration | Use |
|---|---|---|---|
| `demo.cast` | asciinema v2 | source recording | replays in any asciinema-compatible viewer |
| `demo-1x.gif` | GIF, 1× speed | 25 s | **README primary embed — natural reading pace** |
| `demo.gif` | GIF, 2× speed | 9 s | quick TL;DR visual |
| `demo.mp4` | H.264 video, 1× speed | 25 s | Devpost / YouTube upload candidate; download link |
| `run_demo.sh` | shell script | — | source-of-truth for re-recording; runs the contrasting brief+full investigations with sleeps |
| `archive/v1/` | — | — | prior iteration (cyan Unicode boxes, single case) |
| `archive/v2/` | — | — | prior iteration (plain ASCII rules, single case) |

## What this demo shows

Two contrasting cases, then an independent audit-chain verification:

1. **Benign login alert** in `--brief` mode → `Verdict: PASS`, no reasoning prose. Shows the executive-summary capability for high-volume/known-good triage.
2. **Path-traversal attempt** in default mode → `Verdict: BLOCK — path traversal pattern '?name=../../../../etc/passwd'`. The first line is the operator's quick-glance answer (full color, bold). The agent's reasoning is shown below as **fine print** (dim, behind a thin cyan rail) — capability visible for those who pause; not competing for attention from those who don't.
3. **Audit chain verified** → `valid: True, chain_length: 3 entries`, with the `>>> SIGNED WITH ML-DSA-65 (FIPS 204) — VERIFIABLE OFFLINE <<<` callout. Server-side independent verification, not a self-claim.

## Play the cast locally

```bash
asciinema play demo/demo.cast
```

Speed is 1× by default. Use `-s 2` to play at 2× speed.

## Re-record (after CLI changes)

The recording wraps the shell script `run_demo.sh`, which runs three
`pq-sift-defender` subcommands back-to-back with `sleep 3` between sections.
The CLI itself is unchanged — sleeps live in the shell script, not in the
agent. An analyst running `pq-sift-defender investigate` for real work
sees zero added latency.

```bash
asciinema rec \
  --command "demo/run_demo.sh samples/path_traversal.json" \
  --rows 30 --cols 100 \
  --title "pq-sift-defender — IR triage with PQ-signed audit chain" \
  --idle-time-limit 4 \
  --overwrite \
  demo/demo.cast
```

Then regenerate the artifacts:

```bash
# 1× speed, natural reading pace (README primary)
agg --speed 1 --idle-time-limit 4 --font-size 14 --theme monokai \
    demo/demo.cast demo/demo-1x.gif

# 2× speed, TL;DR cut
agg --speed 2 --idle-time-limit 2 --font-size 14 --theme monokai \
    demo/demo.cast demo/demo.gif

# MP4 from the 1× GIF (uses the existing render)
ffmpeg -y -i demo/demo-1x.gif -movflags faststart -pix_fmt yuv420p \
    -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2,fps=15" \
    -c:v libx264 -preset slow -crf 23 \
    demo/demo.mp4
```

`agg` is the asciinema team's GIF generator
(`cargo install --git https://github.com/asciinema/agg`). `ffmpeg` is
standard on most distros.

## What the demo shows

1. Banner with version + DEMO label
2. Sample alert info (path, summary, expected behavior)
3. Live investigation — pre-filter result, each tool call with arguments and one-line summary, every chain entry signed
4. Verdict box with first line color-coded (BLOCK red / FLAG yellow / PASS green)
5. Audit chain verification — `valid=True`, `chain_length=3`, latency, and the ML-DSA-65 signature note
6. Audit chain export — entry count and what each entry represents
7. Closing box — version, GitHub URL, cyclecore.ai

The whole flow runs on a single command; recording captures every step exactly as it happens. No edits, no cuts.
