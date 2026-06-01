#!/usr/bin/env python3
"""Merge supplementary samples with existing batches."""

import json
from pathlib import Path

DATA_DIR = Path("/home/rain/pq-sift-defender/training/data/")

# Batch 2: merge prompt injection into attack_block
print("Merging prompt injection into batch_2_attack_block...")
existing = []
with open(DATA_DIR / "batch_2_attack_block.jsonl") as f:
    for line in f:
        existing.append(json.loads(line.strip()))

extra = []
with open(DATA_DIR / "wcn_supplementary_batch2_prompt_injection.jsonl") as f:
    for line in f:
        extra.append(json.loads(line.strip()))

merged = existing + extra
print(f"  {len(existing)} + {len(extra)} = {len(merged)} samples")

with open(DATA_DIR / "batch_2_attack_block.jsonl", "w") as f:
    for s in merged:
        f.write(json.dumps(s, ensure_ascii=False) + "\n")

# Batch 3: merge supplementary into boundary_recovery
print("Merging supplementary into batch_3_boundary_recovery...")
existing = []
with open(DATA_DIR / "batch_3_boundary_recovery.jsonl") as f:
    for line in f:
        existing.append(json.loads(line.strip()))

extra = []
with open(DATA_DIR / "wcn_supplementary_batch3_boundary_recovery.jsonl") as f:
    for line in f:
        extra.append(json.loads(line.strip()))

merged = existing + extra
print(f"  {len(existing)} + {len(extra)} = {len(merged)} samples")

with open(DATA_DIR / "batch_3_boundary_recovery.jsonl", "w") as f:
    for s in merged:
        f.write(json.dumps(s, ensure_ascii=False) + "\n")

# Update all_merged
print("Rebuilding all_merged.jsonl...")
all_samples = []
for batch_file in [
    "batch_1_benign_pass.jsonl",
    "batch_2_attack_block.jsonl",
    "batch_3_boundary_recovery.jsonl",
    "batch_4_flag_and_format.jsonl",
]:
    with open(DATA_DIR / batch_file) as f:
        for line in f:
            all_samples.append(json.loads(line.strip()))

with open(DATA_DIR / "all_merged.jsonl", "w") as f:
    for s in all_samples:
        f.write(json.dumps(s, ensure_ascii=False) + "\n")

print(f"  all_merged.jsonl: {len(all_samples)} total samples")

# Split into train/val (90/10)
import random

random.seed(42)
random.shuffle(all_samples)
split = int(len(all_samples) * 0.9)
with open(DATA_DIR / "train.jsonl", "w") as f:
    for s in all_samples[:split]:
        f.write(json.dumps(s, ensure_ascii=False) + "\n")
with open(DATA_DIR / "val.jsonl", "w") as f:
    for s in all_samples[split:]:
        f.write(json.dumps(s, ensure_ascii=False) + "\n")
print(f"  train.jsonl: {split} samples")
print(f"  val.jsonl: {len(all_samples) - split} samples")
