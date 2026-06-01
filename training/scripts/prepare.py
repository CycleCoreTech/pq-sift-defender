"""Data preparation: load batches, apply weights, deduplicate, split."""

import hashlib
import json
import random
from dataclasses import dataclass
from pathlib import Path

from config_loader import load_config, resolve_data_path


@dataclass
class WeightedSample:
    data: dict
    weight: float  # combined batch_weight * quality_weight
    source: str  # which batch file it came from
    quality: str  # A/B/C


def replace_system_prompt(sample: dict, new_prompt: str) -> dict:
    """Swap the system prompt in a conversation sample."""
    if sample["conversations"][0]["from"] == "system":
        sample["conversations"][0]["value"] = new_prompt
    return sample


def load_and_weight(config: dict) -> tuple[list[WeightedSample], dict]:
    """Load all batches, apply batch and quality weights, deduplicate."""
    quality_weights = config["data"]["quality_weights"]
    prompt_cfg = config.get("system_prompt", {})
    do_replace = prompt_cfg.get("replace", False)
    new_prompt = prompt_cfg.get("text", "").strip() if do_replace else None
    samples = []
    seen = set()
    stats = {
        "per_batch": {},
        "per_quality": {"A": 0, "B": 0, "C": 0},
        "per_verdict": {"PASS": 0, "FLAG": 0, "BLOCK": 0},
        "duplicates_removed": 0,
        "total_raw": 0,
        "total_unique": 0,
    }

    for batch_cfg in config["data"]["batches"]:
        fpath = resolve_data_path(config, batch_cfg["file"])
        if not fpath.exists():
            print(f"  SKIP {batch_cfg['file']} (not found)")
            continue

        label = batch_cfg.get("label", batch_cfg["file"])
        batch_weight = batch_cfg["weight"]
        batch_count = 0

        for line in open(fpath):
            line = line.strip()
            if not line:
                continue
            stats["total_raw"] += 1

            if config["data"].get("deduplicate", True):
                h = hashlib.md5(line.encode()).hexdigest()
                if h in seen:
                    stats["duplicates_removed"] += 1
                    continue
                seen.add(h)

            d = json.loads(line)
            assert "conversations" in d
            assert d["conversations"][0]["from"] == "system"
            assert d["conversations"][-1]["from"] == "gpt"
            assert "Verdict:" in d["conversations"][-1]["value"]

            if new_prompt:
                d = replace_system_prompt(d, new_prompt)

            quality = d.get("quality", "A")
            q_weight = quality_weights.get(quality, 1.0)
            combined_weight = batch_weight * q_weight

            samples.append(
                WeightedSample(
                    data=d,
                    weight=combined_weight,
                    source=label,
                    quality=quality,
                )
            )
            batch_count += 1

            stats["per_quality"][quality] = stats["per_quality"].get(quality, 0) + 1

            final = d["conversations"][-1]["value"]
            for v in ("BLOCK", "FLAG", "PASS"):
                if v in final:
                    stats["per_verdict"][v] += 1
                    break

        stats["per_batch"][label] = batch_count

    stats["total_unique"] = len(samples)
    return samples, stats


def apply_oversampling(samples: list[WeightedSample], seed: int) -> list[WeightedSample]:
    """Oversample/undersample based on weights. weight=1.5 means 50% chance of duplication."""
    rng = random.Random(seed)
    result = []
    for s in samples:
        copies = int(s.weight)
        fractional = s.weight - copies
        for _ in range(copies):
            result.append(s)
        if rng.random() < fractional:
            result.append(s)
    return result


def split_train_val(samples: list[WeightedSample], val_ratio: float, seed: int):
    """Stratified-ish split: shuffle then split, preserving approximate distributions."""
    rng = random.Random(seed)
    indices = list(range(len(samples)))
    rng.shuffle(indices)
    split_idx = int(len(indices) * (1 - val_ratio))
    train = [samples[i] for i in indices[:split_idx]]
    val = [samples[i] for i in indices[split_idx:]]
    return train, val


def write_jsonl(samples: list[WeightedSample], path: Path):
    with open(path, "w") as f:
        for s in samples:
            f.write(json.dumps(s.data) + "\n")


def write_weighted_jsonl(samples: list[WeightedSample], path: Path):
    """Write JSONL with weight field injected (for weighted loss during training)."""
    with open(path, "w") as f:
        for s in samples:
            row = {**s.data, "_weight": s.weight, "_source": s.source}
            f.write(json.dumps(row) + "\n")


def prepare(config: dict) -> dict:
    """Full preparation pipeline. Returns stats dict."""
    seed = config["data"]["seed"]
    training_dir = Path(__file__).parent.parent
    data_dir = training_dir / config["data"]["base_dir"]

    print("Loading and weighting samples...")
    samples, stats = load_and_weight(config)

    print(
        f"  Raw: {stats['total_raw']}, Unique: {stats['total_unique']}, "
        f"Dupes removed: {stats['duplicates_removed']}"
    )
    print(f"  Per batch: {stats['per_batch']}")
    print(f"  Quality: {stats['per_quality']}")
    print(f"  Verdicts: {stats['per_verdict']}")

    print("Applying oversampling...")
    expanded = apply_oversampling(samples, seed)
    print(f"  After oversampling: {len(expanded)} (from {len(samples)})")

    print("Splitting train/val...")
    train, val = split_train_val(expanded, config["data"]["val_ratio"], seed)
    print(f"  Train: {len(train)}, Val: {len(val)}")

    # Write outputs
    prepared_dir = data_dir / "prepared"
    prepared_dir.mkdir(exist_ok=True)

    write_jsonl(train, prepared_dir / "train.jsonl")
    write_jsonl(val, prepared_dir / "val.jsonl")
    write_weighted_jsonl(train, prepared_dir / "train_weighted.jsonl")

    # Write stats
    stats["after_oversampling"] = len(expanded)
    stats["train_count"] = len(train)
    stats["val_count"] = len(val)

    weight_dist = {}
    for s in expanded:
        bucket = f"{s.weight:.1f}"
        weight_dist[bucket] = weight_dist.get(bucket, 0) + 1
    stats["weight_distribution"] = weight_dist

    with open(prepared_dir / "stats.json", "w") as f:
        json.dump(stats, f, indent=2)

    print(f"  Weight distribution: {weight_dist}")
    print(f"  Written to {prepared_dir}/")
    return stats


if __name__ == "__main__":
    import sys

    profile = sys.argv[1] if len(sys.argv) > 1 else "standard"
    config = load_config(profile)
    from config_loader import config_summary

    print(f"Config: {config_summary(config)}")
    print()
    prepare(config)
