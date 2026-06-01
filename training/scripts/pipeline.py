#!/usr/bin/env python3
"""
pq-sift-defender training pipeline orchestrator.

Usage:
    python pipeline.py [profile] [--stage prepare|train|eval|export|all]
                                 [--adapter-path PATH]
                                 [--override key=value ...]

Examples:
    python pipeline.py fast --stage all
    python pipeline.py standard --stage prepare
    python pipeline.py thorough --stage train
    python pipeline.py standard --stage eval --adapter-path output/standard_20260601/
    python pipeline.py standard --override training.epochs=5 data.batches.2.weight=3.0
"""

import argparse
import json
import sys
from pathlib import Path

from config_loader import config_summary, load_config


def parse_overrides(override_list: list[str]) -> dict:
    """Parse key=value overrides into nested dict. Supports dot notation."""
    result = {}
    for item in override_list:
        key, value = item.split("=", 1)
        parts = key.split(".")

        # Auto-cast value
        try:
            value = int(value)
        except ValueError:
            try:
                value = float(value)
            except ValueError:
                if value.lower() in ("true", "false"):
                    value = value.lower() == "true"

        d = result
        for p in parts[:-1]:
            d = d.setdefault(p, {})
        d[parts[-1]] = value

    return result


def main():
    parser = argparse.ArgumentParser(description="pq-sift-defender training pipeline")
    parser.add_argument(
        "profile", nargs="?", default="standard", help="Config profile (fast/standard/thorough)"
    )
    parser.add_argument(
        "--stage", default="all", choices=["prepare", "train", "eval", "export", "all"]
    )
    parser.add_argument("--adapter-path", help="Path to adapter for eval/export stages")
    parser.add_argument("--override", nargs="*", default=[], help="Config overrides as key=value")
    args = parser.parse_args()

    overrides = parse_overrides(args.override) if args.override else None
    config = load_config(args.profile, overrides)

    print("=" * 60)
    print("pq-sift-defender training pipeline")
    print(f"  {config_summary(config)}")
    print(f"  stage={args.stage}")
    if overrides:
        print(f"  overrides={json.dumps(overrides)}")
    print("=" * 60)
    print()

    adapter_path = args.adapter_path

    if args.stage in ("prepare", "all"):
        print("━" * 40)
        print("STAGE: prepare")
        print("━" * 40)
        from prepare import prepare

        stats = prepare(config)
        print()

    if args.stage in ("train", "all"):
        print("━" * 40)
        print("STAGE: train")
        print("━" * 40)
        from train import train

        adapter_path = str(train(config))
        print()

    if args.stage in ("eval", "all"):
        if not adapter_path:
            print("ERROR: --adapter-path required for eval stage")
            sys.exit(1)
        print("━" * 40)
        print("STAGE: eval")
        print("━" * 40)
        from evaluate import run_eval

        results = run_eval(config, adapter_path)
        with open(Path(adapter_path) / "eval_results.json", "w") as f:
            json.dump(results, f, indent=2)
        if not results["passed"]:
            print(
                f"\n⚠ Eval BELOW threshold ({results['verdict_accuracy']:.1%} < {config['eval']['pass_threshold']:.1%})"
            )
            print("  Consider: more epochs, more data, higher batch 3 weight, or lower threshold.")
        print()

    if args.stage in ("export", "all"):
        if not adapter_path:
            print("ERROR: --adapter-path required for export stage")
            sys.exit(1)
        print("━" * 40)
        print("STAGE: export")
        print("━" * 40)
        from export import export

        export(config, adapter_path)
        print()

    print("=" * 60)
    print("Pipeline complete.")
    if adapter_path:
        print(f"  Adapter: {adapter_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
