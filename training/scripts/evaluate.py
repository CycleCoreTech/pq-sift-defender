"""Post-training evaluation: run test cases through the fine-tuned model."""

import json
import re
import sys
from pathlib import Path

import torch
from config_loader import load_config
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

CHATML_TEMPLATE = {
    "system": "<|im_start|>system\n{content}<|im_end|>\n",
    "human": "<|im_start|>user\n{content}<|im_end|>\n",
    "gpt": "<|im_start|>assistant\n",
}


def load_model(adapter_path: str, base_model: str, trust_remote_code: bool = True):
    """Load base model + LoRA adapter for inference."""
    tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=trust_remote_code)
    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        torch_dtype=torch.bfloat16,
        trust_remote_code=trust_remote_code,
        device_map="auto",
    )
    model = PeftModel.from_pretrained(model, adapter_path)
    model.eval()
    return model, tokenizer


def build_prompt(conversation: list[dict]) -> str:
    """Build chatml prompt from conversation turns (stop before final gpt turn)."""
    prompt = ""
    for turn in conversation:
        role = turn["from"]
        if role == "gpt" and turn == conversation[-1]:
            prompt += CHATML_TEMPLATE["gpt"]
            break
        template = CHATML_TEMPLATE.get(role, CHATML_TEMPLATE["human"])
        prompt += template.format(content=turn["value"])
    return prompt


def extract_verdict(text: str) -> str | None:
    """Extract verdict type from model output."""
    m = re.search(r"Verdict:\s*(PASS|FLAG|BLOCK)", text, re.IGNORECASE)
    return m.group(1).upper() if m else None


def run_eval(config: dict, adapter_path: str) -> dict:
    """Run evaluation on val set and test cases."""
    training_dir = Path(__file__).parent.parent
    prepared_dir = training_dir / config["data"]["base_dir"] / "prepared"
    val_path = prepared_dir / "val.jsonl"

    print("Loading model...")
    model, tokenizer = load_model(
        adapter_path,
        config["model"]["base"],
        config["model"]["trust_remote_code"],
    )

    results = {
        "verdict_accuracy": 0,
        "verdict_format_rate": 0,
        "per_verdict": {
            "PASS": {"correct": 0, "total": 0},
            "FLAG": {"correct": 0, "total": 0},
            "BLOCK": {"correct": 0, "total": 0},
        },
        "failures": [],
    }

    val_samples = [json.loads(l) for l in open(val_path) if l.strip()]
    total = 0
    correct = 0
    formatted = 0

    print(f"Evaluating {len(val_samples)} samples...")
    for i, sample in enumerate(val_samples):
        convs = sample["conversations"]
        expected_text = convs[-1]["value"]
        expected_verdict = extract_verdict(expected_text)
        if not expected_verdict:
            continue

        prompt_convs = convs[:-1] + [{"from": "gpt", "value": ""}]
        prompt = build_prompt(prompt_convs)

        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
        with torch.no_grad():
            output = model.generate(
                **inputs,
                max_new_tokens=150,
                temperature=0.1,
                do_sample=True,
                top_p=0.9,
                pad_token_id=tokenizer.pad_token_id or tokenizer.eos_token_id,
            )

        generated = tokenizer.decode(
            output[0][inputs["input_ids"].shape[1] :], skip_special_tokens=True
        )
        predicted_verdict = extract_verdict(generated)

        total += 1
        results["per_verdict"][expected_verdict]["total"] += 1

        if predicted_verdict:
            formatted += 1

        if predicted_verdict == expected_verdict:
            correct += 1
            results["per_verdict"][expected_verdict]["correct"] += 1
        else:
            results["failures"].append(
                {
                    "index": i,
                    "expected": expected_verdict,
                    "predicted": predicted_verdict,
                    "generated_text": generated[:200],
                    "quality": sample.get("quality", "?"),
                }
            )

        if (i + 1) % 20 == 0:
            print(
                f"  {i + 1}/{len(val_samples)} — accuracy so far: {correct}/{total} ({correct / max(total, 1) * 100:.1f}%)"
            )

    results["verdict_accuracy"] = correct / max(total, 1)
    results["verdict_format_rate"] = formatted / max(total, 1)
    results["total_evaluated"] = total
    results["total_correct"] = correct

    threshold = config["eval"]["pass_threshold"]
    results["passed"] = results["verdict_accuracy"] >= threshold

    print(f"\n{'=' * 50}")
    print(f"Verdict accuracy:    {results['verdict_accuracy']:.1%} ({correct}/{total})")
    print(f"Format compliance:   {results['verdict_format_rate']:.1%}")
    print(f"Pass threshold:      {threshold:.1%}")
    print(f"Result:              {'PASS' if results['passed'] else 'FAIL'}")
    print("\nPer-verdict breakdown:")
    for v, d in results["per_verdict"].items():
        if d["total"] > 0:
            print(f"  {v}: {d['correct']}/{d['total']} ({d['correct'] / d['total'] * 100:.1f}%)")

    if results["failures"]:
        print("\nFirst 5 failures:")
        for f in results["failures"][:5]:
            print(f"  expected={f['expected']} predicted={f['predicted']} Q={f['quality']}")
            print(f"    → {f['generated_text'][:100]}...")

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python evaluate.py <adapter_path> [profile]")
        sys.exit(1)
    adapter_path = sys.argv[1]
    profile = sys.argv[2] if len(sys.argv) > 2 else "standard"
    config = load_config(profile)
    results = run_eval(config, adapter_path)

    output_path = Path(adapter_path) / "eval_results.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved: {output_path}")
