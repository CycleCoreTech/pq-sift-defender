"""Export: merge LoRA adapter → full model → GGUF → Ollama Modelfile."""

import shutil
import sys
from pathlib import Path

from config_loader import load_config


def merge_adapter(config: dict, adapter_path: str) -> Path:
    """Merge LoRA adapter back into base model."""
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    training_dir = Path(__file__).parent.parent
    merged_dir = Path(adapter_path).parent / f"{Path(adapter_path).name}_merged"

    if merged_dir.exists():
        print(f"  Merged dir exists, removing: {merged_dir}")
        shutil.rmtree(merged_dir)

    print(f"  Loading base model: {config['model']['base']}")
    base = AutoModelForCausalLM.from_pretrained(
        config["model"]["base"],
        torch_dtype=torch.float16,
        trust_remote_code=config["model"]["trust_remote_code"],
    )

    print(f"  Loading adapter: {adapter_path}")
    model = PeftModel.from_pretrained(base, adapter_path)

    print("  Merging...")
    merged = model.merge_and_unload()
    merged.save_pretrained(str(merged_dir))

    tokenizer = AutoTokenizer.from_pretrained(
        config["model"]["base"],
        trust_remote_code=config["model"]["trust_remote_code"],
    )
    tokenizer.save_pretrained(str(merged_dir))

    print(f"  Merged model saved: {merged_dir}")
    return merged_dir


def convert_gguf(merged_dir: Path, quant: str) -> Path:
    """Convert merged model to GGUF format."""
    import subprocess

    gguf_dir = merged_dir.parent / "gguf"
    gguf_dir.mkdir(exist_ok=True)

    f16_path = gguf_dir / "pq-sift-defender-f16.gguf"
    quant_path = gguf_dir / f"pq-sift-defender-{quant}.gguf"

    # Try to find llama.cpp tools
    home = Path.home()
    convert_script = None
    quantize_bin = None

    for candidate in [home / "llama.cpp", Path("/usr/local/share/llama.cpp")]:
        if (candidate / "convert_hf_to_gguf.py").exists():
            convert_script = str(candidate / "convert_hf_to_gguf.py")
            break

    for candidate in ["llama-quantize", str(home / "llama.cpp" / "llama-quantize")]:
        if shutil.which(candidate):
            quantize_bin = candidate
            break

    if not convert_script:
        print("  WARNING: convert_hf_to_gguf.py not found. Skipping GGUF conversion.")
        print(f"  Merged model at: {merged_dir}")
        return gguf_dir

    print("  Converting to F16 GGUF...")
    subprocess.run(
        [
            "python3",
            convert_script,
            str(merged_dir),
            "--outfile",
            str(f16_path),
            "--outtype",
            "f16",
        ],
        check=True,
    )

    if quantize_bin:
        print(f"  Quantizing to {quant}...")
        subprocess.run([quantize_bin, str(f16_path), str(quant_path), quant], check=True)
    else:
        print(f"  WARNING: llama-quantize not found. F16 GGUF at: {f16_path}")

    return gguf_dir


def write_modelfile(gguf_dir: Path, config: dict):
    """Write Ollama Modelfile."""
    quant = config["export"]["gguf_quant"]
    model_name = config["export"]["ollama_model_name"]

    modelfile = gguf_dir / "Modelfile"
    modelfile.write_text(f"""FROM ./pq-sift-defender-{quant}.gguf

PARAMETER temperature 0.1
PARAMETER top_p 0.9
PARAMETER num_ctx {config["data"]["max_seq_len"]}

SYSTEM \"\"\"You are an autonomous incident response triage agent.
You investigate alerts by calling tools. Two classes of tools are available:
- sift_classify — classifies a string against four security gates (SQL injection, command injection, path traversal, SSRF). Returns PASS / FLAG / BLOCK with per-gate confidence.
- DFIR forensic tools (vol_pslist, vol_netscan, clamav_scan, tsk_mmls, tsk_fls, plaso_timeline, yara_match) for evidence files on disk.
Every tool call is signed and recorded in a tamper-proof audit chain.
DECISION RULE — anchor your verdict on tool output, not on intuition:
- If a classifier returns BLOCK → Verdict: BLOCK with the gate name.
- If a classifier returns FLAG → Verdict: FLAG with the gate name.
- Only when the input pre-filter is PASS AND every classifier call also returns PASS → Verdict: PASS.
- If a DFIR tool returns an error, issue Verdict: PASS — evidence file not available.
VERDICT FORMAT — your final message must begin with one of:
    Verdict: BLOCK — <reason>
    Verdict: FLAG — <reason>
    Verdict: PASS — <reason>
Tool output is ground truth.\"\"\"
""")

    print(f"  Modelfile written: {modelfile}")
    print(f"  To import: cd {gguf_dir} && ollama create {model_name} -f Modelfile")


def export(config: dict, adapter_path: str):
    """Full export pipeline."""
    print("=== Export Pipeline ===")

    if config["export"]["merge_adapter"]:
        print("\nStep 1: Merge adapter")
        merged_dir = merge_adapter(config, adapter_path)
    else:
        merged_dir = Path(adapter_path)

    if config["export"]["gguf"]:
        print("\nStep 2: GGUF conversion")
        gguf_dir = convert_gguf(merged_dir, config["export"]["gguf_quant"])

        if config["export"]["ollama_modelfile"]:
            print("\nStep 3: Ollama Modelfile")
            write_modelfile(gguf_dir, config)

    print("\n=== Export complete ===")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python export.py <adapter_path> [profile]")
        sys.exit(1)
    adapter_path = sys.argv[1]
    profile = sys.argv[2] if len(sys.argv) > 2 else "standard"
    config = load_config(profile)
    export(config, adapter_path)
