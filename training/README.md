# Training Pipeline

QLoRA fine-tuning pipeline for pq-sift-defender on Qwen2.5-1.5B-Instruct.

## Quick Start

```bash
# Install dependencies (Python 3.12+ recommended)
pip install torch transformers peft datasets bitsandbytes pyyaml accelerate

# Fetch CVE data (optional — enriches training)
python scripts/fetch_cves.py

# Run full pipeline with a profile
python scripts/pipeline.py fast --stage all       # smoke test (~2 min)
python scripts/pipeline.py standard --stage all   # production (~11 min)
python scripts/pipeline.py thorough --stage all   # best quality (~26 min)
```

## Profiles

| Profile | Epochs | LoRA r | LR | Time (RTX 5070Ti) |
|---------|--------|--------|-----|-------------------|
| fast | 1 | 32 | 3e-4 | ~2 min |
| standard | 3 | 64 | 2e-4 | ~11 min |
| thorough | 5 | 64 | 1e-4 | ~26 min |

## Config System

All settings in `configs/base.yml`. Profiles override via deep merge.
CLI overrides: `--override training.epochs=5 adapter.r=128`

## Data

Training data is in `data/` as ShareGPT-format JSONL with quality labels (A/B/C).
The pipeline deduplicates, applies per-batch oversampling weights and per-sample
quality-based loss scaling, replaces system prompts from config, and splits
train/val.

## Export to Ollama

After training, the pipeline merges the adapter and attempts GGUF conversion.
If `convert_hf_to_gguf.py` is not available, use:

```bash
# Convert with llama.cpp (required — Ollama's internal converter has a known bug)
python /path/to/llama.cpp/convert_hf_to_gguf.py output/<run>_merged/ \
  --outfile output/pq-sift-defender-f16.gguf --outtype f16

# Import into Ollama
ollama create pq-sift-defender -f output/Modelfile
```
