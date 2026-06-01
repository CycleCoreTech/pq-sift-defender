"""Training script: QLoRA fine-tuning with weighted loss and config-driven params."""

import json
import sys
from datetime import datetime
from pathlib import Path

import torch
from config_loader import config_summary, load_config
from datasets import Dataset
from peft import LoraConfig, TaskType, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    DataCollatorForSeq2Seq,
    Trainer,
    TrainingArguments,
)

CHATML_TEMPLATE = {
    "system": "<|im_start|>system\n{content}<|im_end|>\n",
    "human": "<|im_start|>user\n{content}<|im_end|>\n",
    "gpt": "<|im_start|>assistant\n{content}<|im_end|>\n",
}


def format_conversation(sample: dict, tokenizer, max_len: int, train_on_inputs: bool):
    """Convert ShareGPT conversation to token IDs + labels."""
    input_ids = []
    labels = []

    for turn in sample["conversations"]:
        role = turn["from"]
        template = CHATML_TEMPLATE.get(role, CHATML_TEMPLATE["human"])
        text = template.format(content=turn["value"])
        ids = tokenizer.encode(text, add_special_tokens=False)

        if role == "gpt" or train_on_inputs:
            input_ids.extend(ids)
            labels.extend(ids)
        else:
            input_ids.extend(ids)
            labels.extend([-100] * len(ids))

    eos = tokenizer.eos_token_id
    if input_ids[-1] != eos:
        input_ids.append(eos)
        labels.append(eos)

    if len(input_ids) > max_len:
        input_ids = input_ids[:max_len]
        labels = labels[:max_len]

    return {"input_ids": input_ids, "labels": labels, "attention_mask": [1] * len(input_ids)}


class WeightedTrainer(Trainer):
    """Trainer subclass that applies per-sample loss weighting.

    Weights are applied by scaling the standard loss per sample rather than
    materializing a full [batch, seq, vocab] tensor (which OOMs on 16GB GPUs).
    """

    def __init__(self, sample_weights=None, **kwargs):
        super().__init__(**kwargs)
        self.sample_weights = sample_weights

    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
        outputs = model(**inputs)
        loss = outputs.loss

        if self.sample_weights is not None and loss is not None:
            batch_size = inputs["input_ids"].size(0)
            idx_start = (self.state.global_step * batch_size) % len(self.sample_weights)
            idx_end = idx_start + batch_size
            if idx_end <= len(self.sample_weights):
                weights = self.sample_weights[idx_start:idx_end].to(loss.device)
                weight_mean = weights.mean()
                loss = loss * weight_mean

        return (loss, outputs) if return_outputs else loss


def train(config: dict):
    """Main training function."""
    training_dir = Path(__file__).parent.parent
    prepared_dir = training_dir / config["data"]["base_dir"] / "prepared"

    run_name = config["output"].get("run_name")
    if not run_name:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_name = f"{config.get('_profile', 'run')}_{ts}"

    output_dir = training_dir / config["output"]["dir"] / run_name
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save resolved config for reproducibility
    import yaml

    with open(output_dir / "config_resolved.yml", "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    print(f"Run: {run_name}")
    print(f"Config: {config_summary(config)}")
    print(f"Output: {output_dir}")
    print()

    # ── Load tokenizer ───────────────────────────────────────
    print("Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(
        config["model"]["base"],
        trust_remote_code=config["model"]["trust_remote_code"],
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # ── Load and tokenize data ───────────────────────────────
    print("Loading training data...")
    train_path = prepared_dir / "train_weighted.jsonl"
    val_path = prepared_dir / "val.jsonl"

    train_samples = [json.loads(l) for l in open(train_path) if l.strip()]
    val_samples = [json.loads(l) for l in open(val_path) if l.strip()]

    sample_weights = torch.tensor(
        [s.pop("_weight", 1.0) for s in train_samples], dtype=torch.float32
    )
    for s in train_samples:
        s.pop("_source", None)

    max_len = config["data"]["max_seq_len"]
    train_on_inputs = config["training"]["train_on_inputs"]

    print(f"  Tokenizing {len(train_samples)} train, {len(val_samples)} val...")
    train_tokenized = [
        format_conversation(s, tokenizer, max_len, train_on_inputs) for s in train_samples
    ]
    val_tokenized = [
        format_conversation(s, tokenizer, max_len, train_on_inputs) for s in val_samples
    ]

    train_dataset = Dataset.from_list(train_tokenized)
    val_dataset = Dataset.from_list(val_tokenized)

    avg_len = sum(len(t["input_ids"]) for t in train_tokenized) / len(train_tokenized)
    print(f"  Avg sequence length: {avg_len:.0f} tokens")

    # ── Load model ───────────────────────────────────────────
    print("Loading model...")
    quant_config = None
    if config["adapter"]["type"] == "qlora":
        quant_config = BitsAndBytesConfig(
            load_in_4bit=(config["adapter"]["quant_bits"] == 4),
            load_in_8bit=(config["adapter"]["quant_bits"] == 8),
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16 if config["training"]["bf16"] else torch.float16,
            bnb_4bit_use_double_quant=True,
        )

    model = AutoModelForCausalLM.from_pretrained(
        config["model"]["base"],
        quantization_config=quant_config,
        dtype=torch.bfloat16 if config["training"]["bf16"] else torch.float16,
        trust_remote_code=config["model"]["trust_remote_code"],
        device_map="auto",
    )

    if config["adapter"]["type"] in ("qlora", "lora"):
        model = prepare_model_for_kbit_training(model)
        lora_config = LoraConfig(
            r=config["adapter"]["r"],
            lora_alpha=config["adapter"]["alpha"],
            lora_dropout=config["adapter"]["dropout"],
            target_modules="all-linear" if config["adapter"]["target_linear"] else None,
            task_type=TaskType.CAUSAL_LM,
            bias="none",
        )
        model = get_peft_model(model, lora_config)
        model.print_trainable_parameters()

    # ── Training args ────────────────────────────────────────
    tcfg = config["training"]
    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=tcfg["epochs"],
        per_device_train_batch_size=tcfg["micro_batch_size"],
        per_device_eval_batch_size=tcfg["micro_batch_size"],
        gradient_accumulation_steps=tcfg["gradient_accumulation_steps"],
        learning_rate=tcfg["learning_rate"],
        lr_scheduler_type=tcfg["lr_scheduler"],
        warmup_ratio=tcfg["warmup_ratio"],
        weight_decay=tcfg["weight_decay"],
        max_grad_norm=tcfg["max_grad_norm"],
        bf16=tcfg["bf16"],
        gradient_checkpointing=tcfg["gradient_checkpointing"],
        logging_steps=tcfg["logging_steps"],
        eval_strategy="epoch" if val_samples else "no",
        save_strategy="epoch",
        save_total_limit=tcfg["save_total_limit"],
        load_best_model_at_end=True if val_samples else False,
        metric_for_best_model="eval_loss" if val_samples else None,
        report_to="none",
        run_name=run_name,
        dataloader_pin_memory=True,
        remove_unused_columns=False,
    )

    # ── Train ────────────────────────────────────────────────
    print("\nStarting training...")
    data_collator = DataCollatorForSeq2Seq(
        tokenizer, pad_to_multiple_of=8, return_tensors="pt", padding=True
    )

    trainer = WeightedTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset if val_samples else None,
        data_collator=data_collator,
        sample_weights=sample_weights,
    )

    result = trainer.train()

    # ── Save ─────────────────────────────────────────────────
    print(f"\nSaving adapter to {output_dir}...")
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)

    metrics = result.metrics
    metrics["run_name"] = run_name
    metrics["profile"] = config.get("_profile", "unknown")
    with open(output_dir / "train_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nTraining complete: {result.metrics}")
    print(f"Adapter saved: {output_dir}")
    return output_dir


if __name__ == "__main__":
    profile = sys.argv[1] if len(sys.argv) > 1 else "standard"
    config = load_config(profile)
    train(config)
