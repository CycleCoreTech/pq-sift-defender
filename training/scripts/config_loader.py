"""Config loader with profile inheritance and CLI overrides."""

import copy
from pathlib import Path

import yaml

CONFIGS_DIR = Path(__file__).parent.parent / "configs"


def deep_merge(base: dict, overlay: dict) -> dict:
    """Recursively merge overlay into base. Overlay wins on conflicts."""
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        if key.startswith("_"):
            continue
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def load_config(profile: str = "standard", overrides: dict | None = None) -> dict:
    """Load base config, merge profile, apply CLI overrides."""
    base_path = CONFIGS_DIR / "base.yml"
    with open(base_path) as f:
        config = yaml.safe_load(f)

    profile_path = CONFIGS_DIR / "profiles" / f"{profile}.yml"
    if profile_path.exists():
        with open(profile_path) as f:
            profile_cfg = yaml.safe_load(f) or {}
        config = deep_merge(config, profile_cfg)

    if overrides:
        config = deep_merge(config, overrides)

    config["_profile"] = profile
    config["_config_dir"] = str(CONFIGS_DIR)

    return config


def resolve_data_path(config: dict, filename: str) -> Path:
    """Resolve a data filename relative to the training directory."""
    training_dir = Path(__file__).parent.parent
    return training_dir / config["data"]["base_dir"] / filename


def config_summary(config: dict) -> str:
    """One-line summary for logging."""
    p = config.get("_profile", "?")
    e = config["training"]["epochs"]
    lr = config["training"]["learning_rate"]
    r = config["adapter"]["r"]
    bs = config["training"]["micro_batch_size"] * config["training"]["gradient_accumulation_steps"]
    batches = len(config["data"]["batches"])
    return f"profile={p} epochs={e} lr={lr} lora_r={r} eff_batch={bs} data_batches={batches}"
