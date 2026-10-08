"""Configurable, uncertainty-aware evidence fusion for risk components."""

from pathlib import Path
from typing import Mapping

import yaml


def hybrid_components(components: Mapping[str, float | None]) -> tuple[float, bool]:
    config_path = Path("config/risk.yaml")
    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
    weights = config.get("risk", {}).get("weights", {})
    available = {key: value for key, value in components.items() if value is not None}
    if not available:
        return 0.0, True
    total_weight = sum(float(weights.get(key, 0)) for key in available)
    if total_weight <= 0:
        return sum(float(value) for value in available.values()) / len(available), True
    score = sum(float(value) * float(weights.get(key, 0)) for key, value in available.items()) / total_weight
    return max(0.0, min(1.0, score)), len(available) != len(components)
