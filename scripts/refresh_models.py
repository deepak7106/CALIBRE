"""Refresh free OpenRouter model IDs in config/models.yaml."""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

import yaml


def main() -> None:
    key = os.getenv("OPENROUTER_API_KEY")
    if not key:
        raise SystemExit("OPENROUTER_API_KEY is required")
    request = Request(
        "https://openrouter.ai/api/v1/models",
        headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
    )
    with urlopen(request, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    free_models = sorted(
        str(item["id"]) for item in payload.get("data", [])
        if str(item.get("id", "")).endswith(":free")
    )
    if not free_models:
        raise SystemExit("No free OpenRouter models were returned; config was not changed")
    path = Path("config/models.yaml")
    config = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    current = config.get("llm_reasoner", {})
    config["llm_reasoner"] = {
        "primary": current.get("primary") if current.get("primary") in free_models else free_models[0],
        "fallbacks": [model for model in free_models if model != current.get("primary")][:5],
    }
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    print(f"Updated {path} with {len(free_models)} free models")


if __name__ == "__main__":
    main()
