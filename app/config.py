from dataclasses import dataclass
import json
import os


@dataclass
class Config:
    db_url: str = "sqlite:///./app.db"
    group_seed: str = "526078169"
    pepper: str = "pepper"

    enable_rate_limit: bool = True
    rate_limit_attempts: int = 20
    rate_limit_window_s: int = 60


def load_config(path: str | None = None) -> Config:
    cfg = Config()
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in data.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
    return cfg