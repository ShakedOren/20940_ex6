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

    enable_lockout: bool = True
    lockout_threshold: int = 10
    lockout_duration_s: int = 300

    enable_captcha: bool = True
    captcha_fail_threshold: int = 3
    captcha_ttl_s: int = 300

def load_config(path: str | None = None) -> Config:
    cfg = Config()
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in data.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
    return cfg