from dataclasses import dataclass
import json
import os

def _bool(env_val: str, default: bool) -> bool:
    if env_val is None:
        return default
    return env_val.lower() in {"1", "true", "yes", "on"}

@dataclass
class Config:
    db_url: str = "sqlite:///./app.db"
    group_seed: str = "526078169"
    attempts_log_file: str = "attempts.log"
    pepper: str = "pepper"
    default_hash_mode: str = "argon2id"

    enable_rate_limit: bool = True
    rate_limit_attempts: int = 20
    rate_limit_window_s: int = 60

    enable_lockout: bool = True
    lockout_threshold: int = 10
    lockout_duration_s: int = 300

    enable_captcha: bool = True
    captcha_fail_threshold: int = 3
    captcha_ttl_s: int = 300

    enable_totp: bool = True

def load_config(path: str | None = None) -> Config:
    cfg = Config()
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in data.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)

    return cfg

def get_protection_flags(cfg: Config) -> list[str]:
    flags = []
    if cfg.enable_rate_limit:
        flags.append("rate_limit")
    if cfg.enable_lockout:
        flags.append("lockout")
    if cfg.enable_captcha:
        flags.append("captcha")
    if cfg.enable_totp:
        flags.append("totp")
    return flags