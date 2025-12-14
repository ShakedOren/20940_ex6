from dataclasses import dataclass


@dataclass
class Config:
    db_url: str = "sqlite:///./app.db"
    group_seed: str = "526078169"
    pepper: str = "pepper"

    enable_rate_limit: bool = True
    rate_limit_attempts: int = 20
    rate_limit_window_s: int = 60
