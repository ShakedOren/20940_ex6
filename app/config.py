from dataclasses import dataclass


@dataclass
class Config:
    db_url: str = "sqlite:///./app.db"
    group_seed: str = "526078169"
    pepper: str = "pepper"