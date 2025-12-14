from typing import Literal

import bcrypt

from app import config

HashMode = Literal["bcrypt"]

def _apply_pepper(password: str, pepper: str) -> bytes:
    combo = password + pepper
    return combo.encode()


def hash_password(password: str, salt: str, pepper: str, mode: HashMode = "bcrypt") -> str:
    payload = _apply_pepper(password, pepper)
    if mode == "bcrypt":
        return bcrypt.hashpw(payload, bcrypt.gensalt(rounds=12)).decode()
    raise ValueError(f"Unsupported hash mode: {mode}")


def verify_password(password: str, stored_hash: str) -> bool:
    pepper = get_pepper()
    payload = _apply_pepper(password, pepper)
    return bcrypt.checkpw(payload, stored_hash.encode())


def get_pepper() -> str:
    return config.Config().pepper