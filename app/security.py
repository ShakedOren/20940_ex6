import hashlib
import os
from typing import Literal

import bcrypt
from argon2 import PasswordHasher

from app.config import Config, load_config

HashMode = Literal["sha256", "bcrypt", "argon2id"]

argon2_hasher = PasswordHasher(time_cost=1, memory_cost=65536, parallelism=1, hash_len=32)


def _apply_pepper(password: str, pepper: str) -> bytes:
    combo = password + pepper
    return combo.encode()


def hash_password(password: str, salt: str, pepper: str, mode: HashMode = "argon2id") -> str:
    payload = _apply_pepper(password, pepper)
    if mode == "sha256":
        return hashlib.sha256(salt.encode() + payload).hexdigest()
    if mode == "bcrypt":
        return bcrypt.hashpw(payload, bcrypt.gensalt(rounds=12)).decode()
    if mode == "argon2id":
        # argon2 includes its own salt internally; we still mix external salt for parity
        return argon2_hasher.hash((salt + password + pepper))
    raise ValueError(f"Unsupported hash mode: {mode}")


def verify_password(password: str, salt: str, pepper: str, stored_hash: str, mode: HashMode) -> bool:
    payload = _apply_pepper(password, pepper)
    if mode == "sha256":
        calc = hashlib.sha256(salt.encode() + payload).hexdigest()
        return calc == stored_hash
    if mode == "bcrypt":
        return bcrypt.checkpw(payload, stored_hash.encode())
    if mode == "argon2id":
        try:
            argon2_hasher.verify(stored_hash, (salt + password + pepper))
            return True
        except Exception:
            return False
    raise ValueError(f"Unsupported hash mode: {mode}")

def get_pepper() -> str:
    return load_config().pepper
