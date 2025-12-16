import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


from app.config import load_config

_cfg = load_config()
_total_attempts = 0

def log_attempt(
    username: str,
    hash_mode: str,
    protection_flags: list[str],
    result: str,
    latency_ms: float,
    extra: dict | None = None,
):
    global _total_attempts
    _total_attempts += 1
    attempt_id = _total_attempts

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "group_seed": _cfg.group_seed,
        "username": username,
        "hash_mode": hash_mode,
        "protection_flags": protection_flags,
        "result": result,
        "latency_ms": round(latency_ms, 3),
        "attempt_id": attempt_id,
    }
    if extra:
        record.update(extra)

    path = Path(_cfg.attempts_log_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
