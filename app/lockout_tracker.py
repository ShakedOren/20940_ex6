
import time
from typing import Dict, Tuple


class LockoutTracker:
    def __init__(self, threshold: int, duration_s: int):
        self.threshold = threshold
        self.duration_s = duration_s
        self.failures: Dict[str, int] = {}
        self.locked_until: Dict[str, float] = {}

    def is_locked(self, key: str) -> Tuple[bool, int]:
        now = time.time()
        until = self.locked_until.get(key, 0)
        if until and until > now:
            return True, int(until - now)
        if until and until <= now:
            self.locked_until.pop(key, None)
        return False, 0

    def record_failure(self, key: str) -> None:
        count = self.failures.get(key, 0) + 1
        self.failures[key] = count
        if count >= self.threshold:
            self.locked_until[key] = time.time() + self.duration_s
            self.failures[key] = 0

    def record_success(self, key: str) -> None:
        self.failures.pop(key, None)
        self.locked_until.pop(key, None)
