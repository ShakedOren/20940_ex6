import time



class RateLimiter:
    def __init__(self, attempts: int, sliding_window: int):
        self.attempts = attempts
        self.sliding_window = sliding_window
        self.buckets: dict[str, list[float]] = {}

    def check(self, key: str) -> bool:
        now = time.time()
        sliding_windowtart = now - self.sliding_window

        bucket = self.buckets.setdefault(key, [])
        while bucket and bucket[0] < sliding_windowtart:
            bucket.pop(0)
        if len(bucket) >= self.attempts:
            return False
        bucket.append(now)
        return True

