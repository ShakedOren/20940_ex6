import time
import pyotp


def generate_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, code: str, valid_window: int = 1) -> tuple[bool, int | None]:
    totp = pyotp.TOTP(secret)
    now = time.time()
    step = totp.interval
    for offset in range(-valid_window, valid_window + 1):
        test_time = now + offset * step
        if totp.verify(code, for_time=test_time, valid_window=0):
            return True, offset
    return False, None
