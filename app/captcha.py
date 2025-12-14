import time
import uuid
from typing import Dict, Tuple

_tokens: Dict[str, float] = {}


def issue_captcha(ttl_s: int) -> Tuple[str, int]:
    token = uuid.uuid4().hex
    expires_at = time.time() + ttl_s
    _tokens[token] = expires_at
    return token, ttl_s


def verify_captcha(token: str) -> bool:
    now = time.time()
    expires = _tokens.get(token)
    if not expires:
        return False
    if now > expires:
        _tokens.pop(token, None)
        return False
    _tokens.pop(token, None)
    return True
