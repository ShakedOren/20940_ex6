import time
from fastapi import FastAPI, HTTPException, Query

from app import db
from app.attempt_logger import log_attempt
from app.captcha import issue_captcha, verify_captcha
from app.config import load_config, get_protection_flags
from app.lockout_tracker import LockoutTracker
from app.models import AdminCaptchaResponse, LoginRequest, LoginResponse, LoginTotpRequest, RegisterRequest, RegisterResponse
from app.rate_limit import RateLimiter
from app.security import verify_password, get_pepper
from app.totp import verify_totp

app = FastAPI(title="Password Defense Lab")

config = load_config("config.json")
rate_limiter = RateLimiter(config.rate_limit_attempts, config.rate_limit_window_s)
lockouts = LockoutTracker(config.lockout_threshold, config.lockout_duration_s)
_captcha_failures: dict[str, int] = {}

@app.on_event("startup")
def startup():
    db.init_db("app.db")

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/register", response_model=RegisterResponse)
def register(req: RegisterRequest):
    existing = db.get_user(req.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    _create_user(req)
    return RegisterResponse(result="created")


@app.post("/login", response_model=LoginResponse)
def login(req: LoginRequest):
    return _handle_login(req)

@app.post("/login_totp", response_model=LoginResponse)
def login_totp(req: LoginTotpRequest):
    return _handle_login(req, True, req.totp_code)


@app.get("/admin/get_captcha_token", response_model=AdminCaptchaResponse)
def admin_get_captcha_token(group_seed: str):
    if group_seed != config.group_seed:
        raise HTTPException(status_code=403, detail="invalid group seed")
    token, ttl = issue_captcha(config.captcha_ttl_s)
    return AdminCaptchaResponse(captcha_token=token, expires_in=ttl)

def _create_user(req: RegisterRequest):
    hash_mode = req.hash_mode if req.hash_mode is not None else config.default_hash_mode
    category = req.category if req.category is not None else "medium"
    db.create_user(req.username, req.password, hash_mode, category)

def _log_and_response(username: str, hash_mode: str, result: str, protection_flags, start_time, extra=None):
    latency_ms = (time.perf_counter() - start_time) * 1000
    log_attempt(
        username=username,
        hash_mode=hash_mode,
        protection_flags=protection_flags,
        result=result,
        latency_ms=latency_ms,
        extra=extra,
    )
    return LoginResponse(
        result=result,
        protection_flags=protection_flags,
        captcha_required=extra.get("captcha_required", False) if extra else False,
        lockout_remaining=extra.get("lockout_remaining") if extra else None,
        latency_ms=latency_ms,
    )

def _handle_login(req: LoginRequest, totp_required: bool = False, totp: str | None = None):
    start_time = time.perf_counter()
    user = db.get_user(req.username)  
    client_key = req.username
    
    protection_flags = get_protection_flags(config)

    if config.enable_rate_limit:
        allowed = rate_limiter.check(client_key)
        if not allowed:
            return _log_and_response(req.username, config.default_hash_mode, "rate_limit_exceeded", protection_flags, start_time)

    if config.enable_lockout:
        locked, remaining = lockouts.is_locked(client_key)
        if locked:
            extra = {"lockout_remaining": remaining} if remaining else None
            return _log_and_response(req.username, config.default_hash_mode, "locked_out", protection_flags, start_time, extra)

    if not user:
        return _log_and_response(req.username, config.default_hash_mode, "invalid_credentials", protection_flags, start_time)
    
    if _requires_captcha(req.username):
        if not req.captcha_token or not verify_captcha(req.captcha_token):
            extra = {"captcha_required": True}
            return _log_and_response(req.username, config.default_hash_mode, "captcha_failed", protection_flags, start_time, extra)
            
    pepper = get_pepper()
    user_hash_mode = user.hash_mode if user.hash_mode is not None else config.default_hash_mode
    password_valid = verify_password(req.password, user.salt, pepper, user.password, user_hash_mode)
    
    if not password_valid:
        if config.enable_lockout:
            lockouts.record_failure(client_key)

        _captcha_failures[client_key] = _captcha_failures.get(client_key, 0) + 1
        extra = {"captcha_required": _requires_captcha(req.username)}
        return _log_and_response(req.username, config.default_hash_mode, "invalid_credentials", protection_flags, start_time, extra)
    
    if totp_required and config.enable_totp:
        if not totp:
            return _log_and_response(req.username, config.default_hash_mode, "totp_required", protection_flags, start_time)
        if not user.totp_secret:
            return _log_and_response(req.username, config.default_hash_mode, "totp_not_configured", protection_flags, start_time)
        is_valid, _ = verify_totp(user.totp_secret, totp)
        if not is_valid:
            return _log_and_response(req.username, config.default_hash_mode, "invalid_totp", protection_flags, start_time)

    if config.enable_lockout:
        lockouts.record_success(client_key)

    _captcha_failures.pop(client_key, None)
    return _log_and_response(req.username, config.default_hash_mode, "success", protection_flags, start_time)

def _requires_captcha(username: str) -> bool:
    count = _captcha_failures.get(username, 0)
    return config.enable_captcha and count >= config.captcha_fail_threshold
