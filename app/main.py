from fastapi import FastAPI, HTTPException, Query

from app import db
from app.captcha import issue_captcha, verify_captcha
from app.config import Config, load_config
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
    db.create_user(req.username, req.password)

def _handle_login(req: LoginRequest, totp_required: bool = False, totp: str | None = None):
    user = db.get_user(req.username)  
    client_key = req.username

    if config.enable_rate_limit:
        allowed = rate_limiter.check(client_key)
        if not allowed:
            raise HTTPException(status_code=401, detail="Too many attempts")

    if config.enable_lockout:
        locked, _ = lockouts.is_locked(client_key)
        if locked:
            raise HTTPException(status_code=401, detail="User locked out")

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if _requires_captcha(req.username):
        if not req.captcha_token or not verify_captcha(req.captcha_token):
            raise HTTPException(status_code=401, detail="Captcha is incorrect")
            
    pepper = get_pepper()
    password_valid = verify_password(req.password, user.salt, pepper, user.password, "argon2id")
    
    if not password_valid:
        if config.enable_lockout:
            lockouts.record_failure(client_key)

        _captcha_failures[client_key] = _captcha_failures.get(client_key, 0) + 1
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if totp_required and config.enable_totp:
        if not totp:
            raise HTTPException(status_code=401, detail="TOTP is required")
        if not user.totp_secret:
            raise HTTPException(status_code=401, detail="TOTP is not configured for this user")
        is_valid, _ = verify_totp(user.totp_secret, totp)
        if not is_valid:
            raise HTTPException(status_code=401, detail="Invalid TOTP code")

    if config.enable_lockout:
        lockouts.record_success(client_key)

    _captcha_failures.pop(client_key, None)
    return LoginResponse(result="success")

def _requires_captcha(username: str) -> bool:
    count = _captcha_failures.get(username, 0)
    return config.enable_captcha and count >= config.captcha_fail_threshold
