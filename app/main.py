from fastapi import FastAPI, HTTPException

from app import db
from app.config import Config, load_config
from app.lockout_tracker import LockoutTracker
from app.models import LoginRequest, LoginResponse, RegisterRequest, RegisterResponse
from app.rate_limit import RateLimiter
from app.security import verify_password, get_pepper

app = FastAPI(title="Password Defense Lab")

config = load_config("config.json")
rate_limiter = RateLimiter(config.rate_limit_attempts, config.rate_limit_window_s)
lockouts = LockoutTracker(config.lockout_threshold, config.lockout_duration_s)


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


def _create_user(req: RegisterRequest):
    db.create_user(req.username, req.password)

def _handle_login(req: LoginRequest):
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
    
    pepper = get_pepper()
    password_valid = verify_password(req.password, user.salt, pepper, user.password, "argon2id")
    
    if not password_valid:
        if config.enable_lockout:
            lockouts.record_failure(client_key)
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if config.enable_lockout:
        lockouts.record_success(client_key)
    return LoginResponse(result="success")