from fastapi import FastAPI, HTTPException

from app import db
from app.config import Config
from app.models import LoginRequest, LoginResponse, RegisterRequest, RegisterResponse
from app.rate_limit import RateLimiter
from app.security import verify_password

app = FastAPI(title="Password Defense Lab")

rate_limiter = RateLimiter(Config.rate_limit_attempts, Config.rate_limit_window_s)


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

    if Config.enable_rate_limit:
        allowed = rate_limiter.check(client_key)
        if not allowed:
            raise HTTPException(status_code=401, detail="Too mant attempts")

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not verify_password(req.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return LoginResponse(result="success")