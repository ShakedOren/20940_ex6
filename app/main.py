from fastapi import FastAPI, HTTPException

from app import db
from app.models import LoginRequest, LoginResponse, RegisterRequest, RegisterResponse
app = FastAPI(title="Password Defense Lab")

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/register", response_model=RegisterResponse)
def register(req: RegisterRequest):
    existing = db.get_user(req.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    user = _create_user(req)
    return RegisterResponse(username=user["username"], hash_mode=user["hash_mode"], message="created")


@app.post("/login", response_model=LoginResponse)
def login(req: LoginRequest):
    return _handle_login(req)


def _create_user(req: RegisterRequest):
    return db.create_user(req.username, req.password)

def _handle_login(req: LoginRequest):
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if user.password != req.password:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return LoginResponse(result="success")