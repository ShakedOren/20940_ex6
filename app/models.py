from typing import Optional
from pydantic import BaseModel, Field


class User(BaseModel):
    username: str
    password: str
    salt: str

class RegisterRequest(BaseModel):
    username: str
    password: str = Field(min_length=6)

class RegisterResponse(BaseModel):
    result: str


class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    result: str
