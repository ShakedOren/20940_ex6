from pydantic import BaseModel, Field
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    pass


class UserModel(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    salt = Column(String, nullable=False)
    totp_secret = Column(String, nullable=True)


class User(BaseModel):
    id: int | None = None
    username: str
    password: str
    salt: str
    totp_secret: str | None = None
    
    @classmethod
    def from_orm_model(cls, orm_user: UserModel) -> "User":
        return cls(
            id=orm_user.id,
            username=orm_user.username,
            password=orm_user.password,
            salt=orm_user.salt,
            totp_secret=orm_user.totp_secret
        )
    
class RegisterRequest(BaseModel):
    username: str
    password: str = Field(min_length=6)

class RegisterResponse(BaseModel):
    result: str

class LoginRequest(BaseModel):
    username: str
    password: str
    captcha_token: str | None = None

class LoginResponse(BaseModel):
    result: str

class AdminCaptchaResponse(BaseModel):
    captcha_token: str
    expires_in: int

class LoginTotpRequest(LoginRequest):
    totp_code: str | None = None
