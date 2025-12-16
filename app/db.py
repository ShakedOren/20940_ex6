from contextlib import contextmanager
import os
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.models import User, UserModel, Base
from app.security import hash_password, get_pepper
from app.totp import generate_secret

db_path = "app.db"
engine = None
SessionLocal = None

def init_db(path: str):
    global db_path, engine, SessionLocal
    db_path = path
    sqlite_url = f"sqlite:///{path}"
    
    engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_session():
    if SessionLocal is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

def create_user(username: str, password: str) -> User:
    salt = os.urandom(16).hex()
    pepper = get_pepper()
    hashed_password = hash_password(password, salt, pepper)
    totp_secret = generate_secret()
    
    with get_session() as session:
        user_model = UserModel(
            username=username,
            password=hashed_password,
            salt=salt,
            totp_secret=totp_secret
        )
        session.add(user_model)
        session.flush()
        return User.from_orm_model(user_model)

def get_user(username: str) -> User | None:
    with get_session() as session:
        stmt = select(UserModel).where(UserModel.username == username)
        user_model = session.execute(stmt).scalar_one_or_none()
        if user_model:
            return User.from_orm_model(user_model)
        return None