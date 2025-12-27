import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from app import db
from app.config import load_config
from app.security import get_pepper
from app.totp import generate_secret

weak_pwds = [
    "123456",
    "password",
    "qwerty",
    "111111",
    "abc123",
    "letmein",
    "monkey",
    "iloveyou",
    "admin",
    "welcome",
]

medium_pwds = [
    "Summer2024!",
    "Winter2023#",
    "Password1!",
    "Qwerty123!",
    "LetMeIn42",
    "BlueSky99!",
    "Orange55#",
    "SecureMe7$",
    "HappyDay8*",
    "TreeHouse6!",
]

strong_pwds = [
    "N2v!e4Gh1@xQz9Lm",
    "p$7Wz!3rQyT1kM0#",
    "Vc8@Lp3#xZq1!sHr",
    "bD6&yT9!qP2^mKs4",
    "Zl5*Yh8!cV2@wQe7",
    "gF4#pR9!xC6$zT1n",
    "Qw7!eR5^tY3@uI9$",
    "xM8$kL2!vB6@cN4#",
    "rT5!fG7^hJ3@kL1$",
    "mP9@qW3!zX7#sD5&",
]

all_pwds = [("weak", weak_pwds), ("medium", medium_pwds), ("strong", strong_pwds)]
hash_modes_cycle = ["argon2id", "bcrypt", "sha256"]


def main():
    cfg = load_config()
    
    # Extract database path from config
    # db_url format: "sqlite:///./app.db" or "sqlite:///app.db"
    db_path = cfg.db_url.replace("sqlite:///", "").replace("./", "")
    if not db_path:
        db_path = "app.db"
    
    db.init_db(db_path)

    users_out = []
    user_idx = 0
    for category, pwd_list in all_pwds:
        for i, pwd in enumerate(pwd_list, start=1):
            user_idx += 1
            username = f"{category}_{i:02d}"
            hash_mode = hash_modes_cycle[(user_idx - 1) % len(hash_modes_cycle)]
            
            # db.create_user() handles password hashing, salt generation, and TOTP secret generation
            # Create user with plain password
            db.create_user(
                username=username,
                password=pwd,  # Plain password, not hash
                hash_mode=hash_mode,
                category=category,
            )
            
            # Get the created user to retrieve the TOTP secret that was generated
            created_user = db.get_user(username)
            if not created_user:
                raise RuntimeError(f"Failed to create user {username}")
            
            users_out.append(
                {
                    "username": username,
                    "password": pwd,
                    "category": category,
                    "hash_mode": hash_mode,
                    "totp_secret": created_user.totp_secret,
                }
            )

    Path("data").mkdir(exist_ok=True)
    with open("data/users.json", "w", encoding="utf-8") as f:
        json.dump(users_out, f, indent=2)
    print("Seeded", len(users_out), "users -> data/users.json and database")


if __name__ == "__main__":
    main()
