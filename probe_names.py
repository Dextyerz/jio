#!/usr/bin/env python3
"""Brute-probe Firebase Realtime Database names for exposed SMS-RAT panels.

Every RAT panel is reachable at `https://<project-id>-default-rtdb.firebaseio.com`
(world-readable, no auth).  Project ids created without an explicit id get a
random suffix, but a large share of these panels are named after the operator's
own word/app ("apkdir", "konach", "konaio"), so a wordlist sweep finds them.

Only `/user_sms` (incoming SMS per device) and `/user_data` (device + SIM
numbers) are probed: a database that answers on those two nodes is a RAT panel,
everything else is somebody's app and gets dropped.

Run:
    python3 probe_names.py --words 5000 --workers 300
    python3 probe_names.py --wordlist /path/to/list.txt --workers 400 --suffix
"""

from __future__ import annotations

import argparse
import itertools
import random
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
OPEN = DATA / "open_panels.txt"
SEEN = DATA / "probed_names.txt"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

# Base vocabulary.  Panels are named by Indian operators for their own apps, so
# Indian given names and the local app/RAT vocabulary are the highest-yield part.
WORDS = """
jio jiomart jiogemini gemini gemini18 ai googleai apkdir konach konaio adslab
heretic akuma fighter modz panel sms smsforward otp otphub forwarder device
rat c2 server control admin master boss king boss smsbot otpsender sender
recharge plan data backup users client clients messages inbox smsapp
dost friend bhai yaar india bharat delhi mumbai kolkata chennai pune jaipur
patna bihar up mp rajasthan gujarat kerala punjab haryana odisha assam
rahul rohit amit vikas ajay sanjay ankit sumit arjun karan manish deepak
priya neha pooja kavita anita rekha sunita kiran meena geeta rani devi
kumar singh sharma verma gupta yadav raj khan patel jain agarwal mishra
sethi kapoor malhotra chowdhury reddy naidu rao iyer nair menon pillai
test testing demo app project myapp my project newapp testapp final v1 v2
firebase fire store database db realtime rtdb cloud backend api node
india1 india2 jio1 jio2 main main1 app1 app2 panel1 panel2 sms1 sms2 otp1
akash abhishek abhi aryan ashish bhavesh chetan dinesh gaurav harsh imran
jatin kamal lokesh mohit nikhil omkar pankaj rakesh ritesh sahil tarun
uday varun yogesh zaid farhan irfan kabir lakshman mahesh nishant
killerguy darkhacker blackhat hacker hack kinghacker cybergod godmode
jioo jioapp jiologin jiorecharge jiophone jiofiber airtel vi vodafone bsnl
panell paneladmin smspanel otppanel devicepanel ratpanel adminpanel
commodities shopstore store mart appz apps solution solutions tech softwares
""".split()

SUFFIXES = ["", "1", "2", "3", "7", "9", "01", "11", "99", "123", "2024", "2025",
            "2026", "x", "xx", "yy", "z", "in", "india", "app", "new", "old"]


def gen_candidates(limit: int, extra_suffix: bool) -> list[str]:
    base = WORDS
    out: list[str] = []
    for w in base:
        out.append(w)
    for w in base:
        for s in SUFFIXES[1:]:
            out.append(w + s)
            out.append(w + "-" + s)
    if extra_suffix:
        # a few hundred random 5-char Firebase id suffixes on the best words
        for w in ("jio", "sms", "otp", "apkdir", "heretic", "panel", "admin"):
            for _ in range(60):
                r = "".join(random.choice("0123456789abcdef") for _ in range(5))
                out.append(f"{w}-{r}")
    seen, uniq = set(), []
    for c in out:
        c = c.lower().strip("-")
        if 3 <= len(c) <= 30 and c not in seen:
            seen.add(c)
            uniq.append(c)
    random.shuffle(uniq)
    return uniq[:limit] if limit else uniq


def panel_bases(name: str) -> list[str]:
    """Both default-RTDB hostnames for a project id.

    us-central1 projects answer on `<id>-default-rtdb.firebaseio.com`; every
    other region (asia-southeast1, europe-west1, ...) answers on
    `<id>-default-rtdb.<region>.firebasedatabase.app` instead, so a probe that
    only tries firebaseio.com silently misses them.
    """
    regions = ("asia-southeast1", "europe-west1", "us-central1", "asia-east1",
               "asia-south1", "australia-southeast1")
    out = [f"https://{name}-default-rtdb.firebaseio.com"]
    out += [f"https://{name}-default-rtdb.{r}.firebasedatabase.app" for r in regions]
    return out


def probe(name: str, session: requests.Session) -> str | None:
    for base in panel_bases(name):
        for node in ("user_sms", "user_data", "clients"):
            try:
                r = session.get(f"{base}/{node}.json?shallow=true", timeout=6)
            except requests.RequestException:
                break
            if r.status_code != 200:
                continue
            try:
                j = r.json()
            except ValueError:
                continue
            if isinstance(j, dict) and j:
                return f"{base}|"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--words", type=int, default=0, help="cap candidate count (0 = all)")
    ap.add_argument("--workers", type=int, default=300)
    ap.add_argument("--suffix", action="store_true", help="add random 5-hex suffixes")
    ap.add_argument("--wordlist", default="")
    args = ap.parse_args()

    done: set[str] = set()
    if SEEN.exists():
        done = set(SEEN.read_text(errors="ignore").split())
    cands = gen_candidates(args.words, args.suffix)
    if args.wordlist:
        cands = [w.strip().lower() for w in Path(args.wordlist).read_text(errors="ignore").split()]
    todo = [c for c in cands if c not in done]
    print(f"[probe] {len(todo)} candidates ({len(done)} already probed)", flush=True)

    hits: list[str] = []
    lock = threading.Lock()

    def work(name: str) -> str | None:
        s = requests.Session()
        s.headers.update({"Accept": "application/json", "User-Agent": UA})
        return probe(name, s)

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(work, c): c for c in todo}
        for i, f in enumerate(as_completed(futs), 1):
            try:
                r = f.result()
            except Exception:
                r = None
            if r:
                hits.append(r)
                print(f"  PANEL {r}", flush=True)
            if i % 2000 == 0:
                rate = time.time() - t0
                print(f"  ...{i}/{len(todo)}  {len(hits)} panels  {i/rate:.0f}/s", flush=True)
    with SEEN.open("a") as fh:
        for c in todo:
            fh.write(c + "\n")
    if hits:
        with OPEN.open("a") as fh:
            for h in hits:
                fh.write(h + "\n")
    print(f"[done] {len(hits)} panels from {len(todo)} names in {time.time()-t0:.0f}s", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
