#!/usr/bin/env python3
"""Unicorn harness for core/rtc_time.inc (NTP seconds-since-1900 -> calendar -> BCD RTC fields).

Assembles the REAL device .inc + a tiny caller, runs ntp_to_rtc_fields in 16-bit unicorn for each
test value, and checks the seven BCD output bytes against the offline oracle (tools/x509/ntp_rtc.py
ntp_seconds_to_calendar + the BCD packing in http_date_rtc.to_cmos). This is the offline asm
correctness gate before any NTP-client / CMOS-RTC wiring; 86Box is authoritative afterward. The
conversion is the error-prone part: a 32-bit long division (/60 /60 /24) + leap-year day counting.
"""
from __future__ import annotations
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bench_harness import build, Run

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "x509"))
import ntp_rtc  # noqa: E402

EXPORTS = ["ntp_seconds", "rtc_sec", "rtc_min", "rtc_hour", "rtc_day",
           "rtc_month", "rtc_year", "rtc_century"]
MAGIC = 0x5A5A1C70
CALLER = "    call ntp_to_rtc_fields\n"
NTP_EPOCH = datetime(1900, 1, 1, tzinfo=timezone.utc)


def build_rtc():
    export_tbl = (f"\n__rtc_exports:\n    dd 0x{MAGIC:08X}\n"
                  + "".join(f"    dd {n}\n" for n in EXPORTS))
    img, exports = build('%include "core/rtc_time.inc"\n' + export_tbl, CALLER)
    pos = img.find(struct.pack("<I", MAGIC))
    if pos < 0:
        raise RuntimeError("rtc export marker not found")
    vals = struct.unpack_from("<%dI" % len(EXPORTS), img, pos + 4)
    exports.update(dict(zip(EXPORTS, vals)))
    return img, exports


def _bcd(n: int) -> int:
    return ((n // 10) << 4) | (n % 10)


def expected(secs: int) -> dict:
    y, mo, d, h, mi, s = ntp_rtc.ntp_seconds_to_calendar(secs)
    return {"rtc_sec": _bcd(s), "rtc_min": _bcd(mi), "rtc_hour": _bcd(h),
            "rtc_day": _bcd(d), "rtc_month": _bcd(mo), "rtc_year": _bcd(y % 100),
            "rtc_century": _bcd(y // 100)}


def main() -> int:
    img, exp = build_rtc()

    def device(secs: int) -> dict:
        r = Run(img, exp)
        uc = r.run(setup=lambda u, e: u.mem_write(e["ntp_seconds"], struct.pack("<I", secs)))
        return {n: uc.mem_read(exp[n], 1)[0] for n in EXPORTS[1:]}

    def secs_of(dt: datetime) -> int:
        return int((dt - NTP_EPOCH).total_seconds())

    samples = [
        datetime(2026, 6, 14, 11, 52, 14, tzinfo=timezone.utc),   # real leaf-validity epoch
        datetime(2024, 2, 29, 23, 59, 59, tzinfo=timezone.utc),   # leap day
        datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc),  # year boundary -1s
        datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),       # year boundary
        datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),       # just after non-leap Feb
        datetime(2028, 2, 29, 12, 0, 0, tzinfo=timezone.utc),     # leap day, leap year
        datetime(2000, 2, 29, 0, 0, 0, tzinfo=timezone.utc),      # century leap year (div 400)
        datetime(2035, 12, 31, 23, 59, 59, tzinfo=timezone.utc),  # near era-0 ceiling
        datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc),       # unix epoch
    ]
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    samples += [base + timedelta(days=k, hours=k % 24, minutes=k % 60, seconds=k % 60)
                for k in range(0, 365 * 6, 13)]   # dense sweep 2024..2030

    fails = 0
    for dt in samples:
        secs = secs_of(dt)
        got, want = device(secs), expected(secs)
        if got != want:
            fails += 1
            if fails <= 5:
                gh = {k: hex(v) for k, v in got.items()}
                wh = {k: hex(v) for k, v in want.items()}
                print(f"  FAIL {dt.isoformat()}\n      got {gh}\n      exp {wh}")

    print(f"checked {len(samples)} timestamps vs the oracle; "
          f"{'ALL GREEN' if fails == 0 else f'{fails} FAILURES'}")
    g = device(secs_of(datetime(2026, 6, 14, 11, 52, 14, tzinfo=timezone.utc)))
    print("  2026-06-14 11:52:14 ->", {k: hex(v) for k, v in g.items()},
          "(sec min hour day month year century, BCD)")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
