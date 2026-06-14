#!/usr/bin/env python3
"""HTTP Date header -> CMOS RTC: the offline oracle for the auto-recertify validity clock.

The VM clock is unreliable, so when the connection comes up Seed reads the real time from the HTTP
`Date:` response header (every response carries it, even a 401) and sets the CMOS RTC; the off-race
cert-validity check then compares notBefore/notAfter against the RTC. This is the reference the 286
asm mirrors: the IMF-fixdate is FIXED-WIDTH, so the parse is a strict fixed-offset extraction +
month-name table + BCD conversion (no flexible date parsing on the device).

  Date: Sun, 14 Jun 2026 11:52:14 GMT
        ^Dow, ^DD ^Mon ^YYYY ^HH:MM:SS GMT     (RFC 7231 IMF-fixdate, the only form GTS/CF servers emit)

CMOS (MC146818, the AT's RTC): reg 0x00 sec, 0x02 min, 0x04 hour, 0x07 day, 0x08 month, 0x09 year
(2-digit), all BCD by default (status reg B bit 2 = 0). Written via ports 0x70 (index) / 0x71 (data).
"""
from __future__ import annotations

MONTHS = {b"Jan": 1, b"Feb": 2, b"Mar": 3, b"Apr": 4, b"May": 5, b"Jun": 6,
          b"Jul": 7, b"Aug": 8, b"Sep": 9, b"Oct": 10, b"Nov": 11, b"Dec": 12}
DAYS_IN_MONTH = [0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]   # Feb 29 allowed (leap-lax)


class DateError(Exception):
    """Any deviation from the fixed IMF-fixdate shape. Fail closed (the clock stays unset)."""


def find_date_header(response: bytes) -> bytes:
    """Return the IMF-fixdate VALUE bytes from an HTTP response's `Date:` header (case-insensitive),
    or raise. Mirrors the device scan: find a line beginning 'Date:' in the header block."""
    head = response.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n"):
        if line[:5].lower() == b"date:":
            return line[5:].strip()
    raise DateError("no Date header")


def _d2(b: bytes, off: int) -> int:
    """Two ASCII digits at off -> int; strict (both must be 0-9)."""
    hi, lo = b[off], b[off + 1]
    if not (0x30 <= hi <= 0x39 and 0x30 <= lo <= 0x39):
        raise DateError(f"non-digit at offset {off}")
    return (hi - 0x30) * 10 + (lo - 0x30)


def parse_imf_date(v: bytes) -> tuple[int, int, int, int, int, int]:
    """Strict fixed-offset parse of 'Dow, DD Mon YYYY HH:MM:SS GMT' -> (y, mo, d, h, mi, s).
    Exactly the fixed-width extraction the asm does. Raises DateError on any shape deviation."""
    if len(v) != 29:
        raise DateError(f"length {len(v)} != 29 (not IMF-fixdate)")
    if v[3:5] != b", " or v[7] != 0x20 or v[11] != 0x20 or v[16] != 0x20:
        raise DateError("separator mismatch")
    if v[19] != 0x3A or v[22] != 0x3A or v[25:29] != b" GMT":
        raise DateError("time/zone separator mismatch")
    day = _d2(v, 5)
    mon = MONTHS.get(bytes(v[8:11]))
    if mon is None:
        raise DateError(f"bad month {v[8:11]!r}")
    year = _d2(v, 12) * 100 + _d2(v, 14)
    hour, minute, sec = _d2(v, 17), _d2(v, 20), _d2(v, 23)
    if not (1 <= day <= DAYS_IN_MONTH[mon] and hour <= 23 and minute <= 59 and sec <= 60):
        raise DateError("field out of range")
    return year, mon, day, hour, minute, sec


def _bcd(n: int) -> int:
    return ((n // 10) << 4) | (n % 10)


def to_cmos(year: int, mon: int, day: int, hour: int, minute: int, sec: int) -> dict[int, int]:
    """The CMOS register writes (index -> BCD value) the device performs to set the RTC."""
    return {0x00: _bcd(sec), 0x02: _bcd(minute), 0x04: _bcd(hour),
            0x07: _bcd(day), 0x08: _bcd(mon), 0x09: _bcd(year % 100)}


def to_cert_cmp(year: int, mon: int, day: int, hour: int, minute: int, sec: int) -> bytes:
    """The 12-byte ASCII 'YYMMDDHHMMSS' form, matching a cert UTCTime's body — so the validity
    check is a byte-lexicographic compare of the RTC against notBefore/notAfter (both 2-digit-year,
    same century window: GTS leaves are ~90 days, so YY ordering is unambiguous)."""
    return f"{year % 100:02d}{mon:02d}{day:02d}{hour:02d}{minute:02d}{sec:02d}".encode()


# ---------------------------------------------------------------------------
def _selftest() -> int:
    ok = True

    def check(cond, msg):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {msg}")
        ok = ok and cond

    # the real observed header
    resp = (b"HTTP/1.1 401 Unauthorized\r\nDate: Sun, 14 Jun 2026 11:52:14 GMT\r\n"
            b"Content-Type: application/json\r\n\r\n{...}")
    v = find_date_header(resp)
    y, mo, d, h, mi, s = parse_imf_date(v)
    check((y, mo, d, h, mi, s) == (2026, 6, 14, 11, 52, 14), f"real header -> {(y,mo,d,h,mi,s)}")
    cmos = to_cmos(y, mo, d, h, mi, s)
    check(cmos == {0x00: 0x14, 0x02: 0x52, 0x04: 0x11, 0x07: 0x14, 0x08: 0x06, 0x09: 0x26},
          f"CMOS BCD = {{sec:{cmos[0]:#04x} min:{cmos[2]:#04x} hour:{cmos[4]:#04x} "
          f"day:{cmos[7]:#04x} mon:{cmos[8]:#04x} year:{cmos[9]:#04x}}}")
    check(to_cert_cmp(y, mo, d, h, mi, s) == b"260614115214", "cert-compare form 260614115214")

    # validity gate logic against the real leaf (notBefore 260510011306, notAfter 260808021049)
    now = to_cert_cmp(y, mo, d, h, mi, s)
    check(b"260510011306" <= now <= b"260808021049", "now is within the real leaf validity window")
    check(not (b"260510011306" <= to_cert_cmp(2026, 9, 1, 0, 0, 0) <= b"260808021049"),
          "a Sept clock is correctly OUTSIDE (expired)")
    check(not (b"260510011306" <= to_cert_cmp(2026, 1, 1, 0, 0, 0) <= b"260808021049"),
          "a Jan clock is correctly OUTSIDE (not yet valid)")

    # strict rejections (the asm fails closed on these -> the clock stays unset)
    for bad, why in [
        (b"Sun, 14 Jun 2026 11:52:14 UTC", "wrong zone"),
        (b"Sun, 14 Jun 2026 11:52:14",     "truncated"),
        (b"Sun, 14 Xyz 2026 11:52:14 GMT", "bad month"),
        (b"Sun, 14 Jun 2026 1X:52:14 GMT", "non-digit"),
        (b"Sun, 32 Jun 2026 11:52:14 GMT", "day out of range"),
        (b"Sun-14 Jun 2026 11:52:14 GMT",  "separator"),
    ]:
        try:
            parse_imf_date(bad)
            check(False, f"should reject ({why}): {bad!r}")
        except DateError:
            check(True, f"rejects {why}")
    print("OVERALL:", "ALL GREEN" if ok else "FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    sys.exit(_selftest())
