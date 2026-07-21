#!/usr/bin/env python3
"""NTP timestamp -> CMOS RTC: the offline oracle for the auto-recertify validity clock (NTP source).

Build 12 task #7. Seed's 286 secure tier validates a (re-)pinned leaf's notBefore/notAfter, which
needs a trustworthy "now". We get it from an INDEPENDENT source -- an NTP query during the internet
setup phase, BEFORE any TLS -- so the time isn't derived from the connection we're authenticating
(not circular). The NTP-derived time sets the CMOS RTC; the off-race cert-validity check then reads
the RTC and compares against the cert dates. This file is the reference the 286 asm mirrors.

It splits exactly like the device work:
  * Acquisition (NTP-specific, here): build the 48-byte client packet, read the transmit-timestamp
    seconds, convert seconds-since-1900 -> calendar. This is the only part that differs from the
    HTTP-Date design; the conversion (day-counting + leap years) is the error-prone bit to validate.
  * RTC + compare (shared): REUSED verbatim from http_date_rtc.py -- to_cmos() writes the BCD
    registers, to_cert_cmp() renders the YYMMDDHHMMSS form for the lexicographic notBefore/notAfter
    gate. Picking NTP over HTTP-Date does not re-write this half.

NTP (RFC 5905) primer for the 4 bytes we use:
  request : 48 bytes; byte0 = 0x1B (LI=0, VN=3, Mode=3 client), rest zero.
  reply   : byte0 Mode=4 (server); Transmit Timestamp at offset 40 = 8 bytes
            (4 B seconds since 1900-01-01 UTC, big-endian | 4 B fraction). We take the seconds only.
  era     : the 32-bit seconds field wraps 2036-02-07 (NTP era 0 = 1900..2036). 2026 (~3.97e9) sits
            in era 0 but ABOVE 2^31, so it must be read UNSIGNED. The device does unsigned 32-bit.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

# the shared RTC+compare half -- reused, not rewritten (the whole point of the split)
from http_date_rtc import to_cmos, to_cert_cmp, DateError

NTP_EPOCH = datetime(1900, 1, 1, tzinfo=timezone.utc)
DAYS_IN_MONTH_COMMON = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]


def build_ntp_request() -> bytes:
    """The 48-byte SNTP client request the device transmits: byte0=0x1B, rest zero."""
    pkt = bytearray(48)
    pkt[0] = 0x1B  # LI=0, VN=3, Mode=3 (client)
    return bytes(pkt)


def parse_ntp_seconds(reply: bytes) -> int:
    """Transmit-Timestamp seconds (offset 40..43, big-endian) = unsigned seconds since 1900-01-01.
    Strict: require a >=48-byte packet and a server-mode reply; fail closed (clock stays unset)."""
    if len(reply) < 48:
        raise DateError(f"NTP reply too short ({len(reply)} < 48)")
    if (reply[0] & 0x07) != 4:
        raise DateError(f"NTP reply mode {reply[0] & 0x07} != 4 (server)")
    secs = int.from_bytes(reply[40:44], "big")  # unsigned 32-bit
    if secs == 0:
        raise DateError("NTP transmit timestamp is zero")
    return secs


def is_leap(year: int) -> bool:
    """Full Gregorian rule. (Within the UTCTime era 2000-2049 the device may use the cheaper
    year%4==0 -- exactly correct there since 2000 is leap and the next exception, 2100, is >2049
    and therefore GeneralizedTime. The oracle uses the full rule as ground truth.)"""
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def ntp_seconds_to_calendar(secs: int) -> tuple[int, int, int, int, int, int]:
    """seconds-since-1900 -> (year, mon, day, hour, minute, sec). This is the day-counting algorithm
    the 286 asm mirrors: split off the time-of-day, then walk years (365/366) and months."""
    days, tod = divmod(secs, 86400)
    hour, rem = divmod(tod, 3600)
    minute, sec = divmod(rem, 60)
    year = 1900
    while True:
        dy = 366 if is_leap(year) else 365
        if days < dy:
            break
        days -= dy
        year += 1
    months = DAYS_IN_MONTH_COMMON[:]
    if is_leap(year):
        months[2] = 29
    mon = 1
    while days >= months[mon]:
        days -= months[mon]
        mon += 1
    return year, mon, days + 1, hour, minute, sec


def ntp_reply_with(dt: datetime) -> bytes:
    """Construct a server reply carrying dt as the transmit timestamp -- for the self-test."""
    secs = int((dt - NTP_EPOCH).total_seconds())
    pkt = bytearray(48)
    pkt[0] = (0 << 6) | (4 << 3) | 4  # LI=0, VN=4, Mode=4 (server)
    pkt[40:44] = secs.to_bytes(4, "big")
    return bytes(pkt)


# ---------------------------------------------------------------------------
def _selftest() -> int:
    ok = True

    def check(cond, msg):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {msg}")
        ok = ok and cond

    # request shape
    req = build_ntp_request()
    check(len(req) == 48 and req[0] == 0x1B and req[1:] == bytes(47),
          "client request = 48 B, byte0=0x1B, rest zero")

    # round-trip a known time through a synthetic reply (the real observed leaf-validity epoch)
    dt = datetime(2026, 7, 21, 5, 27, 20, tzinfo=timezone.utc)
    secs = parse_ntp_seconds(ntp_reply_with(dt))
    cal = ntp_seconds_to_calendar(secs)
    check(cal == (2026, 7, 21, 5, 27, 20), f"NTP reply -> {cal}")
    # the seconds value is > 2^31 -> must be read unsigned
    check(secs > 0x80000000, f"2026 transmit-seconds {secs} is > 2^31 (unsigned read required)")

    # the shared half is REUSED (same outputs as http_date_rtc's expectations)
    cmos = to_cmos(*cal)
    check(cmos == {0x00: 0x20, 0x02: 0x27, 0x04: 0x05, 0x07: 0x21, 0x08: 0x07, 0x09: 0x26},
          f"CMOS BCD via shared to_cmos() = {{sec:{cmos[0]:#04x} .. year:{cmos[9]:#04x}}}")
    check(to_cert_cmp(*cal) == b"260721052720", "cert-compare form via shared to_cert_cmp()")

    # validity gate against the real leaf (notBefore 260708020406, notAfter 261006030404)
    now = to_cert_cmp(*cal)
    check(b"260708020406" <= now <= b"261006030404", "now is within the real leaf validity window")
    nov = to_cert_cmp(*ntp_seconds_to_calendar(parse_ntp_seconds(
        ntp_reply_with(datetime(2026, 11, 1, tzinfo=timezone.utc)))))
    check(not (b"260708020406" <= nov <= b"261006030404"), "a Nov clock is OUTSIDE (expired)")
    jan = to_cert_cmp(*ntp_seconds_to_calendar(parse_ntp_seconds(
        ntp_reply_with(datetime(2026, 1, 1, tzinfo=timezone.utc)))))
    check(not (b"260708020406" <= jan <= b"261006030404"), "a Jan clock is OUTSIDE (not yet valid)")

    # the conversion is correct across leap days, month/year boundaries, and a wide range --
    # cross-checked against Python's datetime (ground truth) so the device-mirrorable algorithm is proven
    samples = [
        datetime(2024, 2, 29, 23, 59, 59, tzinfo=timezone.utc),   # leap day
        datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc),  # year boundary -1s
        datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),       # year boundary
        datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),       # just after (non-leap) Feb
        datetime(2028, 2, 29, 12, 0, 0, tzinfo=timezone.utc),     # leap day, leap year
        datetime(2000, 2, 29, 0, 0, 0, tzinfo=timezone.utc),      # century leap year (div 400)
        datetime(2035, 12, 31, 23, 59, 59, tzinfo=timezone.utc),  # near the era-0 ceiling
        datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc),       # unix epoch, for good measure
    ]
    span_ok = True
    for s in samples:
        got = ntp_seconds_to_calendar(int((s - NTP_EPOCH).total_seconds()))
        exp = (s.year, s.month, s.day, s.hour, s.minute, s.second)
        if got != exp:
            span_ok = False
            print(f"      mismatch {s.isoformat()}: got {got} exp {exp}")
    check(span_ok, "seconds->calendar matches datetime across leap days / boundaries / range")

    # also sweep one full day per ~3-day step across 2024-2030 vs datetime (dense correctness)
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    dense_ok = True
    for k in range(0, 365 * 6, 3):
        s = base + timedelta(days=k, hours=(k % 24), minutes=(k % 60), seconds=(k % 60))
        got = ntp_seconds_to_calendar(int((s - NTP_EPOCH).total_seconds()))
        exp = (s.year, s.month, s.day, s.hour, s.minute, s.second)
        if got != exp:
            dense_ok = False
            print(f"      dense mismatch {s.isoformat()}: got {got} exp {exp}")
            break
    check(dense_ok, "dense sweep 2024-2030 (every ~3 days) matches datetime")

    # strict rejections (fail closed -> RTC stays unset, validity check then SKIPS)
    for bad, why in [
        (bytes(40), "short packet"),
        (bytes([0x1B]) + bytes(47), "client-mode reply (mode 3)"),
        (bytes([0x24]) + bytes(39) + bytes(8), "zero transmit timestamp"),
    ]:
        try:
            parse_ntp_seconds(bad)
            check(False, f"should reject ({why})")
        except DateError:
            check(True, f"rejects {why}")

    print("OVERALL:", "ALL GREEN" if ok else "FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    sys.exit(_selftest())
