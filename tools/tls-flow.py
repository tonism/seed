#!/usr/bin/env python3
"""Walk the TLS record flow of every IPv4:443 connection in a pcap.

Pure-stdlib (no scapy/dpkt/tshark): parse the pcap, reassemble each TCP stream by
sequence number, then walk the 5-byte TLS record headers in both directions with
timestamps. Built to answer the Build 11 reconnect questions:
  - how many client Application-Data records (type 23) the request takes, and their
    sizes (a doubled ~chunk1-sized record => the prebuilt-vs-.ready_tail double-send),
  - whether the server sends ChangeCipherSpec(20)+Finished(22) before it FINs/RSTs
    (handshake ACCEPTED -> request-timeout) or FINs without it (handshake too slow).

Usage: tls-flow.py <pcap> [provider_ip_substr]
  provider_ip_substr filters connections whose server IP contains the substring
  (e.g. the "HTTPS remotes:" IP the harness prints), to drop host background noise.
"""
import bisect
import struct
import sys

REC_TYPE = {20: "CCS", 21: "Alert", 22: "Handshake", 23: "AppData"}


def parse_pcap(path):
    data = open(path, "rb").read()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end = ">"
    else:
        raise SystemExit("not a pcap (bad magic %r)" % magic)
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(end + "I", data[20:24])[0]
    off = 24
    pkts = []
    while off + 16 <= len(data):
        ts_s, ts_f, incl, _ = struct.unpack(end + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        ts = ts_s + ts_f / (1e9 if nano else 1e6)
        pkts.append((ts, pkt))
    return linktype, pkts


def ipv4_tcp(linktype, pkt):
    if linktype == 1:                       # EN10MB
        if len(pkt) < 14 or struct.unpack(">H", pkt[12:14])[0] != 0x0800:
            return None
        ip = pkt[14:]
    elif linktype == 0:                     # NULL/loopback
        if len(pkt) < 4:
            return None
        ip = pkt[4:]
    else:
        return None
    if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 6:
        return None
    ihl = (ip[0] & 0x0f) * 4
    total = struct.unpack(">H", ip[2:4])[0]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    tcp = ip[ihl:total] if total >= ihl else ip[ihl:]
    if len(tcp) < 20:
        return None
    sport, dport = struct.unpack(">HH", tcp[0:4])
    seq, ack = struct.unpack(">II", tcp[4:12])
    doff = (tcp[12] >> 4) * 4
    flags = tcp[13]
    payload = tcp[doff:]
    return src, sport, dst, dport, seq, ack, flags, payload


class Stream:
    def __init__(self):
        self.isn = None
        self.segs = {}          # offset -> bytes (first-seen wins; ignores retransmits)
    def add(self, seq, payload, is_syn):
        if is_syn and self.isn is None:
            self.isn = seq
        if self.isn is None:
            self.isn = seq      # capture started mid-stream; treat first seq as base
        if not payload:
            return
        offrel = (seq - self.isn - 1) & 0xffffffff   # SYN consumes 1 seq
        # unwrap 32-bit wrap into a small positive offset space
        if offrel > 0x7fffffff:
            offrel -= 0x100000000
        self.segs.setdefault(offrel, payload)
    def contiguous(self):
        """Return (blob, offset->ts map seeds) walking from 0 until the first gap."""
        out = bytearray()
        pos = 0
        starts = sorted(self.segs)
        i = 0
        # allow a stream that starts at offset 0 (post-SYN). If the smallest offset
        # is negative (pre-ISN data, shouldn't happen), skip it.
        while i < len(starts):
            o = starts[i]
            if o < pos:
                i += 1
                continue
            if o > pos:
                break                          # gap -> stop (cannot walk records past it)
            out += self.segs[o]
            pos += len(self.segs[o])
            i += 1
        return bytes(out)


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    path = sys.argv[1]
    ipfilter = sys.argv[2] if len(sys.argv) > 2 else None
    linktype, pkts = parse_pcap(path)

    conns = {}      # key -> dict
    for ts, pkt in pkts:
        r = ipv4_tcp(linktype, pkt)
        if not r:
            continue
        src, sport, dst, dport, seq, ack, flags, payload = r
        if 443 not in (sport, dport):
            continue
        key = frozenset(((src, sport), (dst, dport)))
        c = conns.get(key)
        if c is None:
            server = (src, sport) if sport == 443 else (dst, dport)
            client = (dst, dport) if sport == 443 else (src, sport)
            c = conns[key] = dict(server=server, client=client, t0=ts,
                                  cs=Stream(), sc=Stream(),
                                  cseg=[], sseg=[], events=[])
        c["t0"] = min(c["t0"], ts)
        is_syn = bool(flags & 0x02)
        frm = (src, sport)
        if frm == c["client"]:
            st, segts = c["cs"], c["cseg"]
        else:
            st, segts = c["sc"], c["sseg"]
        before = dict(st.segs) if payload else None
        st.add(seq, payload, is_syn)
        if payload and st.segs is not before:
            # record (offset, ts) for any newly placed segment
            offrel = (seq - st.isn - 1) & 0xffffffff
            if offrel > 0x7fffffff:
                offrel -= 0x100000000
            segts.append((offrel, ts))
        if flags & 0x01:
            c["events"].append((ts, "FIN", frm == c["client"]))
        if flags & 0x04:
            c["events"].append((ts, "RST", frm == c["client"]))

    def tsof(segts, offset):
        arr = sorted(segts)
        offs = [a[0] for a in arr]
        j = bisect.bisect_right(offs, offset) - 1
        return arr[j][1] if j >= 0 else None

    def walk(blob, segts, t0):
        recs = []
        pos = 0
        n = len(blob)
        while pos + 5 <= n:
            typ = blob[pos]
            ln = struct.unpack(">H", blob[pos + 3:pos + 5])[0]
            if typ not in REC_TYPE or blob[pos + 1] != 0x03:
                break                          # not a TLS record boundary -> stop
            t = tsof(segts, pos)
            recs.append((t - t0 if t else None, typ, ln, pos))
            pos += 5 + ln
        return recs, pos, n

    order = sorted(conns.values(), key=lambda c: c["t0"])
    shown = 0
    for c in order:
        sip = c["server"][0]
        if ipfilter and ipfilter not in sip:
            continue
        shown += 1
        cblob = c["cs"].contiguous()
        sblob = c["sc"].contiguous()
        crecs, cend, clen = walk(cblob, c["cseg"], c["t0"])
        srecs, send, slen = walk(sblob, c["sseg"], c["t0"])
        timeline = [("C->S", rt, typ, ln) for (rt, typ, ln, _) in crecs] + \
                   [("S->C", rt, typ, ln) for (rt, typ, ln, _) in srecs] + \
                   [(("C->S" if isc else "S->C"), (t - c["t0"]), ev, None)
                    for (t, ev, isc) in c["events"]]
        timeline.sort(key=lambda e: (e[1] if e[1] is not None else 1e9))

        print("=" * 78)
        print("CONN %s:%d  <->  %s:%d   start t=%.3f" %
              (c["client"][0], c["client"][1], c["server"][0], c["server"][1], c["t0"]))
        c_app = [ln for (_, typ, ln, _) in crecs if typ == 23]
        s_has_ccs = any(typ == 20 for (_, typ, _, _) in srecs)
        s_has_hs_after = False
        seen_ccs = False
        for (_, typ, _, _) in srecs:
            if typ == 20:
                seen_ccs = True
            elif typ == 22 and seen_ccs:
                s_has_hs_after = True
        print("  client AppData records: %d  sizes=%s" % (len(c_app), c_app))
        print("  server sent CCS(20): %s   server Finished(22 after CCS): %s" %
              (s_has_ccs, s_has_hs_after))
        if cend < clen:
            print("  [client stream gap/undecodable tail at offset %d of %d]" % (cend, clen))
        if send < slen:
            print("  [server stream gap/undecodable tail at offset %d of %d]" % (send, slen))
        print("  --- timeline (rel s) ---")
        for (d, rt, ev, ln) in timeline:
            rs = ("%8.3f" % rt) if rt is not None else "    ?   "
            if ln is None:
                print("   %s  %s  %s" % (rs, d, ev))
            else:
                print("   %s  %s  %-9s %5d B" % (rs, d, REC_TYPE.get(ev, "?%d" % ev), ln))
    if not shown:
        print("no IPv4:443 connections matched (filter=%r)" % ipfilter)
        ips = sorted({c["server"][0] for c in conns.values()})
        print("server IPs present:", ips)


if __name__ == "__main__":
    main()
