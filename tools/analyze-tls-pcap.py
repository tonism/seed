#!/usr/bin/env python3
"""Walk the TLS handshake of every :443 connection in a pcap (pure Python, no deps).

Built to localize the 286-secure RECONNECT failure: the seed makes a NEW connection per
handshake attempt, so each TCP flow to api.openai.com:443 is one attempt. For each we list the
TLS handshake messages in order per direction + the terminal event (FIN/RST). The tell:
  - client sends ClientKeyExchange (0x10) -> it ACCEPTED the server's ServerKeyExchange sig
    (the pinned/adopted RSA key verified) -> any failure is POST-SKE.
  - client sends NO CKE after ServerHelloDone -> the SKE verify FAILED (wrong key).

Usage: python3 tools/analyze-tls-pcap.py /tmp/seed-cap.pcap
"""
from __future__ import annotations
import struct
import sys

HS = {1: "ClientHello", 2: "ServerHello", 11: "Certificate", 12: "ServerKeyExchange",
      13: "CertificateRequest", 14: "ServerHelloDone", 16: "ClientKeyExchange",
      20: "Finished?", 4: "NewSessionTicket"}
REC = {0x14: "ChangeCipherSpec", 0x15: "Alert", 0x16: "Handshake", 0x17: "ApplicationData"}


def read_pcap(path):
    """Yield (ts, link_layer_bytes) per packet; handle pcap + pcapng-classic + endianness."""
    data = open(path, "rb").read()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian, nano = "<", magic == b"\x4d\x3c\xb2\xa1"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian, nano = ">", magic == b"\xa1\xb2\x3c\x4d"
    else:
        raise SystemExit(f"not a classic pcap (magic {magic.hex()}); if pcapng, recapture with tcpdump")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        ts_s, ts_u, caplen, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        yield (ts_s + ts_u / (1e9 if nano else 1e6), linktype, data[off:off + caplen])
        off += caplen


def parse_ip_tcp(link, linktype):
    """link-layer -> (src_ip, dst_ip, sport, dport, flags, seq, payload) or None."""
    if linktype == 1:               # EN10MB
        if len(link) < 14:
            return None
        eth = struct.unpack(">H", link[12:14])[0]
        if eth != 0x0800:           # IPv4 only
            return None
        ip = link[14:]
    elif linktype in (0, 108):      # NULL / LOOP (loopback)
        ip = link[4:]
    else:
        return None
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0xF) * 4
    if ip[9] != 6:                  # TCP
        return None
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    tcp = ip[ihl:]
    if len(tcp) < 20:
        return None
    sport, dport, seq = struct.unpack(">HHI", tcp[0:8])
    doff = (tcp[12] >> 4) * 4
    flags = tcp[13]
    return src, dst, sport, dport, flags, seq, tcp[doff:]


def reassemble(segs):
    """segs: list of (seq, payload). Return the byte stream from min seq (retransmit-safe)."""
    segs = [s for s in segs if s[1]]
    if not segs:
        return b""
    base = min(s[0] for s in segs)
    buf = bytearray()
    for seq, pl in sorted(segs, key=lambda s: s[0]):
        pos = seq - base
        if pos < 0:
            continue
        if pos > len(buf):
            buf.extend(b"\0" * (pos - len(buf)))
        end = pos + len(pl)
        if end > len(buf):
            buf.extend(b"\0" * (end - len(buf)))
        for i, b in enumerate(pl):
            if buf[pos + i] == 0:
                buf[pos + i] = b
    return bytes(buf)


def walk_records(stream):
    """Yield (rec_type_name, hs_msg_name_or_len) for each TLS record in the stream."""
    i = 0
    while i + 5 <= len(stream):
        rtype = stream[i]
        if rtype not in REC:
            break                    # not (or no longer) a clean TLS record stream
        rlen = struct.unpack(">H", stream[i + 3:i + 5])[0]
        body = stream[i + 5:i + 5 + rlen]
        if rtype == 0x16 and body:    # Handshake: may pack multiple messages
            j = 0
            while j + 4 <= len(body):
                mt = body[j]
                mlen = struct.unpack(">I", b"\0" + body[j + 1:j + 4])[0]
                yield ("Handshake", HS.get(mt, f"hs_type_{mt}"))
                j += 4 + mlen
                if mt not in HS and mt not in (20,):
                    break
        else:
            yield (REC[rtype], f"{rlen}B")
        i += 5 + rlen


def find_sni(stream):
    k = stream.find(b"api.openai.com")
    return "api.openai.com" if k >= 0 else None


def main():
    if len(sys.argv) < 2:
        print(__doc__); return 1
    pkts = list(read_pcap(sys.argv[1]))
    print(f"{len(pkts)} packets")
    flows = {}                       # (cip,cport,sip,sport) -> dict
    order = []
    for ts, lt, link in pkts:
        p = parse_ip_tcp(link, lt)
        if not p:
            continue
        src, dst, sport, dport, flags, seq, pl = p
        if dport == 443:
            key, c2s = (src, sport, dst, dport), True
        elif sport == 443:
            key, c2s = (dst, dport, src, sport), False
        else:
            continue
        f = flows.get(key)
        if f is None:
            f = flows[key] = {"c2s": [], "s2c": [], "fin": [], "rst": [], "first": ts}
            order.append(key)
        (f["c2s"] if c2s else f["s2c"]).append((seq, pl))
        if flags & 0x01:
            f["fin"].append("client" if c2s else "server")
        if flags & 0x04:
            f["rst"].append("client" if c2s else "server")

    api = [k for k in order if find_sni(reassemble(flows[k]["c2s"]))]
    print(f"{len(flows)} :443 flows; {len(api)} to api.openai.com (by SNI)\n")
    for n, key in enumerate(api, 1):
        f = flows[key]
        cs, ss = reassemble(f["c2s"]), reassemble(f["s2c"])
        cmsgs = [m for _, m in walk_records(cs)]
        smsgs = [m for _, m in walk_records(ss)]
        cke = any("ClientKeyExchange" in m for m in cmsgs)
        print(f"--- attempt {n}  {key[0]}:{key[1]} -> {key[2]}:443 ---")
        print(f"  client -> server : {' , '.join(cmsgs) or '(none)'}")
        print(f"  server -> client : {' , '.join(smsgs) or '(none)'}")
        print(f"  close: FIN={f['fin']} RST={f['rst']}")
        print(f"  >> ClientKeyExchange sent: {cke}  "
              f"({'SKE verify PASSED -> failure is POST-SKE' if cke else 'NO CKE -> SKE verify FAILED (key rejected)'})")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
