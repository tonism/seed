#!/usr/bin/env python3
"""Decrypt seed's TLS 1.2 ECDHE-ChaCha20-Poly1305 app-data from a pcap (offline, wire-only).

seed's premaster IS on the wire: it copies the server's ECDHE public-key X coordinate
straight into the premaster (tls.inc tls_parse_server_key_exchange) -- it sends the base
point G as its own ClientKeyExchange point, so the server's shared secret equals its own
public key and both sides use that X. Insecure, but it means we can derive every key from
the capture alone:
  premaster     = server pubkey X (32B, from ServerKeyExchange)
  master_secret = TLS-PRF(premaster,  "master secret", client_random+server_random)[:48]
  key_block     = TLS-PRF(master_secret,"key expansion", server_random+client_random)[:88]
                = client_write_key(32) server_write_key(32) client_write_iv(12) server_write_iv(12)
  per-record nonce = write_iv XOR (0x00000000 || seq_be64)         (RFC 7905)
  plaintext     = ChaCha20(write_key, counter=1, nonce) XOR ciphertext[:-16]
Record seq resets to 0 at each ChangeCipherSpec and counts every encrypted record after it
(the Finished is seq 0, the first app-data seq 1, ...).

Usage: tls-decrypt.py <pcap> [server_ip_substr]   (substr filters to the agent connection)
"""
import hashlib, hmac, struct, sys


# ---------------- pcap ----------------
def parse_pcap(path):
    data = open(path, "rb").read()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end, nano = "<", magic == b"\x4d\x3c\xb2\xa1"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end, nano = ">", magic == b"\xa1\xb2\x3c\x4d"
    else:
        raise SystemExit("not a classic pcap (pcapng unsupported)")
    off, pkts, div = 24, [], (1e9 if nano else 1e6)
    while off + 16 <= len(data):
        ts_s, ts_f, caplen, _ = struct.unpack(end + "IIII", data[off:off + 16])
        off += 16
        pkts.append((ts_s + ts_f / div, data[off:off + caplen]))
        off += caplen
    return pkts


def parse_tcp(raw):
    if len(raw) < 14:
        return None
    etype = struct.unpack(">H", raw[12:14])[0]
    off = 14
    if etype == 0x8100:
        etype = struct.unpack(">H", raw[16:18])[0]
        off = 18
    if etype != 0x0800:
        return None
    ip = raw[off:]
    if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 6:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack(">H", ip[2:4])[0]
    src = ".".join(map(str, ip[12:16]))
    dst = ".".join(map(str, ip[16:20]))
    tcp = ip[ihl:total]
    if len(tcp) < 20:
        return None
    sport, dport = struct.unpack(">HH", tcp[0:4])
    seq = struct.unpack(">I", tcp[4:8])[0]
    doff = (tcp[12] >> 4) * 4
    return (src, sport, dst, dport, seq, tcp[doff:])


def reassemble(segs):
    # segs: list of (seq, payload); rebuild the contiguous byte stream from the lowest seq.
    if not segs:
        return b""
    base = min(s for s, _ in segs)
    buf = bytearray()
    for seq, pl in sorted(segs, key=lambda x: x[0]):
        pos = seq - base
        if pos < 0:
            continue
        if pos > len(buf):
            buf.extend(b"\x00" * (pos - len(buf)))  # gap (shouldn't happen on a clean stream)
        end = pos + len(pl)
        if end > len(buf):
            buf.extend(b"\x00" * (end - len(buf)))
        buf[pos:end] = pl  # last writer wins (retransmits overwrite identically)
    return bytes(buf)


def tls_records(stream):
    out, i = [], 0
    while i + 5 <= len(stream):
        rtype, ver, ln = stream[i], stream[i + 1:i + 3], struct.unpack(">H", stream[i + 3:i + 5])[0]
        body = stream[i + 5:i + 5 + ln]
        if len(body) < ln:
            break
        out.append((rtype, body))
        i += 5 + ln
    return out


# ---------------- crypto ----------------
def prf(secret, label, seed, n):
    seed = label + seed
    out, a = b"", seed
    while len(out) < n:
        a = hmac.new(secret, a, hashlib.sha256).digest()
        out += hmac.new(secret, a + seed, hashlib.sha256).digest()
    return out[:n]


def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 7)


def _chacha_block(key, counter, nonce):
    st = list(struct.unpack("<4I", b"expand 32-byte k")) + list(struct.unpack("<8I", key)) \
        + [counter & 0xFFFFFFFF] + list(struct.unpack("<3I", nonce))
    w = st[:]
    for _ in range(10):
        _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13); _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
        _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12); _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(w[i] + st[i]) & 0xFFFFFFFF for i in range(16)])


def chacha20(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = _chacha_block(key, counter + i // 64, nonce)
        out += bytes(b ^ k for b, k in zip(data[i:i + 64], ks))
    return bytes(out)


def rec_nonce(write_iv, seq):
    s = b"\x00\x00\x00\x00" + struct.pack(">Q", seq)
    return bytes(a ^ b for a, b in zip(write_iv, s))


# ---------------- driver ----------------
def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    pcap, ipsub = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "")
    pkts = parse_pcap(pcap)
    # group into connections keyed by the 4-tuple (canonicalised), keep per-direction segs
    conns = {}
    for ts, raw in pkts:
        p = parse_tcp(raw)
        if not p:
            continue
        src, sp, dst, dp, seq, payload = p
        if 443 not in (sp, dp):
            continue
        srv = (src, sp) if sp == 443 else (dst, dp)
        cli = (dst, dp) if sp == 443 else (src, sp)
        if ipsub and ipsub not in srv[0]:
            continue
        key = (cli, srv)
        c = conns.setdefault(key, {"c2s": [], "s2c": []})
        if payload:
            c["c2s" if (src, sp) == cli else "s2c"].append((seq, payload))

    for (cli, srv), c in conns.items():
        c2s = reassemble(c["c2s"])
        s2c = reassemble(c["s2c"])
        cr = tls_records(c2s)
        sr = tls_records(s2c)
        # --- handshake parse ---
        def hs_stream(recs):
            return b"".join(b for t, b in recs if t == 22)

        def hs_msgs(stream):
            out, i = [], 0
            while i + 4 <= len(stream):
                t = stream[i]
                ln = struct.unpack(">I", b"\x00" + stream[i + 1:i + 4])[0]
                out.append((t, stream[i + 4:i + 4 + ln]))
                i += 4 + ln
            return out

        client_random = server_random = premaster = None
        for t, b in hs_msgs(hs_stream(cr)):
            if t == 1 and len(b) >= 34:
                client_random = b[2:34]
        for t, b in hs_msgs(hs_stream(sr)):
            if t == 2 and len(b) >= 34:
                server_random = b[2:34]
            if t == 12 and len(b) >= 37 and b[0] == 3 and b[4] == 0x04:
                premaster = b[5:37]
        print(f"== conn {cli} <-> {srv} ==")
        if not (client_random and server_random and premaster):
            print(f"  missing handshake fields (cr={bool(client_random)} sr={bool(server_random)} pm={bool(premaster)})")
            continue
        master = prf(premaster, b"master secret", client_random + server_random, 48)
        kb = prf(master, b"key expansion", server_random + client_random, 88)
        cwk, swk, cwiv, swiv = kb[0:32], kb[32:64], kb[64:76], kb[76:88]
        print(f"  premaster(serverX)={premaster.hex()[:24]}..  master={master.hex()[:24]}..")

        def decrypt_dir(recs, wk, wiv, who):
            seq, ccs = 0, False
            for t, b in recs:
                if t == 20:  # ChangeCipherSpec -> following records are encrypted, seq resets
                    ccs, seq = True, 0
                    continue
                if not ccs:
                    continue
                if len(b) < 16:
                    seq += 1
                    continue
                pt = chacha20(wk, 1, rec_nonce(wiv, seq), b[:-16])
                seq += 1
                yield (t, pt)

        print(f"  --- CLIENT->SERVER decrypted records ---")
        for t, pt in decrypt_dir(cr, cwk, cwiv, "C"):
            if t == 23:
                txt = pt.decode("latin1")
                print(f"  [appdata {len(pt)}B] {txt[:600]}")
            else:
                print(f"  [hs/other type {t} {len(pt)}B]")
        print(f"  --- SERVER->CLIENT decrypted records ---")
        for t, pt in decrypt_dir(sr, swk, swiv, "S"):
            if t == 23:
                txt = pt.decode("latin1")
                print(f"  [appdata {len(pt)}B] {txt[:600]}")
            else:
                print(f"  [hs/other type {t} {len(pt)}B]")


if __name__ == "__main__":
    main()
