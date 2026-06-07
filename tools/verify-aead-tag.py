#!/usr/bin/env python3
"""Given the device's dumped otk (poly_r||poly_s, 32 hex bytes) and a pcap, extract the
first server TLS app-data record (1703030569), recompute the ChaCha20-Poly1305 AEAD tag
with a reference Poly1305, and compare against the wire tag and the device's computed tag.

Usage: verify-aead-tag.py <pcap> <otk-hex-32B> [<device-computed-tag-hex>]
"""
import struct
import sys

P = (1 << 130) - 5


def clamp_r(r16):
    r = bytearray(r16)
    for i in (3, 7, 11, 15):
        r[i] &= 0x0f
    for i in (4, 8, 12):
        r[i] &= 0xfc
    return bytes(r)


def poly1305(otk, msg):
    r = int.from_bytes(clamp_r(otk[:16]), "little")
    s = int.from_bytes(otk[16:32], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        blk = msg[i:i + 16]
        n = int.from_bytes(blk, "little") + (1 << (8 * len(blk)))
        acc = ((acc + n) * r) % P
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def aead_tag(otk, aad, cipher):
    m = bytes(aad) + b"\x00" * ((16 - len(aad) % 16) % 16)
    m += bytes(cipher) + b"\x00" * ((16 - len(cipher) % 16) % 16)
    m += len(aad).to_bytes(8, "little") + len(cipher).to_bytes(8, "little")
    return poly1305(otk, m)


def s2c(path):
    d = open(path, "rb").read()
    end = "<" if d[:4] in (b"\xd4\xc3\xb2\xa1",) else ">"
    lt = struct.unpack(end + "I", d[20:24])[0]
    off = 24
    out = bytearray()
    while off + 16 <= len(d):
        _, _, incl, _ = struct.unpack(end + "IIII", d[off:off + 16])
        off += 16
        p = d[off:off + incl]
        off += incl
        ipoff = 14 if lt == 1 else (4 if lt == 0 else 0)
        ip = p[ipoff:]
        if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 0x0f) * 4
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue
        if struct.unpack(">H", tcp[0:2])[0] == 443:
            out += tcp[(tcp[12] >> 4) * 4:]
    return bytes(out)


def main():
    pcap, otk_hex = sys.argv[1], sys.argv[2]
    dev_tag = sys.argv[3] if len(sys.argv) > 3 else None
    otk = bytes.fromhex(otk_hex)
    stream = s2c(pcap)
    # first TLS app-data record header (1369-byte cipher fragment = 0x0569 total len)
    hdr = stream.find(bytes.fromhex("1703030569"))
    print(f"record header @ {hdr}")
    frag_len = 0x0569          # 1385
    cipher = stream[hdr + 5:hdr + 5 + (frag_len - 16)]   # 1369
    wire_tag = stream[hdr + 5 + (frag_len - 16):hdr + 5 + frag_len]
    print(f"cipher len {len(cipher)}, wire tag {wire_tag[:4].hex()} (full {wire_tag.hex()})")
    # AAD = seq(8 BE) | type(1) | version(2) | plaintext-len(2 BE).  First app-data record => seq 1.
    for seq in (1, 0, 2):
        aad = seq.to_bytes(8, "big") + b"\x17" + bytes.fromhex("0303") + (len(cipher)).to_bytes(2, "big")
        ref = aead_tag(otk, aad, cipher)
        flag = "  <== MATCHES WIRE" if ref == wire_tag else ""
        dflag = "  <== MATCHES DEVICE" if dev_tag and ref[:len(bytes.fromhex(dev_tag))] == bytes.fromhex(dev_tag) else ""
        print(f"seq={seq}: ref tag {ref[:4].hex()} (full {ref.hex()}){flag}{dflag}")


if __name__ == "__main__":
    main()
