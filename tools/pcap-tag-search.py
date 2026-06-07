#!/usr/bin/env python3
"""Search a pcap's server->client (sport 443) TCP payloads for given hex byte
sequences. Used to find the genuine TLS tag on the wire and decide whether a
verify mismatch is a MAC-computation bug or a tag-capture bug.

Usage: pcap-tag-search.py <pcap> <hex1> [<hex2> ...]
"""
import struct
import sys


def payloads(path):
    data = open(path, "rb").read()
    magic = data[:4]
    le = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    end = "<" if le else ">"
    linktype = struct.unpack(end + "I", data[20:24])[0]
    off = 24
    s2c = bytearray()
    c2s = bytearray()
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack(end + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        if linktype == 1:        # EN10MB
            if len(pkt) < 14 or struct.unpack(">H", pkt[12:14])[0] != 0x0800:
                continue
            ipoff = 14
        elif linktype == 0:      # NULL / loopback
            ipoff = 4
        elif linktype == 101:    # RAW IP
            ipoff = 0
        else:
            ipoff = 14
        ip = pkt[ipoff:]
        if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 0x0f) * 4
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue
        sport = struct.unpack(">H", tcp[0:2])[0]
        dport = struct.unpack(">H", tcp[2:4])[0]
        doff = (tcp[12] >> 4) * 4
        seg = tcp[doff:]
        if sport == 443:
            s2c += seg
        elif dport == 443:
            c2s += seg
    return bytes(s2c), bytes(c2s)


def main():
    pcap = sys.argv[1]
    needles = sys.argv[2:]
    s2c, c2s = payloads(pcap)
    print(f"server->client bytes: {len(s2c)}   client->server bytes: {len(c2s)}")
    for h in needles:
        b = bytes.fromhex(h)
        i = s2c.find(b)
        j = c2s.find(b)
        print(f"  {h}: server->client {'@%d' % i if i >= 0 else 'NOT FOUND'} | "
              f"client->server {'@%d' % j if j >= 0 else 'NOT FOUND'}")


if __name__ == "__main__":
    main()
