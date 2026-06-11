#!/usr/bin/env python3
"""Faithful Python port of seed's 8088 Poly1305 (poly1305.inc) next to a reference
implementation, run over many-block messages to locate a value/size-dependent bug.

The port mirrors the asm byte-for-byte:
  add_block: acc[0..15] += block; acc[16] += 1 + carry   (full block + 2^128)
  mul_acc_r: schoolbook acc(17B) * r(16B) -> product(36B)
  reduce:    poly_value = product low 130 bits; fold product/​value high bits *5; sub prime
"""

P = (1 << 130) - 5


def clamp_r(r16):
    r = bytearray(r16)
    for i in (3, 7, 11, 15):
        r[i] &= 0x0f
    for i in (4, 8, 12):
        r[i] &= 0xfc
    return bytes(r)


# ---------- reference ----------
def poly_ref(otk, msg):
    r = int.from_bytes(clamp_r(otk[:16]), "little")
    s = int.from_bytes(otk[16:32], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block, "little") + (1 << (8 * len(block)))  # raw poly: 1 bit past data
        acc = ((acc + n) * r) % P
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def poly_ref_fullblocks(otk, msg):
    """Reference but ALWAYS add 2^128 (matches the device's add_block; valid when msg is
    pre-padded to whole blocks, as in the AEAD construction)."""
    assert len(msg) % 16 == 0
    r = int.from_bytes(clamp_r(otk[:16]), "little")
    s = int.from_bytes(otk[16:32], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16], "little") + (1 << 128)
        acc = ((acc + n) * r) % P
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


# ---------- device port ----------
def add_al_times5(val, di, al):
    if al == 0:
        return
    v = al * 5
    w = val[di] | (val[di + 1] << 8)
    w += v
    val[di] = w & 0xff
    val[di + 1] = (w >> 8) & 0xff
    carry = w >> 16
    bx = di + 2
    while carry:
        t = val[bx] + carry
        val[bx] = t & 0xff
        carry = t >> 8
        bx += 1


def reduce_product(product):
    VLEN = 24
    val = bytearray(VLEN)
    val[0:17] = product[0:17]
    val[16] &= 0x03
    # fold_product_high
    for i in range(19):
        al = (product[16 + i] >> 2) | ((product[17 + i] << 6) & 0xff)
        add_al_times5(val, i, al)
    al = product[35] >> 2
    add_al_times5(val, 19, al)
    # fold_value_high x3
    for _ in range(3):
        for i in range(7):
            al = (val[16 + i] >> 2) | ((val[17 + i] << 6) & 0xff)
            add_al_times5(val, i, al)
        al = val[23] >> 2
        add_al_times5(val, 7, al)
        val[16] &= 0x03
        for k in range(17, VLEN):
            val[k] = 0
    # subtract prime until below
    prime = (P).to_bytes(17, "little")
    def below():
        for k in range(16, -1, -1):
            if val[k] < prime[k]:
                return True
            if val[k] > prime[k]:
                return False
        return False  # equal -> not below
    while not below():
        borrow = 0
        for k in range(17):
            t = val[k] - prime[k] - borrow
            val[k] = t & 0xff
            borrow = 1 if t < 0 else 0
    return bytes(val[0:17])


def mul_acc_r(acc, r):
    product = bytearray(36)
    for i in range(17):
        for j in range(16):
            prod = acc[i] * r[j]
            idx = i + j
            w = product[idx] | (product[idx + 1] << 8)
            w += prod
            product[idx] = w & 0xff
            product[idx + 1] = (w >> 8) & 0xff
            carry = w >> 16
            bx = idx + 2
            while carry:
                t = product[bx] + carry
                product[bx] = t & 0xff
                carry = t >> 8
                bx += 1
    return product


def add_block_fullblock(acc, block16):
    acc = bytearray(acc)
    carry = 0
    for k in range(16):
        t = acc[k] + block16[k] + carry
        acc[k] = t & 0xff
        carry = t >> 8
    t = acc[16] + 1 + carry
    acc[16] = t & 0xff  # NOTE: asm does `adc [di],al` with al=1 -> acc[16]+=1+carry, NO further carry out
    return bytes(acc)


def poly_device(otk, msg):
    assert len(msg) % 16 == 0
    r = clamp_r(otk[:16])
    s = int.from_bytes(otk[16:32], "little")
    acc = bytes(17)
    for i in range(0, len(msg), 16):
        acc = add_block_fullblock(acc, msg[i:i + 16])
        product = mul_acc_r(acc, r)
        acc = reduce_product(product)
    accint = int.from_bytes(acc, "little")
    return ((accint + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def process_block(acc, block16, r):
    acc = add_block_fullblock(acc, block16)
    return reduce_product(mul_acc_r(acc, r))


def poly_aead_streaming(otk, aad, cipher):
    """Faithful port of tls_poly1305_app_init/update/final (the AEAD MAC the device uses)."""
    r = clamp_r(otk[:16])
    s = int.from_bytes(otk[16:32], "little")
    acc = bytes(17)
    # app_init: AAD into a zeroed block, process, reset
    pb = bytearray(16)
    pb[0:len(aad)] = aad
    acc = process_block(acc, pb, r)
    pb = bytearray(16)
    fill = 0
    # app_update: byte-by-byte into pb, process at 16
    for b in cipher:
        pb[fill] = b
        fill += 1
        if fill == 16:
            acc = process_block(acc, pb, r)
            pb = bytearray(16)
            fill = 0
    cipher_len = len(cipher)
    # app_final: trailing partial (already zero-padded), then the lengths block
    if fill != 0:
        acc = process_block(acc, pb, r)
    pb = bytearray(16)
    pb[0] = len(aad)
    pb[8] = cipher_len & 0xff
    pb[9] = (cipher_len >> 8) & 0xff
    acc = process_block(acc, pb, r)
    return ((int.from_bytes(acc, "little") + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def poly_aead_reference(otk, aad, cipher):
    msg = bytes(aad) + b"\x00" * ((16 - len(aad) % 16) % 16)
    msg += bytes(cipher) + b"\x00" * ((16 - len(cipher) % 16) % 16)
    msg += len(aad).to_bytes(8, "little") + len(cipher).to_bytes(8, "little")
    return poly_ref_fullblocks(otk, msg)


def main():
    import os
    print("=== AEAD streaming layer vs reference (AAD=13, varying cipher len) ===")
    for clen in (5, 100, 250, 256, 500, 531, 536, 1369, 1376, 1385):
        aad = bytes((i * 17 + 3) & 0xff for i in range(13))
        cipher = bytes((i * 37 + 11) & 0xff for i in range(clen))
        otk = bytes((i * 53 + 7) & 0xff for i in range(32))
        ref = poly_aead_reference(otk, aad, cipher)
        dev = poly_aead_streaming(otk, aad, cipher)
        ok = "OK " if ref == dev else "MISMATCH"
        print(f"  cipher={clen:5d} (fill={clen % 16:2d}): {ok}  ref={ref[:6].hex()}  dev={dev[:6].hex()}")
    print("=== core (whole-block) vs reference ===")
    for nblocks in (1, 2, 8, 27, 28, 50, 85, 86, 100):
        msg = bytes((i * 37 + 11) & 0xff for i in range(nblocks * 16))
        otk = bytes((i * 53 + 7) & 0xff for i in range(32))
        ref = poly_ref_fullblocks(otk, msg)
        dev = poly_device(otk, msg)
        ok = "OK " if ref == dev else "MISMATCH"
        print(f"{nblocks:4d} blocks: {ok}  ref={ref[:6].hex()}  dev={dev[:6].hex()}")


if __name__ == "__main__":
    main()
