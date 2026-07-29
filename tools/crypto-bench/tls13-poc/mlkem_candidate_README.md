# Provisional ML-KEM-768 candidate overlay

`mlkem_candidate_kernel.asm` is a product-shaped, `cpu 8086` implementation of
the provisional ML-KEM-768 boundary:

```text
m'       = K-PKE.Decrypt(dkPKE, c)
(K', r') = G(m' || H(ek))
```

It is not standards-complete decapsulation. The post-socket Fujisaki-Okamoto
phase must still re-encrypt, compare all 1088 serialized ciphertext bytes,
compute `J(z || c)`, and select the valid or implicit-rejection secret before
authentication can commit.

## Overlay ABI

The product link origin is `0x1800`, and the exported entry is
`mlkem_candidate_entry` at `0x1800`. `DS`, `ES`, and `SS` must be zero. The
caller supplies the product stack. The routine establishes `CLD`, clobbers the
general registers and flags, returns with `DF` clear, and returns the fixed
`G` pointer (`0x3b9c`) in `AX`.

The source is link-relocatable by defining `MLKEM_LOAD_ADDR`; it is not a
byte-for-byte runtime-position-independent image. The checker also links and
runs it at `0x2000`, while every external phase pointer remains fixed.

| Lifetime | Address | Bytes | Object |
| --- | ---: | ---: | --- |
| input, read-only | `0x08c0..0x0d00` | 1088 | raw `c` |
| input, consumed | `0x3600..0x3780` | 384 | compressed `sHat[0]` |
| input, copied first | `0x3780..0x37a0` | 32 | `H(ek)` |
| input, preserved | `0x37a0..0x37c0` | 32 | `z` |
| input, consumed | `0x3800..0x3980` | 384 | compressed `sHat[1]` |
| input, consumed | `0x3980..0x3b00` | 384 | compressed `sHat[2]` |
| in-K work | `0x3200..0x3400` | 512 | decoded `u`, then decoded `v` |
| in-K work | `0x3400..0x3600` | 512 | direct product accumulator |
| disposable high work | `0x3600..0x37e8` | 488 | Keccak state and auxiliaries |
| persistent output | `0x3a40..0x3a60` | 32 | decrypted `m'` |
| persistent output | `0x3b9c..0x3bdc` | 64 | `G = K' || r'` |
| persistent output | `0x3bdc..0x3bfc` | 32 | preserved `z` |

The candidate processes `sHat[2]`, `sHat[1]`, then `sHat[0]`. Each component
is decoded backward from 384 to 512 bytes in its own address band, so stores
can overlap only bytes already read or secret components already consumed.
Each decoded component is multiplied directly into `0x3400`; there is no
512-byte `poly_product`. After all three components die, their low address
bands become Keccak work.

The raw ciphertext is never modified. After return, the scheduler can copy it
from `0x08c0..0x0d00` to `0x3600..0x3a40`. That copy ends exactly where the
persistent `m'` output begins, so the full FO overlay retains `m' || r'`
without repeating K-PKE.Decrypt.

## Exact size ledger

The frozen product-origin image is 2113 bytes:

| Image part | Bytes |
| --- | ---: |
| executable | 1530 |
| immutable tables | 540 |
| internal scalar state | 43 |
| total | 2113 |

It occupies five load sectors (2560 bytes), ending at `0x2200`. This leaves
4096 sector-safe bytes at `0x2200..0x3200` for other timed-overlay code/state,
plus the required 1024-byte polynomial work area at `0x3200..0x3600`.
Candidate stack high water is 22 bytes including the synthetic return address.

## Oracle gate

Run:

```sh
python3 tools/crypto-bench/tls13-poc/mlkem_candidate_check.py
```

The checker:

- freezes the kernel, binary, vector source, input, and output SHA-256 hashes;
- reconstructs the existing OpenSSL/FIPS-derived ML-KEM-768 fixture;
- independently evaluates K-PKE.Decrypt with the existing integer oracle;
- tests the valid ciphertext and an exact one-bit `c[0]` mutation;
- confirms the invalid provisional candidate differs from OpenSSL's final
  implicit-rejection result;
- checks all three reverse/in-place secret decodes;
- proves raw `c` is byte-identical after both calls;
- checks the stack guard, all writes below 16 KiB, immutable/free address
  sentinels, fixed outputs, and the absence of a product polynomial; and
- links and executes the same source at `0x2000` to gate relocation.

For the chosen one-bit invalid mutation, K-PKE decoding intentionally produces
the same `m'` and `G` as the valid ciphertext. OpenSSL returns a different
implicit-rejection secret. This is a useful boundary test: the provisional
result must remain quarantined until the full FO phase validates `c`.
