# Offline ML-KEM-768 FO tail

`fo_tail_kernel.asm` is the product-shaped post-socket
Fujisaki-Okamoto tail. It consumes the provisional handoff without repeating
K-PKE.Decrypt:

```text
c'       = K-PKE.Encrypt(ek, m', r')
valid    = fixed_length_compare(c', c)
reject   = J(z || c)
selected = valid ? K' : reject
```

The implementation is `cpu 8086`, has no fixture, serial, or timing harness,
and fits as one K overlay.

## Entry and result

The product entry is `fo_tail_entry` at `0x1800`. `DS`, `ES`, and `SS` must be
zero. `BX` supplies a near public-object read callback. The routine establishes
`CLD` and returns:

| Return | Meaning |
| --- | --- |
| `CF=0`, `AX=1` | serialized `c' == c`; `0x3b9c..0x3bbc` is confirmed `K'` |
| `CF=0`, `AX=0` | reject; `0x3b9c..0x3bbc` is `J(z || c)` |
| `CF=1`, `AX=0xffff` | public read failed; the 32-byte output was zeroed |

The compare visits all 1088 serialized bytes and OR-reduces every difference.
The `K'/J` selection is branchless. The public valid/reject status is returned
only after selection.

The directly callable labels `fo_reencrypt_start`, `fo_reencrypt_end`, and
`fo_j_start` are retained for an 8088 timing wrapper. The source can also be
linked at another origin with `FO_LOAD_ADDR`; the checker executes an
alternate `0x2000` link.

## Stream callback ABI

The callback receives:

```text
AL = object id: 0 for ek[1184], 1 for c[1088]
DX = byte offset
CX = byte count, at most 384
DI = destination below 0x4000
```

It returns carry clear on success or set on failure, preserves `BX`, `BP`,
`DS`, `ES`, and `SS`, and returns with `DF` clear. The object IDs must refer to
one immutable, attempt-bound snapshot for the entire call. A disk-backed
implementation must bind the header/generation/hash before entering this
overlay; the kernel does not defend against an object changing between reads.

The fixed valid and invalid schedule is 17 requests:

- `ek`: `rho[32]`, then three `tHat[384]` components — 1184 bytes total;
- first `c` pass: three `u[320]` components and `v[128]` — 1088 bytes;
- second `c` pass for `J`: `104 + 7×136 + 32` bytes — 1088 bytes.

Valid and invalid ciphertexts execute the same read schedule. The raw public
objects never need to coexist in the low workspace.

## Memory and lifetimes

| Lifetime | Address | Bytes | Object |
| --- | ---: | ---: | --- |
| preserved | `0x0700..0x0830` | 304 | ticket hold |
| FO work | `0x0830..0x0e30` | 1536 | `yHat[0..2]` |
| FO work | `0x0e30..0x0e50` | 32 | cached `rho` |
| FO work | `0x0e50..0x0fd0` | 384 | bounded public stream buffer |
| guard | `0x0fd0..0x1000` | 48 | low-work overrun guard |
| FO work | `0x3000..0x31e8` | 488 | Keccak state and auxiliaries |
| free | `0x31e8..0x3400` | 536 | K gap |
| FO work | `0x3400..0x3600` | 512 | direct accumulator |
| preserved | `0x3600..0x3a40` | 1088 | optional saved-`c` RAM mirror |
| input, preserved | `0x3a40..0x3a60` | 32 | `m'` |
| input/output | `0x3b9c..0x3bbc` | 32 | provisional then selected secret |
| input, preserved | `0x3bbc..0x3bdc` | 32 | `r'` |
| input, preserved | `0x3bdc..0x3bfc` | 32 | `z` |

Three complete `yHat` polynomials are necessary because every `u` row and
`v` use all three. Matrix and `tHat` polynomials are consumed four
coefficients at a time and multiplied directly into `0x3400`; there is no
512-byte `poly_product`.

## Exact ledger

The product-origin image is 2829 bytes:

| Image part | Bytes |
| --- | ---: |
| executable | 2182 |
| immutable tables | 574 |
| internal scalar state | 73 |
| total | 2829 |

It loads in six sectors (3072 bytes), ending at `0x2400`. There are 3072
sector-safe bytes before Keccak work begins at `0x3000`. External K work is
1000 bytes, and stack high water is 26 bytes including the synthetic return.
No overlay split is required.

## Oracle gate

Run:

```sh
python3 tools/crypto-bench/tls13-poc/fo_tail_check.py
```

The checker freezes source, binary, input, and output hashes; streams the
existing OpenSSL/FIPS-derived objects through a hooked callback; independently
re-encrypts with the Python FIPS arithmetic oracle; runs valid and exact
one-bit-invalid cases; verifies OpenSSL valid and implicit-rejection outputs;
checks failure at every read position; and gates all writes, the ticket hold, high public
mirror, persistent handoff, arena/context, stack, 16 KiB ceiling, and
alternate link origin.
