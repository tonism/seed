# Exact-leaf P-256 CertificateVerify overlay

This is an isolated product-shaped TLS 1.3 authentication PoC. It does not
change or link the Seed runtime.

The production image:

- assembles as `cpu 8086` at `0x1800`;
- loads only 13 sectors inside the unchanged 15-sector K window;
- accepts a SHA-256 CertificateVerify digest, strict-DER ECDSA signature, and
  P-256 leaf point;
- requires that point to equal the immutable tracked `api.openai.com` leaf;
- generates the width-4 G and leaf tables on target;
- executes the complete P-256 ECDSA equation;
- returns only success/failure and provides a zeroization entry;
- reuses offline low scratch without moving the 16 KiB arena, context, or
  stack.

It deliberately does not implement Brotli, X.509, hostname/time policy, WE1
recertification, transcript construction, TLS records, or sockets.

## ABI

The first five words at `0x1800` are:

| Offset | Value |
|---:|---|
| `+0` | near pointer: `auth_overlay_verify` |
| `+2` | near pointer: `auth_overlay_pin_match` |
| `+4` | near pointer: `auth_overlay_clear` |
| `+6` | near pointer: immutable SPKI SHA-256 |
| `+8` | image byte length |

Call the verify entry with `DS=ES=0`:

```text
CF=0, AX=1, auth_output_status=1   accepted
CF=1, AX=0, auth_output_status=0   rejected
```

All failure stages must map to the same caller-visible close path.

The fixed input block overlays the quarantined attempt cache:

| Address | Bytes | Meaning |
|---:|---:|---|
| `0x3b9c` | 8 | checker sentinel; not part of the product ABI |
| `0x3ba4` | 32 | CertificateVerify SHA-256 digest, big-endian |
| `0x3bc4` | 2 | little-endian DER length, `8..72` |
| `0x3bc6` | 72 | DER signature capacity |
| `0x3c0e` | 32 | leaf x, big-endian |
| `0x3c2e` | 32 | leaf y, big-endian |
| `0x3c4e` | 1 | output status |
| `0x3c94` | 8 | checker sentinel; not part of the product ABI |

The target-generated mutable work occupies `0x0700..0x0fb6` (2,230 bytes).
The original 1,334-byte authentication state remains at `0x0700..0x0c36`.
Defining `P256_EXTERNAL_WORK_BASE=0x0c36` makes `p256.inc` alias its complete
896-byte wNAF, Karatsuba, and Solinas work block into the remaining phase-local
scratch instead of emitting it in K:

| Low interval | Bytes | P-256 storage |
|---:|---:|---|
| `0x0c36..0x0cb6` | 128 | width-4 x table |
| `0x0cb6..0x0d36` | 128 | width-4 y table |
| `0x0d36..0x0db6` | 128 | 2P x/y, negated y, scalar |
| `0x0db6..0x0ec9` | 275 | digits, count, temporary, pointers |
| `0x0ec9..0x0eca` | 1 | alignment |
| `0x0eca..0x0f92` | 200 | Karatsuba work |
| `0x0f92..0x0fb6` | 36 | Solinas accumulator |
| `0x0fb6..0x1000` | 74 | checked untouched tail |

This is valid only after the provisional socket is retired and the FO phase is
complete: the packet/phase/file scratch in that window must be dead. The
assembly asserts the 896-byte private-work contract and the `0x1000` ceiling;
the checker separately mirrors the address ledger and guards the 74-byte tail.
Without `P256_EXTERNAL_WORK_BASE`, the shared P-256 include emits its original
data block, so existing runtime consumers retain their layout. The overlay does
not touch:

```text
0x1000..0x1800  resident nucleus and active baseline product driver
0x3600..0x3b9c  FO/TLS vault
0x3c9c..0x3e40  reconnect and ESC state
0x3e40..0x3f00  96-byte arena plus 96-byte context
0x3f00..0x4000  stack guard
```

## Pin

`auth_p256_pins.inc` is derived from the first certificate in
`tools/x509/certs/ecdsa_live_chain.pem`:

```text
subject:  CN=api.openai.com
issuer:   Google Trust Services WE1
notAfter: 2026-08-08 02:13:12 UTC
SPKI SHA-256:
f60fa6b7254084bdf0425d0954e283292e4d66d616b72e6942e2e35a44a54c25
```

The checker independently extracts that tracked certificate with OpenSSL and
requires the embedded point and complete SPKI digest to match. Rotation fails
closed. A successor/WE1-authorized update path is outside this PoC.

## Gate

Run:

```sh
python3 tools/crypto-bench/tls13-poc/auth_p256_check.py
```

To refresh the checked result:

```sh
python3 tools/crypto-bench/tls13-poc/auth_p256_check.py \
  --json-out tools/crypto-bench/tls13-poc/auth_p256_results.json
```

The checker assembles both production and deterministic synthetic-pin images.
The synthetic build uses the known-private fixture from
`tls13-spike/auth_integrated_oracle.py` and executes in Unicorn:

- a valid CertificateVerify and all `r/s/z/w/u1/u2/x mod n` intermediates;
- a changed transcript digest;
- a canonical but incorrect signature;
- malformed DER;
- a changed exact leaf point;
- zeroization;
- input, K-tail, resident-driver, vault, reconnect, arena/context, and stack
  sentinels.

The current measured layout is 6,632 content bytes and 13 rounded sectors. It
leaves 1,048 bytes of the unchanged K capacity unloaded. The 904-byte content
reduction consists of 896 externalized data bytes plus an 8-byte redundant
K-zeroing sequence that is no longer needed. Low-memory high-water is
`0x0fb6`, leaving 74 bytes before the resident nucleus; routine-only stack
high-water remains 72 bytes.
