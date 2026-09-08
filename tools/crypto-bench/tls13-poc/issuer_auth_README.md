# WE1-authorized TLS 1.3 authentication overlay

This isolated PoC removes the exact-leaf dependency from the 16 KiB trust
phase. It does not change or link the Seed runtime.

One `cpu 8086` image is loaded twice:

1. pass 1 validates a parser-supplied P-256 leaf point, then verifies
   `SHA-256(TBSCertificate)` and the leaf certificate signature under an
   immutable Google Trust Services WE1 P-256 anchor;
2. pass 1 commits that authenticated dynamic leaf into post-FO high memory;
3. the overlay may be reloaded and all low curve work discarded;
4. pass 2 verifies TLS 1.3 `CertificateVerify` under only the committed leaf.

The pass-2 point-shaped input capacity is ignored. Calling pass 2 first,
changing attempts, failing issuer verification, or corrupting the handoff
fails closed.

## Measured layout

The image is 7,134 content bytes and exactly 14 rounded sectors:

| Interval | Bytes | Use |
|---|---:|---|
| `0x1800..0x33de` | 7,134 | immutable overlay code/constants |
| `0x33de..0x3600` | 546 | unloaded K tail |
| `0x0700..0x0fba` | 2,234 | phase-local ECDSA/point work |
| `0x0fba..0x1000` | 70 | checked untouched low tail |
| `0x3600..0x3672` | 114 | authenticated leaf handoff |
| `0x3ba4..0x3c53` | 175 | reused pass input/output ABI |

The resident nucleus, active baseline product driver, reconnect/ESC state,
96-byte arena, 96-byte context, and stack keep their existing addresses.
Target routine stack high-water in the checker is 78 bytes.

Externalizing the shared P-256 mutable block through
`P256_EXTERNAL_WORK_BASE` is what makes the phase fit. Both passes use the
same 14 sectors; there is no requirement to keep both copies resident.

## Entry table

The first six words at `0x1800` are:

| Offset | Value |
|---:|---|
| `+0` | near pointer: verify leaf certificate signature under WE1 |
| `+2` | near pointer: verify TLS CertificateVerify under committed leaf |
| `+4` | near pointer: clear low/input/commit state |
| `+6` | near pointer: immutable WE1 SPKI SHA-256 |
| `+8` | image content length |
| `+10` | ABI version, currently 1 |

Calls use `DS=ES=SS=0` and return:

```text
CF=0, AX=1, output_status=1   accepted
CF=1, AX=0, output_status=0   rejected
```

The clear entry is a zeroization operation and has no success-result ABI.
All failure stages must map to the same caller-visible close path.

## Input ABI

Eight-byte checker guards bracket the product input:

| Address | Bytes | Meaning |
|---:|---:|---|
| `0x3b9c` | 8 | checker guard |
| `0x3ba4` | 2 | exact parser/profile bitmap |
| `0x3ba6` | 2 | nonzero local attempt generation |
| `0x3ba8` | 32 | signed-input SHA-256 digest, big-endian |
| `0x3bc8` | 2 | strict DER ECDSA length, `8..72` |
| `0x3bca` | 72 | signature capacity |
| `0x3c12` | 32 | pass-1 leaf x, big-endian |
| `0x3c32` | 32 | pass-1 leaf y, big-endian |
| `0x3c52` | 1 | output status |
| `0x3c94` | 8 | checker guard |

The default isolated ABI is not coexistence-safe with the full retained
symmetric state: `0x3ba4..0x3c53` overlaps `0x3b40..0x3c2e` by 138 bytes.
The native ticket identity/nonce/metadata bundle may still end at `0x3c2d`;
the extra retained byte is nevertheless live. The optional
`TLS13_POC_READ_ONLY_INPUT` profile relocates it to `0x3400..0x34af` after the
network/parser controller retires. The dedicated
`issuer_input_relocation_check.py` proves both real signatures, phase reloads,
native ticket stability, and handoff to the atomic commit gate. The default
checker intentionally retains the collision as its negative architecture
control.

Pass 1 requires profile `0x003f`. Its six caller-owned parser/policy proofs
are:

1. canonical outer and TBS `ecdsa-with-SHA256` algorithms match;
2. SPKI is exactly `id-ecPublicKey`, `prime256v1`, uncompressed 65-byte SEC1;
3. `CA=false`, digital-signature key use, and server-auth EKU pass;
4. the required `api.openai.com` DNS identity passes;
5. bounded canonical certificate/TBS framing produced the exact TBS digest;
6. validity syntax and the caller's chosen time policy pass.

Pass 2 requires profile `0x0700`: exact scheme `0x0403`, exact TLS 1.3 server
CertificateVerify context construction, and the transcript boundary/order
through Certificate all passed.

These bitmaps are a narrow ABI from trusted parser/policy code. Network input
cannot be treated as a bitmap. A separate strict uncompressed target parser
now earns the structural/name/use bits in isolated overlays. It is not
live-linked into K14, it does not establish trusted time, and no bounded target
Brotli decoder exists.

## Handoff and ordering

Pass 1 writes status last:

| Address | Bytes | Meaning |
|---:|---:|---|
| `0x3600` | 1 | committed status |
| `0x3601` | 1 | reserved zero |
| `0x3602` | 4 | `WE1!` magic |
| `0x3606` | 4 | magic complement |
| `0x360a` | 2 | attempt generation |
| `0x360c` | 2 | accepted leaf profile |
| `0x360e` | 64 | authenticated leaf x/y, big-endian |
| `0x364e` | 32 | authenticated TBS digest |
| `0x366e` | 4 | torn/corruption checksum |

The checksum catches accidental or torn state and is not a cryptographic RAM
MAC. The security boundary is the pass-1 ECDSA proof plus trusted control flow:
only that success path writes committed status. A caller that permits arbitrary
RAM writes can also bypass the caller itself and is outside this PoC's threat
model.

Pass 2 requires the same nonzero attempt generation, verifies the handoff, and
revalidates the committed point's coordinate ranges and curve equation before
building its table. Any pass-2 failure clears the commit.

## Real checked vector

The immutable anchor is the WE1 certificate already present as the second
certificate in `tools/x509/certs/ecdsa_live_chain.pem`:

```text
WE1 SPKI SHA-256:
908769e8d34477cc2cba0632c88605b22d7294c0840f78596d247c645b1afc0e
```

`issuer_auth_live_leaf.pem` and `issuer_auth_live_vector.json` are a
credential-free capture from `api.openai.com:443` on 8 September 2026. The
captured leaf has SPKI
`94655ad1e178ae4e1a28f7bfc97c0b0e48684f4b6370c639ab988a27d11e028f`
and expires 4 December 2026. The host capture uses X25519 and
TLS_CHACHA20_POLY1305_SHA256, completes the authenticated handshake, and sends
no application request. It supplies a real CertificateVerify fixture; target
hybrid-route acceptance still requires the live product gate.

The checker independently:

- verifies the captured leaf's WE1 chain, hostname, purpose, and validity at
  capture time with OpenSSL;
- extracts the exact TBS bytes, certificate signature, and leaf point;
- reconstructs and host-verifies the captured CertificateVerify signed input;
- runs both real signatures through the 8086 overlay in order;
- reloads the phase and poisons all low work between passes.

The dated leaf is only a deterministic real fixture. It is not embedded in the
overlay and is not a pin or provider SLA.

## Gate

Run:

```sh
python3 tools/crypto-bench/tls13-poc/issuer_auth_check.py
```

The hostile matrix covers:

- CertificateVerify before issuer authorization;
- wrong parser profiles and zero/stale attempt generations;
- coordinates at or above `p`, and off-curve points;
- long-form, negative, zero, redundantly padded, trailing, and `r/s >= n`
  signature forms;
- a canonical but wrong issuer signature;
- a torn authenticated handoff;
- a canonical but wrong CertificateVerify signature;
- phase reload, low-work poisoning, zeroization, exact return IP/SP/word, and
  all surrounding memory sentinels.

## Remaining product gaps

- The strict uncompressed target parser exists as an isolated overlay, but its
  live K14 routing, authentication-order handoff, and failure cleanup are not
  linked. No bounded target Brotli decoder exists.
- The default issuer input ABI overlaps full retained symmetric state by
  138 bytes. The isolated read-only relocation gate resolves the memory
  lifetime, but the same ordering still needs live parser/FO linkage.
- Trusted certificate-time policy on a cold 8088 remains unresolved. The
  checked vector proves validity at capture time on the host; the bitmap does
  not manufacture trusted time.
- WE1 itself expires in 2029 and needs a separately authenticated anchor-update
  policy.
- This task did not run a literal 4.77 MHz timing measurement. The earlier
  one-signature exact-leaf phase measured about 54 seconds; two issuer/leaf
  equations therefore have a floor around 109 seconds before extra point
  validation, phase I/O, parsing, and decompression. That work is post-Finished
  and need not fit the initial 15-second race, but it must still be measured.
- This is an isolated PoC. Ticket promotion, credential release, TLS record
  plumbing, and failure-path integration remain outside it.
