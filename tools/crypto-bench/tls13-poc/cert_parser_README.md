# Streaming TLS 1.3 certificate parser PoC

This isolated `cpu 8086` PoC closes the target-side parsing gap between the
TLS 1.3 symmetric flight and `issuer_auth_overlay.asm`. It does not change or
link the Seed runtime, and no VM result is claimed.

The recommended first integration path is an **uncompressed** TLS 1.3
Certificate message:

1. stream a bounded tentative-plaintext callback while the record is
   provisional;
2. publish nothing until the record tag passes;
3. parse one captured leaf with a narrow, strict X.509 profile;
4. hash the exact TBSCertificate and TLS CertificateVerify signed input;
5. apply a separate trusted-time policy;
6. pass the resulting digest, signature, point, and profile bits to
   `issuer_auth`.

This removes the need to retain the whole certificate chain. It does not remove
the need to authenticate the leaf under WE1 or to find a self-contained trusted
time source.

## Trust boundary

The parser earns leaf profile `0x001f`, covering:

- bounded canonical Certificate/TBSCertificate framing and strict encoding of
  every walked security-profile field;
- matching inner and outer `ecdsa-with-SHA256`;
- exact P-256 `id-ecPublicKey`/`prime256v1` uncompressed SPKI;
- critical `CA=false` basic constraints;
- critical digital-signature-only key usage;
- noncritical server-auth-only EKU;
- exactly one SAN extension containing exact `api.openai.com`;
- canonical, positive, nonzero, at-most-256-bit ECDSA scalars;
- normalized validity syntax and calendar fields.

Unknown critical extensions, duplicate required extensions, malformed walked
fields, trailing fields, and unsupported algorithms fail closed. Issuer and
subject Names are covered by the certificate signature but only their outer
SEQUENCE bounds are walked; their signed inner contents remain opaque and are
not assigned policy meaning.

The parser does **not** earn trusted-time bit `0x0020`. The one-sector time
overlay accepts only an already-trusted `YYYYMMDDHHMMSS` value, validates the
full 2000–2099 calendar, performs inclusive validity comparison, and then
elevates exactly `0x001f -> 0x003f`. It does not establish a clock. BIOS time,
unauthenticated NTP, or server-controlled time cannot be presented as trusted.

CertificateVerify separately earns profile `0x0700` only for exact scheme
`0x0403`, strict signature DER, and the TLS 1.3 server CertificateVerify
context digest. Neither ECDSA equation is checked here:
`issuer_auth_overlay.asm` verifies the certificate signature under immutable
WE1 and then verifies CertificateVerify under only that authenticated leaf.

The handoff is deliberately monotonic. Parser success is
`leaf_status=1/profile=0x001f`; the hash phase consumes and zeroizes the leaf,
then emits the distinct post-hash seal
`leaf_status=2/hash_status=1/profile=0x001f`. The time phase accepts only that
seal. A second hash invocation first clears `hash_status`, rejects the consumed
leaf, and cannot manufacture a digest over zeroized bytes. Direct low-work
clear removes status 2, parser reset clears hash/time status, failed leaf/CV
re-entry clears its profile, and a pre-elevated time profile is cleared before
any early status rejection.

## Measured layout

The current real fixture is a 903-byte OpenAI leaf, leaving 121 bytes inside
the deliberately hard 1,024-byte leaf limit.

| Interval | Bytes | Lifetime/use |
|---|---:|---|
| `0x0700..0x08b7` | 439 | live NIC receive band; checked untouched |
| `0x08c0..0x0cc0` | 1,024 | captured leaf in retired ML-KEM ciphertext band |
| `0x0cc0..0x0cd2` | 18 | streaming Certificate state |
| `0x0d00..0x0d22` | 34 | post-flight X.509 state |
| `0x0d40..0x0edc` | 412 | post-flight SHA-256 work |
| `0x1800..0x2288` | 2,696 | parser image, six rounded sectors |
| `0x1800..0x1ffd` | 2,045 | hash image, four rounded sectors |
| `0x1800..0x194f` | 335 | time image, one sector |
| `0x3400..0x3600` | 512 | K14 phase-owned reclaimed space; checked untouched |
| `0x3600..0x3790` | 400 | parser/hash/profile outputs |
| `0x39a5..0x3b25` | 384 | existing symmetric mutable record payload |

The hash workspace ends below the `0x0f00` delta-loader trampoline. The attempt
cache at `0x3b9c`, reconnect state, arena/context at `0x3e40`, and stack remain
at their existing addresses. Measured routine stack high-water is 40 bytes.

The output band deliberately reuses symmetric **handshake-only** state.
Integration may overwrite it only after the Finished/application-key
transition has made `0x3600..0x3790` dead. Application secrets and keys above
that range must remain live.

## Streaming and hostile-input gate

The Certificate parser accepts arbitrary chunk cuts up to the existing
384-byte MSS. It captures only the leaf and validates/discards the remaining
chain framing. Current limits are:

- 4,096-byte Certificate body;
- 1,024-byte leaf;
- 2,048-byte discarded chain certificate;
- 1,024-byte per-entry extensions;
- four entries after the leaf;
- 80-byte complete CertificateVerify handshake message.

`cert_parser_check.py` assembles each overlay in default and K14 modes and
requires byte identity. Under Unicorn it checks the real OpenAI/WE1/GTS fixture
with 384-, 383-, one-byte, and mixed chunking, then rejects:

- every one of 2,495 proper Certificate prefixes;
- 17 framing/limit mutations;
- 21 DER/profile mutations;
- 85 CertificateVerify truncation/DER/scheme mutations;
- 17 time/profile mutations, while accepting both inclusive boundaries.

It independently checks the two target SHA-256 digests, a canonical TBS
tamper, direction-flag hardening, exact return stack, low zeroization, and all
surrounding memory sentinels.

## Live-link gate

The first standalone layout had a 780-byte prefix, but its general reset also
zeroed `0x3600..0x3790` and was therefore unsafe while symmetric handshake
state was live. The PoC now exposes a distinct low-only reset/rollback and a
748-byte capture callback.

The current 278-byte figure is only a raw code subtraction:
`7,168 - 6,142 - 748`. It omits the symmetric overlay's simultaneously live
1,016-byte mutable K workspace at `0x3000..0x33f8`. That workspace already
leaves only 8 bytes below `0x3400`. Naively appending the callback moves the
aligned workspace to `0x32f0..0x36e8`, overflowing K14 by 744 bytes and
colliding with phase-owned reclaimed space. The callback therefore
cannot coexist as ordinary linked K14 code in the current layout.

The 748 bytes would arithmetically occupy `0x0d00..0x0fec` after the HELLO
transcript context has been imported. This is only an unproved relocation
candidate: it overlaps the live protected-flight scatter at
`0x0d00..0x0eff`, immediately below the loader schedule beginning at `0x0f00`.
The scatter/loader lifetime and all sentinels would need a different linked
proof before that placement is usable.

Before integration can be called viable, one combined K14 image must prove:

1. the controller routes Certificate bytes to the callback across arbitrary
   record and TCP cuts;
2. provisional plaintext remains quarantined until `sym_open_finish`;
3. a bad tag erases leaf and stream state;
4. CertificateVerify and the transcript boundary survive until their strict
   parser runs;
5. Finished and application-key derivation complete before parser outputs
   reuse the dead handshake band;
6. executable placement is resolved without colliding with the symmetric K
   workspace or protected-flight staging;
7. the linked image, writes, stack, and 4.77 MHz timing pass the literal 16 KiB
   harness.

No K14 coexistence claim is made until that image exists.

## Why Brotli is deferred

For the current reconstructed flight, omitting RFC 8879 certificate compression
saves seven ClientHello bytes but expands the protected Certificate record by
696 bytes:

| Item | Brotli q6 | Uncompressed |
|---|---:|---:|
| Certificate handshake | 1,799 B | 2,495 B |
| Protected record | 1,945 B | 2,641 B projected |
| 384-byte chunks | 6 | 7 |

Existing literal 4.77 MHz measurements convert that delta to ten ChaCha
blocks, 43 Poly1305 blocks, eleven SHA-256 blocks, and 44 timer ticks
(2.4167 seconds). The provisional fixed-work total including the ML-KEM
candidate becomes 12.6658 seconds, leaving only 2.3342 seconds to 15 seconds
before several omitted costs. It is a cost estimate, not an end-to-end pass.

The exact decoded body was re-encoded with Brotli 1.2.0. The q6 stream declares
WBITS=12 (legal backward distance 4,080); one instrumented re-encode happened
to use distance at most 1,705 and no static dictionary. A 2,048-byte ring would
therefore decode that one re-encoded command stream, but RFC 8879 negotiates
neither a smaller window nor a restricted command profile. A future server
stream may legally need the full window, static dictionary, context maps,
block switching, and general Huffman/command handling.

Therefore the first PoC should omit certificate compression and pay the
measured 696-byte/2.4167-second delta. A restricted Brotli decoder becomes
reasonable only with retained raw provider streams, an enforceable provider
profile, and separate target code/workspace/timing gates.

## Run

```sh
python3 tools/crypto-bench/tls13-poc/cert_parser_check.py --json
python3 tools/crypto-bench/tls13-poc/cert_parser_tradeoff_check.py --json
```

Machine-readable results are in `cert_parser_results.json` and
`cert_parser_tradeoff_results.json`.

## Remaining blockers

- No self-contained trusted clock source has been selected or proved.
- The 1,024-byte leaf cap is a provider-compatibility contract; the current
  leaf has only 121 bytes of growth margin.
- The 748-byte live-safe callback does not fit beside the current 6,142-byte
  symmetric image and `0x3000..0x33f8` mutable K workspace below `0x3400`;
  only 8 bytes remain and the naive aligned link overflows by 744 bytes.
- The `0x0d00..0x0fec` relocation candidate is unproved and conflicts with the
  live scatter at `0x0d00..0x0eff` and adjacent loader schedule at `0x0f00`.
- Issuer input at `0x3ba4..0x3c53` overlaps full retained symmetric state at
  `0x3b40..0x3c2e` by 138 bytes; the native ticket bundle may still end at
  `0x3c2d`. Live ordering or relocation is unproved.
- Certificate/CV routing, tag-failure rollback, Finished ordering, and
  credential-release gating are not integrated.
- No new literal 4.77 MHz VM timing was run for the parser or linked path.
- WE1 anchor rotation/expiry remains a separate authenticated update problem.
