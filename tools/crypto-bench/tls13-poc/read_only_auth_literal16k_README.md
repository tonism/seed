# Literal 16 KiB read-only authentication/commit PoC

This harness proves that the post-Finished authentication, route commit, and
fixed credential-unlock architecture can execute in the exact-speed 86Box
floor configuration:
4.772728 MHz 8088, exactly 16 KiB RAM, and dynarec disabled. During the
recorded run the generated floppy image had host mode `0444`, a host
write-only open was denied, and its before/after hash was unchanged. This is
fixture-fed evidence, not a physical-machine or complete live secure-connection
claim.

ROM BASIC loads a four-sector resident prefix. The same contiguous,
host-read-only floppy image supplies cold phases and public fixtures:

1. runtime-test that AH=03 is rejected before the harness's sole `INT 13h`;
2. stage a complete tentative ticket in the symmetric overlay's native slots;
3. load the exact 14-sector issuer phase;
4. verify the checked-in current OpenAI leaf signature under immutable WE1;
5. reload the same phase, ending exactly at `0x3400`;
6. verify the captured TLS 1.3 CertificateVerify under the committed leaf;
7. load the two-sector hostile-tested atomic gate;
8. forge the old internally consistent route/state marker quartet and prove
   that the direct callback still rejects it because the complete committed
   bundle is absent;
9. publish the `LIVE_TICKET` route only after issuer, CertificateVerify, and
   ticket validation;
10. reject a deliberately partial first credential callback, scrub its target
   and six-byte publication descriptor,
   and preserve the valid commit for retry;
11. invoke the same fixed build-time callback with its fixed phase key and
   destination, revalidate the full bundle through the gate's fourth entry,
   read a credential-free canary sector into retired low scratch, and publish
   its 32-byte test key plus trailing NUL, checksum, length, inverse, and
   status-last descriptor.

The fixed credential slot phase-reuses retired issuer input at
`0x3400..0x34c1`. It supports a final key length of 1–192 bytes plus NUL and
leaves the complete `0x3e40..0x3f00` arena/context pool untouched.

## Exact-speed result

The passing run in `read_only_auth_literal16k_results.json` used
`vm-net-ne2k8`, ROM BASIC entry, 16 KiB RAM, 4.772728 MHz 8088, dynarec off,
and the runner's host-enforced read-only floppy configuration:

```text
AUTH1 PASS t=984 ticks
AUTH2 PASS t=986 ticks
FORGE PASS
COMMIT PASS
RETRY PASS
UNLOCK PASS
READONLY PASS reads=34 bios=34 blocked=1
PASS
RESULT
```

At 18.2065 BIOS ticks per second, the authentication passes are approximately
54.04 and 54.15 seconds. They are deliberately post-Finished and therefore do
not consume the initial 15-second ClientHello-to-client-Finished deadline.

The resident binary contains one `INT 13h` opcode behind a fixed wrapper. The
wrapper accepts only AH=02 single-sector read and AH=00 reset, counts every
executed function at runtime, and rejects other functions before the
interrupt. The guest's AH=03 self-test is the recorded `blocked=1`; the
physical phase path records `bios=34`, matching its 34 successful reads.
Caller registers cannot select the callback, phase key, or destination.
Ticket bytes, reconnect/ESC, and the full arena/context pool remain checked
across both long passes and retryable callback failure.

Build offline:

```sh
python3 tools/crypto-bench/tls13-poc/build_read_only_auth_literal16k.py
```

Audit the frozen exact-speed evidence without starting 86Box:

```sh
python3 \
  tools/crypto-bench/tls13-poc/read_only_auth_literal16k_check.py
```

The offline audit verifies the floor-configuration record, serial milestones
and timings, host read-only evidence, current source hashes, memory and
phase geometry, and the intentionally non-secure claim boundary. It then
rebuilds the manifest, 24-sector phase container, and 160 KiB runner floppy
byte-for-byte. It also checks that the runner exposes, forwards, and enforces
`--floppy-read-only`; it does not launch 86Box.

Repeat the exact-speed run:

```sh
python3 tools/crypto-bench/tls13-poc/build_read_only_auth_literal16k.py \
  --run-16k --profile vm-net-ne2k8 --timeout 240
```

## Claim boundary

This fixture-fed ticket/auth/canary path requires no media writes and proves
the real P-256 arithmetic, phase loads, atomic gate, and canary release in the
exact-speed 86Box floor configuration. It does not prove complete Seed boot or
restart behavior from physically write-protected media, live certificate
capture and parsing, live FO inputs, trusted certificate time, fresh
read-only-boot entropy, or resumed target TLS. `secure_floor_proven` therefore
remains false.
