# Full TLS 1.3 symmetric-path literal-16-KiB timing

This isolated gate executes the product-shaped symmetric overlay on an
original-speed 4.77 MHz 8088 with exactly 16 KiB installed RAM.  ROM BASIC
loads only a four-sector resident scheduler at `1000..17ff`; the active driver
slot remains reserved at `1600..17ff`, and the 12-sector symmetric overlay is
demand-read into K at `1800..35ff`.

The target executes, rather than models:

- import of HELLO's committed SHA-256 transcript handoff at `0d00..0daa`;
- the initial 64-byte fixed-profile handshake schedule;
- arbitrarily cut streaming ChaCha20-Poly1305 open of the 1,925-byte protected
  server flight;
- server and client Finished;
- application and resumption schedules;
- the literal credential-free OpenAI HEAD;
- protected NewSessionTicket open, bounds checking, capture, and PSK derivation;
- a real PSK-DHE binder; and
- a fresh 64-byte resumed schedule, certificate-free resumed flight, client
  Finished, application schedule, and HEAD.

The deterministic Unicorn gate first checks every byte against the TLS oracle,
all 16 public entry return IP/SP contracts, hostile ticket/tag paths, and
malformed/uncommitted transcript handoffs.  The target then verifies compact
checksums of the complete 528-byte security-state span and outbound records,
plus the low packet/ciphertext bands, driver slot, reconnect state, arena, and
stack sentinels.

Run the offline build/gate:

```sh
python3 tools/crypto-bench/tls13-poc/build_tls13_sym_literal16k_timing.py
```

Run the scoped target gate:

```sh
python3 tools/crypto-bench/tls13-poc/build_tls13_sym_literal16k_timing.py \
  --run-16k
```

The BASIC screen remains at `RUN` because results are emitted only through the
captured COM1 stream.  The runner restores the profile config/NVR byte-for-byte
and terminates only the 86Box process it spawned.

## Historical target results

The retained target result in `tls13_sym_literal16k_results.json` was measured
against the previous 6,041-byte symmetric overlay. The current source-derived
overlay is 6,142 bytes and still occupies 12 sectors, but this reconciliation
does not rerun 86Box. The timings below are therefore historical evidence only,
not a current-layout performance claim.

| Target-executed span | BIOS ticks | Seconds |
|---|---:|---:|
| load 12-sector symmetric overlay | 49 | 2.691 |
| import through client Finished | 177 | 9.722 |
| full initial symmetric path through ticket capture | 228 | 12.523 |
| post-client-Finished application/HEAD/NST tail | 51 | 2.801 |
| full same-boot resumed path | 83 | 4.559 |

For historical context, an older pre-import artifact took 221 ticks (12.139
seconds) through client Finished. Because both the overlay and fixture changed
after that measurement, it is not a byte-matched A/B comparison with the
recorded 177-tick result and is not used as a current performance claim.

`compute` in the COM1 output is a measured residual: total BIOS ticks minus
ticks observed inside fixture-sector reads.  It still includes resident copies,
loops, and BIOS-tick quantization, so it is not a cycle-exact primitive figure.

## Not measured by this harness

TCP/IP and NIC transfer, real server latency, ML-KEM KeyGen/candidate work, and
X.509/CertificateVerify authentication are excluded.  HELLO performs the SHA
work incrementally while emitting/receiving the hello; this gate starts with
its committed context already in low RAM.  Any end-to-end deadline estimate
that combines these results with separately measured candidate and overlay
reload figures is a model, not a single target trace.
