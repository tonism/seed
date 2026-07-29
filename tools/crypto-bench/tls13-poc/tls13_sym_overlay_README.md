# TLS 1.3 symmetric product-shape PoC

This artifact is an isolated proof against the current product layout, not
runtime integration. It turns the checked TLS 1.3 spike primitives into one
`cpu 8086` flat overlay linked for the current K window at `0000:1800`.

The overlay implements the complete symmetric provisional and resumed paths:

- import of HELLO's committed 171-byte low-memory handoff, including the server
  X25519 share, `ClientHello || ServerHello` digest, and resumable SHA-256
  state/block/byte length; this removes transcript replay after the candidate;
- no-PSK SHA-256 handshake schedule from the live fixed-u=9 profile's external
  64-byte `ML-KEM K' || server X25519 public` string and
  `ClientHello..ServerHello` digest (with a checked compile-time 32-byte
  compatibility variant);
- incremental ChaCha20-Poly1305 record open across arbitrary chunks of at most
  the product's 384-byte MSS, with plaintext transcript hashing;
- server Finished verification;
- client Finished construction, encryption, and transcript update;
- application and resumption-master secret derivation;
- one compiled, credential-free OpenAI `HEAD /v1/models` record; and
- strict capture of one NewSessionTicket with a 192-byte identity ceiling,
  a 32-byte nonce ceiling, a seven-day lifetime ceiling, and PSK derivation;
  its extension vector must be empty, contain exactly `early_data`, or contain
  `early_data` followed by one well-formed zero-length unknown extension;
- RFC 8446 `res binder` / Finished-key binder generation over
  `ClientHelloTruncated`; and
- PSK-DHE resumption with a fresh 64-byte hybrid Extract and the observed
  certificate-free EncryptedExtensions/Finished flight.

The entry table and fixed writable-address manifest are described at the top of
`tls13_sym_overlay.asm`.  Decrypted chunks remain quarantined until the final
record-tag call succeeds.  Any tag failure invalidates the provisional
transcript; the integration contract is close-and-discard, never rollback and
continue. Record open and seal also reject an exhausted all-ones sequence
without wrapping it to zero.

Run the deterministic gate:

```sh
TLS13_POC_K14=1 \
  python3 tools/crypto-bench/tls13-poc/check_tls13_sym_overlay.py
```

The gate assembles the overlay from source, loads it at `0x1800` in Unicorn,
and drives the integrated spike's exact ClientHello, ServerHello, protected
flight, and NewSessionTicket geometry.  Its first-handshake keys and Finished
match the integrated oracle's live-profile 64-byte combiner exactly.  The gate
then constructs a realistic 1,621-byte PSK-DHE ClientHello (PSK extension last),
checks its binder, adds selected_identity to ServerHello, and completes a fresh
certificate-free resumed handshake.  It checks every derived key against the
Python TLS oracle, deliberately cuts ciphertext at non-ChaCha-aligned
boundaries, compares encrypted outbound records, and rejects bad tags and
hostile ticket bounds, duplicate `early_data`, and record-sequence exhaustion.
Every public call also has its exact return IP and post-`RET` SP checked,
including rejection paths.  Malformed, inconsistent, or uncommitted HELLO
contexts are rejected before import.

Current measured shape:

| Item | Bytes |
|---|---:|
| overlay code + immutable constants | 6,142 |
| rounded floppy sectors | 12 |
| logical K14 window | 7,168 |
| static tail before K14 limit | 1,026 |
| mutable K work (`3000..33f8`) | 1,016 |
| genuinely free K14 tail after work | 8 |
| fixed high state/IO span (`3600..3c2e`) | 1,582 |
| remaining bytes before arena floor `3e40` | 530 |

The high span includes the 405-byte record IO slot and the 192-byte ticket
identity slot; it is not all simultaneously live secret material.
The separate `0x3400..0x3600` reclaimed sector remains phase-owned: its
controller and 77-byte runtime tail are neither user arena nor reconnect-safe
persistent storage.

The literal 16 KiB / 4.77 MHz target gate is documented in
`tls13_sym_literal16k_README.md`. Its 177-BIOS-tick / 9.722-second
client-Finished result belongs to the previous 6,041-byte overlay and is
retained only as historical timing. The current 6,142-byte K14 overlay passes
the source-derived Unicorn and layout gates but has not been rerun for literal
target timing.

## Integration gate still open

This proves code size, memory coexistence, and byte-exact symmetric behavior,
but deliberately does not alter `SEED.SYS`, its loader, the NIC drivers, or the
TLS 1.2 path.  Mutable SHA/HMAC/AEAD work now lives entirely after static code
inside logical K14 at `0x3000..0x33f8`. Sentinel gates prove it does not touch
either `0700..08b6` (the live receive frame) or `08c0..0cff` (the retained
1,088-byte ML-KEM ciphertext), and that phase-owned writes remain ordered.

Runtime integration still has to route live network chunks through this entry
ABI and bind the symmetric result to the deferred KEM and identity proof gates.
The isolated HELLO PoC now exports the same fixed low-memory context ABI, but
the product runtime does not yet load these overlays.  The checker reports
`runtime_integration: false` so this artifact cannot be mistaken for a boot
gate.
