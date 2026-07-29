# TLS 1.3 fixed-profile hello overlay

This is an isolated proof against the current product layout, not runtime
integration. It implements the fresh and same-boot-resumed
ClientHello/ServerHello boundary as one flat `cpu 8086` overlay linked at
`0000:1800`. The normal proof does not call a NIC
or alter `SEED.SYS`; the fresh-only build has an optional executable
cached-target connector tested against resident/NIC shims.

Run the deterministic executable gate:

```sh
python3 tools/crypto-bench/tls13-poc/hello_check.py
```

The checker assembles the source, executes it in Unicorn, independently builds
the TLS messages and RFC 8446 binder with Python `hashlib`/`hmac`, cross-checks
the fresh message against the existing integrated oracle, replays both
ClientHellos, mutates hostile ServerHellos, verifies memory sentinels, and
reports an exact byte ledger.

## Fixed wire profile

Both modes offer only:

- `api.openai.com` SNI;
- TLS 1.3 with `TLS_CHACHA20_POLY1305_SHA256`;
- `X25519MLKEM768` (`0x11ec`);
- `ecdsa_secp256r1_sha256`;
- Brotli certificate compression;
- one hybrid key share containing `ek[1184] || 09 || 00[31]`; and
- the existing 14-byte padding extension.

The fresh handshake message is exactly 1,376 bytes. The five-byte TLS record
header makes the iterator's wire stream 1,381 bytes.

Resumption adds `psk_key_exchange_modes = psk_dhe_ke` and one bounded ticket
identity. `pre_shared_key` is the final ClientHello extension. For the maximum
192-byte identity, the handshake message is 1,621 bytes and the record is
1,626 bytes. The binder is:

```text
early_secret = HKDF-Extract(zeros, ticket_psk)
binder_key   = Derive-Secret(early_secret, "res binder", Hash(""))
finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32)
binder       = HMAC(finished_key, Hash(Truncate(ClientHello)))
```

`Truncate(ClientHello)` retains the full encoded handshake and extension
lengths plus the complete identities vector, and omits the binders vector.

The strict resumed ServerHello requires the fixed cipher/version/hybrid share
and `selected_identity = 0`. A fresh ServerHello accepts exactly the two
RFC-legal fixed-profile extension orders observed from the provider:
`supported_versions, key_share` and `key_share, supported_versions`. The
parser hashes the bytes in their actual wire order and maps either order onto
one canonical bounded extraction path. A one-shot HelloRetryRequest, a zero
X25519 coordinate, extra/changed extensions, incorrect lengths, or a
mismatched legacy session ID fails closed.

## Fragment and lifetime ABI

The entry table is embedded in `hello_overlay.asm`:

| Entry | Operation |
|---:|---|
| 0 | begin fresh ClientHello |
| 1 | begin resumed ClientHello |
| 2 | return the next pending fragment in `SI:CX` |
| 3 | acknowledge that the pending fragment was consumed |
| 4 | rewind for an exact whole-message retransmission |
| 5 | begin ServerHello parsing |
| 6 | feed 1–384 ServerHello handshake bytes from `SI:CX` |
| 7 | finish and atomically publish the digest/share |
| 8 | clear the phase-owned state |

Entry 2 keeps returning the same pointer and length until entry 3 acknowledges
it. The first fragment includes the TLS record header; only its handshake bytes
enter the transcript. Rewind emits identical bytes without hashing the
ClientHello twice.

The 438-byte receive frame at `0700..08b6` is the only staging buffer. During
transmit it holds the small dynamic prefix/suffix fragments. The large middle
fragments point directly at KeyGen's `ek` at `08c0`. Server parsing cannot
begin until the caller consumes the final ClientHello fragment, so the parser
cannot replace `ek` with `c` too early.

The receive entry consumes ServerHello handshake bytes after the resident TLS
record layer checks and removes the five-byte record header. On success:

```text
08c0..0cff  raw ML-KEM c[1088]
0d00..0d1f  server X25519 public coordinate[32]
0d20..0d3f  SHA256(ClientHello || ServerHello)[32]
0d40..0da9  committed live SHA-256 context (`T13C`, v1)
0daa         committed status = 1
```

The context carries block length, 32-bit byte length, 32 chaining-state bytes,
and the full 64-byte partial block. Its checker compares the exported midstate
byte-for-byte with an independent Python SHA-256 compression oracle. The
symmetric overlay can therefore continue the transcript without replaying the
2,586-byte fresh CH||SH prefix. The raw ciphertext is quarantined: a late
parser failure may leave a partial `c`, but status remains zero and the
handoff is not committed. Integration must close and discard that attempt.

## Measured shape

The current generic fresh/resumed image is 4,132 bytes and ends at the
exclusive address `0x2824`.

| Item | Bytes |
|---|---:|
| code + immutable constants | 4,132 |
| sector-rounded image | 4,608 (9 sectors) |
| mutable state at `3000..313c` | 317 |
| bounded ticket identity at `3200..32bf` | 192 |
| SHA-256/HMAC work at `32c0..35b7` | 760 |
| exact non-overlapping K occupancy | 5,401 |
| free bytes in `1800..35ff` | 2,279 |
| routine stack high-water, including return word | 52 |

The split KeyGen private state at `3600..3b9b`, reconnect/ESC state, executable
arena, context window, and stack guard remain unchanged.

The mutable state is deliberately not adjacent to the code. With the
12-sector symmetric overlay preloaded before the SYN, the generic
fresh/resumed HELLO replaces its first nine sectors. HELLO state, ticket, and
SHA/HMAC work occupy only the symmetric overlay's later mutable-work
addresses. The generic restore therefore reloads nine prefix sectors while the
surviving symmetric static tail at `2a00..2fff` remains intact.

`HELLO_FRESH_ONLY` removes first-flight binder/resumption construction and is
3,326 bytes (7 sectors), leaving 770 bytes in the eight-sector prefix. Adding
`HELLO_CACHED_CONNECT` gives the specialized executable 3,734-byte (8-sector)
first-flight overlay used by the live path, leaving 362 bytes in that same
prefix. Its 408-byte increment includes a cached-target SYN/SYN-ACK/ACK opener
with three exact retransmissions, a 96-byte NIC read cap, and zero-window /
window-update ACK entries. The connector calls only the current resident frame
builder, timer, sequence adder, ACK sender, and active NIC vtable. It
does not load the old `0900..0ed1` connect phase, which would overwrite `ek`.

The executable checker requires every tested success and failure branch of all
nine public entries to return through the exact synthetic return address with
the exact post-`ret` stack pointer.  This gate catches asymmetric pushes/pops in
fragment-only branches that otherwise can leave the emitted wire bytes looking
correct.

## Critical backpressure and delta reload

After the final ServerHello byte, the receiver must acknowledge exactly
through that byte and advertise a zero window. Any protected-flight tail
coalesced in the same TCP segment is deliberately left unacknowledged and may
be discarded. After candidate decapsulation, symmetric-context import, and
key-schedule readiness, drain stale frames and send the ordinary 256-byte
window-update ACK with unchanged sequence numbers. The server then retransmits
from the first protected byte. This bounds receive pressure during the modeled
disk/crypto path. The 3c501 single-buffer case and other receive shapes remain
live regression gates.

This is TCP flow control, not valid TLS dialogue: it does not reset or extend a
server handshake deadline. The CH-to-client-Finished path must still fit the
server's TLS timeout.

`delta_loader.asm` is a 146-byte `cpu 8086` trampoline at `0f00..0f91`
(`0f00..0f92` as a half-open range).
Because it executes below K, it can safely replace the candidate with the
symmetric prefix. It batches contiguous INT 13h reads without crossing a
track, preserves the active driver at `1600..17ff`, and falls back to
single-sector reads after a BIOS rejects a batch. The executable geometry gate
reduces a 9-sector generic reload from nine BIOS calls to at most two, and a
12-sector preload to at most three (two on 18-sector tracks). The specialized
live sibling remains an eight-sector HELLO/restore path. Its harness adds seven
cold padding sectors so its five-sector candidate at absolute LBA 80 and
eight-sector symmetric restore at LBA 88 each take one BIOS call on the
160 KiB image. Its exact-speed pcap runs measure the resulting wire path
directly.

## Hybrid schedule handoff

This overlay does not derive handshake keys. It makes the following exact
64-byte handoff geometry explicit for the symmetric overlay:

```text
ML-KEM candidate K'[32] || server X25519 public coordinate[32]
```

Because the ClientHello advertises the fixed coordinate `u=9`, the received
server coordinate is the fixed-u=9 X25519 component used by the current spike
formula. Fresh and resumed handshakes use the same 64-byte geometry; resumption
changes the early-secret/binder path, not the fresh hybrid key share.

## Still outside this isolated overlay proof

The sibling live deadline harness now covers the first-flight NIC/TCP stream,
KeyGen, provisional candidate, protected-flight processing, and client
Finished transmission. They remain outside this overlay's own executable gate.

- ClientHello TCP-send / ServerHello TLS-record stream integration;
- KeyGen and candidate/full decapsulation (only full FO validation remains
  outside the sibling deadline path);
- encrypted-handshake processing;
- ticket capture/promotion and socket-close recovery;
- persistent or cross-boot ticket safety; and
- a frozen raw OpenSSL resumed ClientHello. The resumed form here is the
  strict RFC-shaped Seed profile with one identity of at most 192 bytes.
