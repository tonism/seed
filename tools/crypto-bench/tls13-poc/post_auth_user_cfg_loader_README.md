# TLS 1.3 post-auth read-only USER.CFG loader PoC

This isolated callback closes the credential bridge between the authenticated
TLS 1.3 commit gate and the post-auth OpenAI request controller. It is a
read-only, fixed-layout proof for a builder-resolved `SEED/USER.CFG`; it is not
wired into the shipping `SEED.SYS` and does not change the shipping
configuration loader. The isolated credentialed-live sibling composition uses
the same source through the relocated live contract below.

The proof never opens the developer's local configuration. Its checker creates
temporary synthetic files, passes them through the real FAT12 image builder,
then independently resolves the resulting directory entry, FAT chain, LBA, and
CHS before assembling the callback.

## Fixed authority and disk contract

The standalone callback entry is fixed at `0x0520` and accepts no arguments.
The live composition keeps `0x0520` as a 63-byte immutable trampoline and
cold-loads the 807-byte body at `0x0900` only after the resumption controller
has retired. This keeps every disk sector load below the live handoff/NIC/TCP
range at `0x0600..0x08b6`; the request controller replaces the loader at
`0x0900` after it returns.

Before any disk access the loader calls the compile-time full-authorize gate
entry
with `AX`, `BX`, `CX`, `DX`, `SI`, and `DI` all zero. Its only `INT 13h`
instruction sits behind one checked wrapper. That wrapper repeats full
authorization immediately before each operation, permits only:

- `AH=02`, `AL=1`: one-sector read from the builder-resolved USER.CFG CHS into
  `0x0e00`; or
- `AH=00`: one bounded reset between a failed read and one retry.

The wrapper reconstructs the drive, CHS, count, and destination itself. Caller
registers cannot select a phase, route, disk location, or destination. Runtime
counters at `0x3c62..0x3c6b` make every authorization, accepted read/reset,
and denied operation observable to the offline gate.

The compiled descriptor rejects zero-length, over-512-byte, and multi-cluster
files before disk I/O. This is deliberately narrower than the product's
mutable configuration path: it proves that a read-only boot image can recover
its own credential without writable media or a second machine.

## Parsing and publication

Only `model ` and `key ` values are copied into bounded temporary fields at
`0x1c00..0x1d06`, immediately above the live ROG4 phase in retired HELLO
space. This preserves the durable issuer object at `0x3600..0x3672`, which
ROG4 must validate again at the request boundary. An optional `agent ` line is
accepted only when its value is
exactly `openai`; other visible newline-terminated settings are ignored.
Duplicate, empty, overlength, unterminated, control-containing, or malformed
recognized lines fail closed. Model bytes are restricted to the safe token
alphabet used by the request builder. Key bytes must be visible ASCII, which
excludes header-breaking CR/LF.

After a successful parse, the callback scrubs the raw 512-byte sector and
publishes the fixed `PAK1` object at `0x0d00..0x0e18`. That object contains a
nonzero authenticated generation, fixed OpenAI application route, bounded
key/model fields, inverse fields, and two checksums. The status byte at
`0x0d00` is written last. The first 24 bytes of the retired raw-sector address
are then occupied by this publication; the remainder of the sector and all
temporary fields are zero. Every failure clears the entire raw sector,
temporary fields, parser state, and partial publication.

The standalone 807-byte callback occupies `0x0520..0x0846`. Its live variant
occupies `0x0900..0x0c26` inside a fixed two-sector phase and is retired before
the request is loaded at the same address. The live request callback page is
76 bytes: send remains at `0x0500`, symmetric restore at `0x0510`, and
authorization at `0x0520`; nothing crosses `0x0600`.

## Offline gate

Run:

```sh
python3 tools/crypto-bench/tls13-poc/post_auth_user_cfg_loader_check.py
```

The checker executes the actual cpu-8086 callback under Unicorn at both the
standalone `0x0520` and live `0x0900` origins. Positive
fixtures cover LF/CRLF, optional agent, line reordering, maximum field sizes,
an exact 512-byte file, and a failed-read/reset/retry sequence. Hostile fixtures
cover authorization failures, wrong or duplicate agents/fields, missing and
overlength values, missing final newline, control bytes, invalid file layout,
permanent disk failure, and a direct unsupported wrapper request.

The final gate installs the callback at the real request controller's fixed
unlock entry, reads the synthetic FAT12 sector, publishes `PAK1`, seals the
byte-exact OpenAI request through K14 ChaCha20-Poly1305, and verifies that no
credential remains in RAM after send.
