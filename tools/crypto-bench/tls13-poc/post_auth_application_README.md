# TLS 1.3 post-auth application PoC

This isolated PoC answers the application-layer question left after the K14
TLS 1.3 handshake proof: can the 16 KiB path publish an authenticated
credential and model, send a bounded OpenAI Responses request, and accept a
multi-record streamed `ok` without exposing unauthenticated response bytes to
the scanner?

It is not wired into `SEED.SYS`. The shipping builder, phase table, and live
controllers remain unchanged.

## Cold phases

The proof reuses two phase slots:

- `post_auth_request_controller.asm` loads at `0x0900`. It calls one fixed,
  no-argument callback at `0x0520`. Only that callback may publish the fixed
  `PAK1` credential/model object at `0x0d00`; the object carries magic and
  inverse, generation, fixed OpenAI route and inverse, bounded key and model
  fields, two checksums, and a status byte written last.
- The fixed outbound-send callback is at `0x0500`, immediately above the BIOS
  data area.
- The fixed `0x0510` callback restores the eight-sector K14 symmetric phase
  after the authorization gate has occupied `0x1800`; the request accepts no
  caller-selected phase key or destination.
- `post_auth_sym_adapter.asm` loads at `0x3400` for the outbound phase. It
  exposes only client application-data sealing and immutable request literals.
- `post_auth_response_controller.asm` then replaces the request controller at
  `0x0900`.
- `post_auth_response_literals.asm` replaces the request adapter at `0x3400`
  with two bounded helpers and immutable HTTP/SSE tokens. It ends before K14
  runtime state at `0x3510`.

The request is emitted as TLSInnerPlaintext fragments no larger than 224 bytes
(below the 383-byte application-data bound), then all key, model, decimal, and
fragment plaintext is scrubbed.

The credentialed-live composition uses the controller's
`POST_AUTH_PRELOADED_PUBLICATION` variant. Its supervisor first installs a
63-byte callback page at `0x0500`, loads and executes UCL1 at `0x0900`, and
receives status-last `PAK1` at `0x0d00`. It then installs the 76-byte request
callback page and request controller without touching `PAK1`. The fixed
`0x0520` request callback revalidates the full ROG4 route and requires the
PAK1 generation to equal the gate generation before normal descriptor
validation. Both callback pages stop before `0x0600`, preserving the live
handoff and NIC/TCP state through `0x08b6`.

## Authenticated receive rule

Each server record is decrypted in place into the existing three-span
quarantine:

```text
0x0d00..0x0f00  512 bytes
0x3600..0x3838  568 bytes
0x3920..0x3b40  544 bytes
```

The HTTP/SSE finite-state scanner is not called until the actual K14
ChaCha20-Poly1305 finish operation verifies the complete record tag. Its small
state at `0x3c4a..0x3c62` survives authenticated TLS record seams. It requires
a 2xx response, aggregates output-text delta values to exactly the two bytes
`ok` (either one delta or `o` then `k`), rejects a wrong or third output byte,
then requires a later `response.completed` type, and finally requires the exact
authenticated HTTP terminal chunk `0\r\n\r\n`. Normal SSE `event:` lines,
pretty JSON whitespace, TLS padding, and marker splits at arbitrary TLS record
seams are harmless. Bytes after the terminal chunk fail closed.

Any record/tag/protocol rejection revokes request success, clears scanner
state, clears all quarantine spans, and makes the response stream terminal.

## Offline gate

Run:

```sh
python3 tools/crypto-bench/tls13-poc/post_auth_application_check.py
```

The checker assembles all four cpu-8086 phases plus the actual K14 symmetric
image and executes them under Unicorn. It decrypts the outbound records with
the host oracle and requires a byte-exact minimal OpenAI request. Its response
fixture uses HTTP chunking, realistic SSE lines, seven authenticated TLS
records, a 1,539-byte record spanning all quarantine regions, seams inside both
output delta events and the completion type, and a separately authenticated
terminal chunk.

Hostile cases cover pre-commit and partial publications, callback failure,
key/model bounds and termination, route/checksum corruption, send failure,
tag failure after a previously authenticated partial marker, non-2xx status,
wrong/orphan/cross-object/extra output, whitespace inside the output value,
missing completion, missing or trailing bytes after the HTTP terminator, and an
oversized record. The result report contains no credential value.

The companion
[`post_auth_user_cfg_loader_README.md`](post_auth_user_cfg_loader_README.md)
proves a fixed, read-only FAT12 USER.CFG callback at `0x0520` and executes it
end to end through this request controller; it also executes the relocated
live UCL1 body at `0x0900`.
