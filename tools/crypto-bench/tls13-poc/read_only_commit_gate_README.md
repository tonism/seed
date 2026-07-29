# RAM-only route commit and fixed credential gate

This PoC closes the high-memory overlap without making floppy writes part of
the secure path. The symmetric ticket remains in its native slots. The gate
accepts two explicitly separate authenticated issuer publishers:

- durable `WE1!` uses the relocated `0x3400..0x34af` two-pass issuer input and
  remains the general issuer-anchor architecture proof; and
- dated exact-leaf `LP1!` is accepted only from the fixed live-P256 publication
  adapter documented in `auth_p256_publication_adapter_README.md`.

A final cold two-sector gate validates either complete authenticated issuer
handoff and one of three route contracts, retires the old issuer-input band,
and publishes the committed state byte last:

- `1 / LIVE_NO_TICKET` requires all native ticket slots to be zero and may
  unlock;
- `2 / LIVE_TICKET` requires one bounded retained ticket and may unlock; and
- `3 / TICKET_ONLY` requires one bounded retained ticket but cannot unlock
  until a later resumption controller promotes a live route.

`gate_commit` receives `AX=nonzero generation` and `BX=route`. `gate_unlock`
accepts no authority-bearing input. The image embeds the resident credential
callback at `0x1580`, one phase key, and fixed `0x3400` destination. It
contains no indirect call, caller-selected loader, write callback, BIOS
interrupt, or port-I/O instruction.

The gate continues to require the pass-2 profile, generation, and status for
`WE1!`. It skips those obsolete input checks only for a structurally complete
`LP1!` object; LP1's fixed adapter has already rerun strict DER and full P-256
against the immutable leaf before publishing generation, profile, exact leaf,
authenticated digest, checksums, and status-last. A lone old auth status or
lone LP1 status is insufficient. The LP1 checksum is a torn-write detector,
not a MAC against arbitrary RAM-writing code, so fixed phase provenance
remains part of the contract.

The v4 header retains the fixed fourth entry used only by that resident
credential callback and adds a fifth, credential-free
`gate_validate_ticket_only` entry for resumption. Both revalidate the complete
committed bundle: state and inverse, ROG3
magic/inverse, nonzero generation, authenticated issuer handoff and checksum,
route and inverse, route-specific ticket shape, and the checksum binding the
generation, route, and fixed ticket slots. The fourth entry accepts only live
routes; the fifth accepts only `TICKET_ONLY`, performs no non-stack writes, and
cannot reach the credential callback. The callback checks the loaded ROG3
header before calling its fourth entry. Consequently, a known address/key and
a forged copy of the old route/state marker quartet are not enough to read a
credential.

The callback returns carry set when a read or parse cannot complete. On
success it must publish a key length of 1–192 bytes, a checksum over exactly
that many bytes, a trailing NUL, and inverse/status bytes with status written
last. The gate clears both destination and descriptor before every attempt and
validates the publication before writing `UNLOCKED`. Callback failure,
success-without-publication, a partial success, bad length/checksum/NUL, or
zero content clears only credential scratch and preserves the valid committed
route, issuer handoff, and promoted ticket for retry. Corrupt committed state
or failed proof validation still invokes full zeroization.

The control block is `0x3c30..0x3c40`: generation at `0x3c30`, bundle
checksum at `0x3c32`, magic/inverse at `0x3c34..0x3c3c`, route/inverse at
`0x3c3c..0x3c3e`, and state inverse/state at `0x3c3e..0x3c40`. Commit writes
the final state pair last. The six-byte credential-publication descriptor is
`0x3c40..0x3c46`.

The destination phase-reuses `0x3400..0x34c0`, the retired issuer-input band:
192 key bytes plus a trailing NUL end at `0x34c1`, below the `0x3510`
symmetric-work boundary. The issuer input is consumed and cleared before
credential loading, so the lifetimes do not overlap. This also leaves the
entire `0x3e40..0x3f00` 16 KiB arena/context pool untouched. The exact harness
reads the fixture sector into retired low scratch at `0x0700`, then copies its
32-byte test key plus NUL to the fixed destination.

The checker assembles the 8086 image and executes its durable WE1 path under
an exact `0x0000..0x4000` 16 KiB Unicorn RAM ceiling. Its positive path
proves:

- issuer generation, profile, status, and torn-handoff checksums are accepted;
- all three route/ticket contracts and their inverse/checksum binding are
  accepted;
- commit clears the retired issuer input without changing the ticket or
  authenticated issuer handoff;
- the canary remains unloaded until an atomic live-route commit is visible;
- hostile caller AX/BX/DX values cannot change the fixed callback ABI;
- the fixed callback revalidates the complete committed bundle and copies the
  exact phase;
- the old internally consistent route/state marker quartet cannot authorize a
  direct callback;
- a bounded key descriptor, checksum, NUL, inverse, and status-last store are
  required before unlock;
- a deliberately partial callback failure is scrubbed and a second invocation
  succeeds without repeating authentication;
- `TICKET_ONLY` rejects unlock without destroying its valid commit;
- commit and unlock state bytes are the final non-stack stores; and
- all writes stay inside declared state, canary, or stack ranges.

The hostile matrix covers direct callback before commit, the forged old
marker quartet, unlock before commit, generation/profile/status mismatches,
invalid routes, route/ticket mismatches, stale absent-ticket bytes, corrupt
issuer checksum, zero and oversized ticket lengths/lifetime, missing ticket
presence, ticket and route mutation after commit, callback CF failure,
success-without-publication, partial-success/checksum mismatch, missing NUL,
zero/oversized key length, all-zero content, retry, explicit abort, rejection
of both committed live routes through the ticket-only validator, and rejection
of a checksum-corrupted ticket-only bundle without writes or credential reach.
Proof/control rejection avoids a callback and fully zeroizes issuer, ticket,
control, and credential state. Expected `TICKET_ONLY` and
callback/publication rejections preserve the valid commit while clearing
credential scratch. Every case preserves boundary sentinels.

The sibling `auth_p256_publication_adapter_check.py` executes the actual dated
live CertificateVerify vector through P-256, publishes LP1, replaces the auth
phase with this exact gate, and reaches the fixed `0x1580` loader. Keeping that
composition in a separate checker avoids implying that the dated exact-leaf
PoC is the durable WE1 architecture.

Run the gate and refresh its frozen result with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 \
  tools/crypto-bench/tls13-poc/read_only_commit_gate_check.py \
  --json-out \
  tools/crypto-bench/tls13-poc/read_only_commit_gate_results.json
```

This checker is an offline architecture gate. The sibling literal target
harness in `read_only_auth_literal16k.asm` has one checked `INT 13h` wrapper,
runtime-counts every executed AH=00/AH=02 call, and proves an AH=03 self-test is
rejected before the interrupt. It exercises that BIOS path while its generated
image is host mode `0444`; the recorded host write-only open is denied and the
before/after image hash is unchanged. Neither gate exercises a
physical write-protect mechanism, one complete live TLS chain, fresh session
entropy, or trusted time. The route argument is the future proof controller's
trusted output; this gate does not itself observe TCP liveness. The fixed
credential callback is also trusted code in the resident nucleus. Those
boundaries remain required before claiming the 4.77 MHz 8088 secure tier.
