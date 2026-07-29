# 8086 attempt-seed ratchet overlay PoC

This is an isolated architecture spike for making each ML-KEM key-generation
attempt self-contained on the target machine. It is not wired into
`SEED.SYS`, the loader, FAT12, or BIOS disk I/O.

The PoC implements and executes an 8086 phase overlay that is byte-compatible
with the existing host crash oracle in
`../tls13-spike/entropy_ratchet_oracle.py`. Its purpose is narrower than a
random-number generator: advance a persistent attempt state before making
ML-KEM `d || z` available, so a reset does not deterministically reuse an
attempt when the latest valid floppy state is preserved.

## Contract

The caller preloads two dedicated 512-byte sectors and invokes the overlay:

1. Parse both records and select the newest unambiguous valid generation.
2. Append up to 96 bytes collected on the target.
3. Derive the next state and a private 32-byte attempt root.
4. Return a complete 512-byte record and the alternate slot number.
5. The caller writes that slot and reads the physical sector back into the
   readback buffer.
6. Verify exact record/readback equality, the record digest, generation, and
   state.
7. Only after step 6, derive and expose independently domain-separated
   32-byte `d` and 32-byte `z`.

Before verified readback, the public `get_dz` entry fails and its 64-byte
output area remains zero. `abort` also zeros the pending attempt root and
`d || z`. The disk write itself is intentionally outside this overlay; an
in-memory copy into the readback buffer is not evidence of durability unless
the caller actually performed the write and physical readback.

Each record has this checked host format:

| Offset | Bytes | Meaning |
| ---: | ---: | --- |
| 0 | 8 | `SEEDRT13` |
| 8 | 4 | version 1 plus reserved zeros when emitted |
| 12 | 8 | little-endian generation |
| 20 | 32 | ratchet state |
| 52 | 428 | zero padding when emitted |
| 480 | 32 | SHA3-256 of domain string plus the 480-byte body |

The digest detects corruption but is not a MAC. Anyone able to modify the
floppy can create a different valid record and digest.

## Target timing collector

The separate collector entry appends a 12-byte, nonblocking snapshot:

- a latched PIT channel 0 count;
- the four-byte BIOS tick count;
- BIOS keyboard-ring head and tail;
- a nonconsuming peek at the queued key word when the head pointer is sane.

The checker gives this **zero credited entropy bits**. It establishes the
collector ABI and byte flow only. Real-machine measurement is still needed to
estimate timing independence, attacker influence, cold-boot behavior, and
whether more event samples are required.

## Deterministic coherent-chain mode

`build_poc_harness.py` assembles its byte-exact end-to-end oracle with
`POC_DETERMINISTIC_COHERENT_CHAIN`. In that mode the harness deliberately
skips PIT/BDA collector mixing so the generated downstream KeyGen, HELLO, and
protected-flight fixtures remain reproducible. It still executes
prepare → BIOS sector write → BIOS reset/flush → physical reread → exact
verification, and releases `d || z` only after that durable-record check.

This mode is a **durability and phase-integration test, not secure entropy**.
It establishes no physical min-entropy and must not be used as evidence that a
4.77 MHz machine has gathered unpredictable input. The separate
`entropy_ratchet_check.py` gate continues to exercise the collector ABI and the
ratchet/crash model, while retaining zero credited entropy bits.

## Literal 16 KiB geometry

All addresses are physical real-mode offsets below `0x4000`:

| Use | Half-open range | Bytes |
| --- | --- | ---: |
| Slot 0 input | `0x0700..0x0900` | 512 |
| Slot 1 input | `0x0900..0x0b00` | 512 |
| Supplemental bytes | `0x0b00..0x0b60` | 96 |
| Collector sample | `0x0b80..0x0b8c` | 12 |
| Pending write record | `0x0c00..0x0e00` | 512 |
| Physical readback | `0x0e00..0x1000` | 512 |
| Overlay image | `0x1800..0x201c` | 2,076 |
| Persistent/transient high work | `0x3600..0x394c` | 844 |
| Published `d || z` within high work | `0x3660..0x36a0` | 64 |
| Stack top used by checker | below `0x3ff0` | — |

The image rounds to five 512-byte sectors and is well inside the
`0x1800..0x3600` 15-sector phase window. High work includes the 200-byte
Keccak state and scratch. It ends 848 bytes below `0x3c9c`, the current
high-security-state ceiling used by the other TLS 1.3 PoCs.

This proves address fit, not coexistence with a final integrated 16 KiB
schedule. The literal harness still has to sequence disk buffers, NIC receive
memory, ML-KEM overlays, TLS state, and the BASIC-entry loader without making
simultaneously-live ranges overlap.

## Executed regression gate

Run:

```sh
python3 tools/crypto-bench/tls13-poc/entropy_ratchet_check.py
```

The Unicorn gate assembles and executes the target binary and checks:

- exact record and derivation parity with the existing host oracle;
- all 513 possible prefix-write outcomes (0 through 512 bytes);
- all 512 incomplete readback prefixes keep `d || z` inaccessible;
- the three modeled post-write crash/emission boundaries;
- all 512 single-byte record corruptions are rejected;
- equal-generation/different-state ambiguity is rejected;
- equal-generation/identical-state tie-breaking matches the host;
- 128 successful target attempts with identical supplemental bytes do not
  repeat `d || z`;
- the existing host oracle independently retains its 4,096-attempt sequence;
- copied media plus identical supplemental input deterministically repeats the
  same record and `d || z`, documenting rather than hiding the rollback limit.

The shorter 128-attempt target sequence keeps the full assembly gate near
interactive test time; the target count can be raised with
`--target-identical-attempts`.

## Exact power-loss claim

Under the oracle's model—one old valid slot and an alternate-sector write that
leaves any prefix of the new 512-byte sector—a reboot chooses either the old
valid generation or the fully written new generation. It never treats an
incomplete prefix as committed. If the complete sector landed but the machine
reset before exposing or using `d || z`, the next boot advances from that new
generation, intentionally abandoning the unobserved attempt root. Thus the
same deterministic attempt is not released twice.

This claim does **not** cover arbitrary analog/multi-sector failure patterns,
controller write caching, remapped sectors, actively forged records, copied or
rolled-back media, or write-protected media. It also does not prove that the
timing collector contributes entropy.

## Integration questions left open

- Which two physical sectors can be permanently reserved without violating
  the current FAT12/loader contract?
- What exact INT 13h write, reset/flush, and reread sequence is reliable on
  the supported original floppy controllers and media?
- Read-only boot is mandatory. The automatic candidate now performs 256
  alternating read-only floppy operations and PIT measurements before
  networking; what conservative physical-drive min-entropy estimate and
  calibrated health gates make that source creditable when the medium cannot
  advance?
- How are failed writes surfaced without accidentally releasing the pending
  attempt or blocking a read-only boot whose local entropy fallback passes?
- Does real 4.77 MHz hardware collect enough independent event timing before
  the first secure attempt, and what conservative entropy estimate is
  defensible?
- Is rollback resistance a product requirement? Two unauthenticated floppy
  slots alone cannot supply it; solving it requires non-rollbackable state or
  genuinely fresh target-side entropy.
