# TLS 1.3 PoC K-window repack gate

This gate answers one narrow architecture question: can every current TLS 1.3
PoC phase run with a logical 14-sector or 13-sector K window without moving the
resident nucleus, selected NIC driver, reconnect state, ESC hook,
arena/context, or stack?

The answer from the current assembled sources is:

- **K14 (`0x1800..0x3400`) is feasible and is the recommended first target.**
- **The current proposed K13 (`0x1800..0x3200`) split is infeasible.** Its
  source-derived symmetric primitive span is `0x3000..0x3238`, crossing the K13
  ceiling by exactly 56 bytes. The corresponding low split still has 51 bytes
  and the slim authentication image has 24 bytes, but neither repairs that
  blocker.

This file began as the original mechanical address-feasibility study and now
records the current-source result. The optional K14 transformation has been
implemented behind
`TLS13_POC_K14`; its executable, write-set, return, sector, delta-restore, and
full-container gates are documented in
[`k14_variant_README.md`](k14_variant_README.md). The feasibility gate below
assembles the default K15 form and independently applies the proposed
relocations to its interval ledger. It allows only the one exact K13 blocker
above; a changed or additional blocker still fails the gate.

## Current assembled inputs

| Phase | Image bytes | Sectors | Current image end |
| --- | ---: | ---: | ---: |
| KeyGen | 2871 | 6 | `0x2337` |
| HELLO | 4132 | 9 | `0x2824` |
| candidate | 2113 | 5 | `0x2041` |
| symmetric | 6142 | 12 | `0x2ffe` |
| FO tail | 2829 | 6 | `0x230d` |
| slim P-256 auth | 6632 | 13 | `0x31e8` |
| entropy ratchet | 2076 | 5 | `0x201c` |

The generated JSON records source/image hashes and the complete probed symbol
snapshot. The table above is explanatory; the Python gate is authoritative.

Without relocation, the exact logical-window overflows are:

| Phase | K14 overflow | K13 overflow |
| --- | ---: | ---: |
| KeyGen | 512 | 1024 |
| HELLO | 440 | 952 |
| candidate | 512 | 1024 |
| symmetric | 69 | 581 |
| FO tail | 512 | 1024 |
| slim auth | 0 | 0 |
| entropy | 0 | 0 |

Those are address blockers, not image-size blockers, except for the tight
auth/symmetric margins described below.

## K14 placement

K14 keeps `0x3400..0x3600` out of every phase's logical K use.

| Phase | Exact move | Remaining limiting margin |
| --- | --- | ---: |
| KeyGen | polynomial `0x3200..0x3400` → `0x3000..0x3200`; accumulator `0x3400..0x3600` → `0x3200..0x3400` | ends exactly at `0x3400` |
| HELLO | state `0x3000..0x313d` → low `0x0dc0..0x0efd`; ticket `0x3200..0x32c0` → `0x3000..0x30c0`; SHA/HMAC `0x32c0..0x35b8` → `0x30c0..0x33b8` | 72 K bytes; 259 low bytes |
| candidate | decoded polynomial `0x3200..0x3400` → `0x3000..0x3200`; accumulator `0x3400..0x3600` → `0x3200..0x3400` | ends exactly at `0x3400` |
| symmetric | keep image `0x1800..0x2ffe` and primitive work `0x3000..0x33f8`; move the 77-byte runtime tail `0x33f8..0x3445` → low `0x0dc0..0x0e0d` | 8 contiguous K-top bytes; 499 low bytes |
| FO tail | keep Keccak `0x3000..0x31e8`; accumulator `0x3400..0x3600` → `0x3200..0x3400` | ends exactly at `0x3400` |
| slim auth | no K move; retain external low work `0x0700..0x0fb6` | 536 K bytes; 74 low bytes |
| entropy | no K move | 5092 K bytes |

This mechanical ledger places HELLO state at `0x0dc0..0x0efd` and the
symmetric tail at `0x0dc0..0x0e0d`. The latter overlaps the beginning of
`0x0e00..0x0fff`, so the ledger alone does not prove a whole-sector protected
flight staging slot. The implemented `TLS13_POC_K14` variant instead places
the cold symmetric controller at `0x3400..0x34c5` and its runtime tail at
`0x3510..0x355d`, leaving the complete low sector available; see
`k14_variant_README.md`. The current default HELLO source is nine sectors;
phase-specific eight-sector live restore contracts are separate from this
default-source mechanical ledger. Symmetric work begins at the rounded image
end `0x3000`.

## K13 placement

K13 uses the same low HELLO state, then moves the shared polynomial pair down
another sector:

- decoded polynomial/ticket sector: `0x2e00..0x3000`;
- accumulator: `0x3000..0x3200`;
- HELLO ticket: `0x2e00..0x2ec0`;
- HELLO SHA/HMAC: `0x2ec0..0x31b8`;
- FO Keccak: `0x2e00..0x2fe8`;
- FO accumulator: `0x3000..0x3200`.

The prior symmetric split no longer fits. The image now ends at `0x2ffe`; the
primitive portion that must remain in K is `0x3000..0x3238`, ending 56 bytes
past `0x3200`. Moving the block beginning at
`hmac_prepared_inner_state` from `0x3238..0x3445` to `0x0dc0..0x0fcd`
still leaves 51 bytes below the resident nucleus, but does not remove the
K-space overflow. The auth image ends at `0x31e8`, leaving 24 bytes.

K13 also loses the exact K14 delta-restore shape: HELLO ticket/SHA and the
candidate use symmetric sector 11 (`0x2e00..0x3000`), so that sector must be
restored in addition to HELLO's immutable sectors 0–7.

K13 therefore needs at least 56 more bytes of symmetric code/work relocation or
shrinkage, followed by a new linked split. It remains a useful optimization
target, but this proposed placement is not address-feasible.

## Hard limits and scope

- The current 13-sector auth image depends on P-256 mutable work remaining
  external in offline low scratch. Re-embedding that work can block both
  smaller windows.
- The low symmetric split must remain after the HELLO handoff and raw
  ciphertext. It cannot consume the receive frame, `0x08c0..0x0d00`
  ciphertext, or `0x0d00..0x0dab` transcript handoff.
- Retained TLS state remains at `0x3600..0x3c2e`; attempt/reconnect state
  follows above it. This gate does not yet
  reclaim the newly unused K tail for arena/context; that is a later,
  independently checked address migration.
- Sector-rounded loading is reported, but work may begin in zero padding after
  the content end because it is initialized only after the overlay load.
- A passing ledger does not validate rewritten absolute operands, functional
  crypto, stack depth, delta-loader behavior, or live timing.

## Original implementation order (completed through step 6)

1. Keep the current slim auth/external-P-256 gate green.
2. Parameterize the logical K end and polynomial pair; move KeyGen and
   candidate, then rerun their exact-output and write-set checks.
3. Move HELLO state to `0x0dc0`, bind its ticket/SHA addresses to the lowered
   polynomial sector, and verify the current K14 nine-sector delta contract.
4. Move the FO accumulator and rerun valid/invalid/read-failure checks.
5. Split only the symmetric 77-byte runtime tail for K14 into phase-owned
   reclaimed space after its cold controller. Update its header to describe
   the non-contiguous K/phase-owned work, then rerun all entry, transcript, AEAD,
   ticket, and literal-16K timing gates.
6. Link the complete K14 phase chain and rerun the 16 KiB harness before
   changing product arena/context addresses.
7. Treat K13 as a follow-up code-size project. First remove at least the exact
   56-byte symmetric K overflow and create deliberate auth margin, then
   implement the deeper split and extra delta restore.
8. Only after the phase chain is stable should the freed physical address band
   be assigned to a larger executable arena/context layout.

## Run

```sh
python3 tools/crypto-bench/tls13-poc/k_window_repack_gate.py
python3 tools/crypto-bench/tls13-poc/k_window_repack_gate.py \
  --check-recorded
```

Both commands pass only when K14 has no blockers and K13 has exactly the
recorded 56-byte symmetric blocker. Any changed or additional range blocker,
any overlap, or disappearance of the recorded blocker without an intentional
gate update fails closed.

To refresh the auditable snapshot after an intentional source/layout change:

```sh
python3 tools/crypto-bench/tls13-poc/k_window_repack_gate.py \
  --json-out tools/crypto-bench/tls13-poc/k_window_repack_results.json
```
