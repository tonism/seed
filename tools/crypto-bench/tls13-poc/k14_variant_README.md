# Optional TLS 1.3 PoC K14 phase layout

`TLS13_POC_K14` is an opt-in implementation of the mechanically checked
14-sector logical K layout. It does not change the default K15 PoC or the
current product runtime. The variant keeps the resident nucleus, selected NIC
driver, high security state, reconnect state, ESC hook, product arena/context,
and stack at their existing addresses.

The one physically reclaimed sector is:

```text
3400..3600  phase-owned executable/staging space (512 bytes)
```

High security state still begins at `0x3600`. This space is reused by whichever
phase owns it; it is not user arena, is not reconnect-safe persistent storage,
and is not contiguous with the product arena/context at `0x3e40..0x3f00`.
The gate therefore does not count it as arena or context growth.

## Exact phase placement

| Phase | K14 placement | Image |
| --- | --- | ---: |
| KeyGen | polys `3000..3200`, `3200..3400` | 2871 B / 6 sectors |
| HELLO | low state `0dc0..0efd`, ticket `3000..30c0`, SHA/HMAC `30c0..33b8` | 4132 B / 9 sectors |
| candidate | polys `3000..3200`, `3200..3400` | 2113 B / 5 sectors |
| symmetric | K work `3000..33f8`, controller `3400..34c5`, runtime tail `3510..355d` | 6142 B / 12 sectors |
| FO tail | Keccak `3000..31e8`, accumulator `3200..3400` | 2829 B / 6 sectors |
| exact leaf auth | external low work, image through `31e8` | 6632 B / 13 sectors |
| issuer auth | external low work, image through `33de` | 7134 B / 14 sectors |
| entropy ratchet | unchanged | 2076 B / 5 sectors |

HELLO now occupies nine rounded sectors while its mutable state remains low, so
a preloaded twelve-sector symmetric phase needs a nine-sector delta restore.
The still-live preloaded suffix is `0x2a00..0x2fff`. The protected-flight
controller and its 77-byte mutable tail use the reclaimed space only while that
phase owns it. This leaves `0e00..0fff` available as a whole-sector disk staging
buffer while preserving the candidate handoff at `0700` and the raw ML-KEM
ciphertext at `08c0`.

ServerHello fixture reads use `3400..35ff` before the symmetric controller is
installed. The offline gate models full 512-byte BIOS writes—not only the
384-byte network payload—and proves the three phase-specific staging sectors
do not overlap simultaneously live ciphertext, accumulator, candidate, or
high-security state.

## Gates

Run the complete offline K14 gate:

```sh
python3 tools/crypto-bench/tls13-poc/k14_variant_check.py \
  --json-out tools/crypto-bench/tls13-poc/k14_variant_results.json
```

It executes the exact crypto oracles, hostile-input cases, return/stack
contracts, write-set and protected-band sentinels, sector and interval gates,
builds a full four-sector-resident K14 phase container, then rebuilds the
default K15 container. It never launches 86Box.

Build only the offline phase container:

```sh
python3 tools/crypto-bench/tls13-poc/build_poc_harness.py --k14
```

The retained K14 artifact is
`build/crypto-bench/tls13-poc/poc_harness_k14.bin`. The optional
`--run-16k` path propagates `TLS13_POC_K14` to the child assembler. The
historical literal-machine result in
`phase_chain_literal16k_k14_results.json`: exactly 16 KiB, 4.772728-MHz 8088,
dynarec disabled, `CF t=225`, and terminal `PASS` then `RESULT`.
That timing predates the current 4,132-byte/nine-sector HELLO and 6,142-byte
symmetric overlay, so it is retained as historical evidence rather than a
current-layout timing claim. This reconciliation does not rerun 86Box.

The current source-derived offline result is fixture-fed. Its candidate handoff
at `0700..077f` deliberately
uses the otherwise idle NIC receive frame, and after symmetric initialization
the runtime tail at `3510..355c` makes any later whole-sector controller copy
to `3400..35ff` invalid. The sibling live deadline harness resolves those
blockers with a different lifetime schedule: temporary `K′` at `08c0`, the
final controller at `0900..0cff`, an embedded loader copied low before
`sym_init`, and zero later writes to the reclaimed phase space. That schedule has repeated
exact-speed NE.DRV wire passes; the current K14 gate remains an offline
full-chain proof.

Individual functional gates select K14 through the environment:

```sh
TLS13_POC_K14=1 python3 tools/crypto-bench/tls13-poc/check_keygen_overlay.py
TLS13_POC_K14=1 python3 tools/crypto-bench/tls13-poc/mlkem_candidate_check.py
TLS13_POC_K14=1 python3 tools/crypto-bench/tls13-poc/hello_check.py
TLS13_POC_K14=1 python3 tools/crypto-bench/tls13-poc/check_tls13_sym_overlay.py
TLS13_POC_K14=1 python3 tools/crypto-bench/tls13-poc/fo_tail_check.py
```

This checkpoint proves the phase implementation and safe, ordered reuse of the
512-byte phase-owned space. It does not prove that space can hold user arena,
reconnect state, or data that survives a phase transition. Moving high state
to enlarge contiguous arena/context remains separate work.
