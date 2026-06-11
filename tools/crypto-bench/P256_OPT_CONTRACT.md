# P-256 ECDHE optimization — feasibility testbench contract

GOAL (testbench only — NOT shipped code): make the real P-256 scalar multiply
fast enough that a secure handshake fits ~15 s on a **286 @ 6 MHz**. Baseline
286@6 ECDHE ≈ 24 s; we need ~1.8–2× on the scalar mult. Nothing here touches
Seed's `core/p256.inc`; we are verifying whether the idea is worth building.

## What a variant is
A drop-in replacement for `tools/crypto-bench/p256_real.inc` (the dormant real
P-256, brought to life + OpenSSL-verified). Copy it, optimize ONE thing, keep
every entry point + the data-symbol contract (the harness defines the buffers).
8086 instructions only (`cpu 8086`) — the 286 runs the SAME code faster; we are
NOT using 286-only instructions (they don't help crypto; see FINDINGS).

## How to evaluate (REQUIRED — real numbers)
```
cd tools/crypto-bench
python3 p256_eval.py variants/<yourfile>.inc            # fast gate: field-mul + point-double correct, field-mul cycles
python3 p256_eval.py variants/<yourfile>.inc --full     # also runs the full scalar mult == PEER_PUBLIC (slow, ~30-60s)
```
Returns `ok`, `field_mul_cycles`, `field_mul_speedup` (vs baseline), and with
--full `scalar_instrs` + `scalar_instr_ratio`. A variant must be `ok` (correct vs
the OpenSSL oracle) before its speed counts. Field-mul variants: use the fast
gate (if the field mul + point-double are exact, the scalar mult is too).
Scalar-structure variants (windowing): use --full.

## Where the time goes (baseline, measured)
- One scalar mult = ~3732 field multiplies (255 doubles × 8 + 141 set-bits × 12).
- One field multiply (`p256_mul_mod`) = 137,589 cyc = schoolbook multiply
  (`p256_mul_product`, ~67%) + reduction (`p256_reduce_product`, ~33%).
- **On the 286 the `MUL` opcode is ~6× faster than the 8088**, so the *overhead*
  (memory traffic, the reduction loop) dominates — that's what to cut.

## The three high-value optimizations (one per agent)
1. **Solinas reduction** — replace the generic table-driven `p256_reduce_product`
   (`p256_reduce_coeffs` + per-coeff loop) with the **direct NIST P-256 fast
   reduction**: the special form of p lets you reduce a 512-bit product with ~8–9
   additions/subtractions of word-aligned 32-bit limbs (the FIPS 186 P-256
   reduction: s1 + 2·s2 + 2·s3 + s4 + s5 − s6 − s7 − s8 − s9, specific limb
   arrangements) + a final few conditional subtracts. No table, no coeff loop.
   Biggest single lever. Verify the field mul stays exact vs the oracle.
2. **Register-resident Comba multiply** — `p256_mul_product` already accumulates
   column-wise but keeps the 3 accumulators in MEMORY (`add [p256_mul_acc0],ax;
   adc [mul_acc1],dx; adc [mul_acc2],0` every inner step). Keep acc0/acc1/acc2 in
   REGISTERS across the inner loop; minimize the per-step memory traffic + index
   recompute. (Like the SHA track's register-residency win.)
3. **Windowed / wNAF scalar mult** — `p256_scalar_mult_mixed` is plain
   double-and-add (~141 point-adds). A 4-bit fixed window or wNAF cuts the adds
   to ~64 / ~51 (precompute a small table of odd multiples). Fewer field muls.
   Verify with --full (scalar_instr_ratio should rise).

## Output you must return (structured)
`name`, `technique`, `ok`, `field_mul_cycles`, `field_mul_speedup`,
`scalar_instr_ratio` (if --full), `bytes`, `error`, `notes`. Be honest — a
correct 1.3× beats a broken "3×". The winner gets measured on a real 286@6 in 86Box.
