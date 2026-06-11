# SHA-256 variant contract (speed-track evolutionary search)

You are optimizing Seed's SHA-256 for the **4.77 MHz Intel 8088**. SHA-256 is the
hot core of the TLS-PRF that dominates the handshake (~4.9 s of always-runs
symmetric crypto). Faster SHA-256 → faster handshake → more margin under
Cloudflare's ~15 s patience window.

## What a variant is
A drop-in replacement for `core/sha256.inc`. It is `%include`d in place of the
original, so it MUST define every symbol the rest of the code calls:

- `sha256_init`, `sha256_update`, `sha256_finish`
- `sha256_process_block`            ← the hot loop; this is what you optimize
- `sha256_save_context`, `sha256_restore_context`
- `hmac_prepare_current_key_context`, `hmac_sha256_prepared`
  (plus their helpers `hmac_load_prepared_inner` / `hmac_load_prepared_outer`)

It operates on the SAME state addresses from `core/data.inc` (do not change the
layout): `sha256_state` (8×32-bit, the canonical hash state), `sha256_block`
(64-byte input), `sha256_w` (message schedule, 64×32-bit), `sha256_a..h`,
`sha256_t1/t2/tmp`, `sha256_k` (round constants), etc. You MAY change how
`process_block` uses scratch internally, and you MAY rewrite/replace the
sigma/rotate helpers, as long as the externally-visible result is identical.

## Hard constraints
- **8086 instructions ONLY** (the assembler enforces `cpu 8086`). No `shl r,imm`,
  no `movzx`, no 32-bit registers, no `push imm`. If nasm errors, your variant is
  rejected.
- Output must be **bit-exact** SHA-256 (the evaluator checks vs OpenSSL/hashlib
  AND runs the full TLS-PRF vectors through your code).
- Smaller cycles win. Keep an eye on size (the real nucleus is byte-tight) but
  the search ranks on cycles first; report your variant's byte size.

## How to evaluate (REQUIRED — report real numbers, never guess)
```
cd tools/crypto-bench
python3 evaluate.py variants/<yourfile>.inc --json
```
Returns JSON: `ok_sha`, `ok_prf` (both must be true), `block_cycles`,
`block_speedup` and `prf_speedup` (vs the frozen ORIGINAL baseline), `error`.
The cycle model is calibrated ~99% to real 86Box hardware.

## The baseline and where the time goes (original `core/sha256.inc`)
- ~735,000 cycles/block (~154 ms). The full PRF ~23.2 M cycles (~4.86 s).
- The original `sha256_rotr32`/`sha256_shr32` rotate **one bit per loop
  iteration** (rotr-by-22 = 22×`shr/rcr/loop`). This is the single biggest waste.
- All 32-bit math is **memory-to-memory** 16-bit halves; on the 8088 every 16-bit
  memory access costs ~4 cycles/byte on the shared 8-bit bus, so memory traffic
  dominates. Cutting memory round-trips is the second big lever.
- `v001_byterot.inc` (already in `variants/`) replaced the bit-loop with
  byte-granular rotation (≥16 → `xchg` halves, ≥8 → byte rotate, ≤7 residual
  bits): **1.53× block / 1.51× PRF**, confirmed on 86Box (1.42×). Beat it.

## Optimization ideas (not exhaustive — invent your own)
1. **Specialize rotates by their constant shift.** The sigmas use fixed amounts
   (Σ0: 2,13,22; Σ1: 6,11,25; σ0: 7,18,>>3; σ1: 17,19,>>10). Inline an optimal
   fixed sequence per amount instead of the generic `rotr32` call+branches.
   e.g. rotr22 = rotr16(`xchg`)+rotr6; pick rotr-n vs rotl-(32-n) to minimize the
   ≤4 residual single-bit shifts.
2. **Load each 32-bit word once** into registers; the current sigmas re-read
   `[si]`/`[si+2]` three times. Compute all three rotates from one register copy.
3. **Cut the per-round state shuffle.** Each round copies 7 of a..h in memory.
   Rotate via pointers / a sliding window, or keep the hot words in registers.
4. **Keep the working variables in registers** across a round where possible
   (8086 has ax,bx,cx,dx,si,di,bp = limited; spend them on the hottest values).
5. **Message schedule**: same rotate trick for σ0/σ1; consider register reuse.
6. **Reduce `sha256_tmp` round-trips** — keep XOR accumulation in registers.
7. **Combine Σ1+ch and Σ0+maj** add chains; minimize `add [mem],reg`.
8. Loop unrolling (watch size); table-driven rotates; `lea` for address math.

## Output you must return (structured)
`name`, `parent` (which leader you mutated, or "fresh"), `idea` (1 sentence),
`technique` (short tag), `ok` (ok_sha && ok_prf), `block_cycles`,
`block_speedup`, `prf_speedup`, `bytes` (size of your process_block region or
file), `error` (if rejected), `notes` (what worked / what to try next).
