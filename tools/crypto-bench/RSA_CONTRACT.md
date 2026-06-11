# RSA-2048 verify — testbench contract

**Goal:** one correct RSA-2048 signature verify, `rsa_sig^65537 mod rsa_n`, in 8086
assembly, to MEASURE its time on a 6 MHz 286 (86Box). Testbench only — nothing ships.
Correctness is the only gate here; speed is measured later on real hardware, so write a
*real* Montgomery modmul (representative operation count), not a shortcut.

## What you implement

A single file `rsa_verify.inc` defining the label **`rsa_verify`** (a `ret`-terminated
routine, `cpu 8086`). It takes no arguments. It reads the input buffers, computes the
modular exponentiation, and writes the answer to `rsa_result`.

All operands are **128 little-endian 16-bit limbs** (2048-bit), i.e. limb 0 is the least
significant word. The buffers already exist (the harness appends them after your code) —
just refer to them by name; **do not define them yourself**:

| buffer | size | role |
|---|---|---|
| `rsa_n` | 128 w | modulus N (input) |
| `rsa_sig` | 128 w | signature s (input) |
| `rsa_r2` | 128 w | R² mod N, R = 2²⁰⁴⁸ (input) |
| `rsa_n0inv` | 1 w | −N⁻¹ mod 2¹⁶ (input) |
| `rsa_one` | 128 w | the constant 1 (preset) |
| `rsa_result` | 128 w | **OUTPUT** = s^65537 mod N |
| `rsa_x`, `rsa_sm`, `rsa_tmp` | 128 w each | scratch you may use |
| `rsa_t` | 260 w | scratch (e.g. the CIOS accumulator t[0..n+1]) |

Memory model: real mode, `CS=DS=ES=SS=0`, flat. Buffers are reachable by their 16-bit
offset (the label). Stack is fine (SP high). You may clobber any registers.

## The exponent is fixed: e = 65537 = 2¹⁶ + 1

So the exponentiation is exactly **16 squarings + 1 multiply** in the Montgomery domain.
Use Montgomery multiplication (`montmul(a,b) = a·b·R⁻¹ mod N`) so there is no division:

```
sm     = montmul(rsa_sig, rsa_r2)   ; enter Montgomery domain: s·R mod N
x      = sm                          ; copy 128 limbs
repeat 16 times:  x = montmul(x, x)  ; x = sm^(2^16)
x      = montmul(x, sm)              ; x = sm^(2^16 + 1) = sm^65537
rsa_result = montmul(x, rsa_one)     ; leave domain: x·R⁻¹ = s^65537 mod N
```

That's 19 montmuls. Use `rsa_x`/`rsa_sm`/`rsa_tmp` for the intermediates.

## Montgomery multiply — CIOS, n = 128, base b = 2¹⁶

`montmul(a, b)` → result `u` (n limbs) = `a·b·R⁻¹ mod N`, where `n0 = rsa_n0inv`:

```
t[0..n+1] = 0
for i in 0..n-1:
    C = 0                                    ; multiply phase: t += a * b[i]
    for j in 0..n-1:
        full = t[j] + a[j]*b[i] + C          ; 32-bit; a[j]*b[i] is a 16x16->32 MUL
        t[j] = full & 0xFFFF ;  C = full >> 16
    full = t[n] + C ;  t[n] = full & 0xFFFF ;  t[n+1] = full >> 16

    m = (t[0] * n0) & 0xFFFF                  ; reduction phase
    full = t[0] + m*n[0]                      ; low word becomes 0, propagate carry
    C = full >> 16
    for j in 1..n-1:
        full = t[j] + m*n[j] + C
        t[j-1] = full & 0xFFFF ;  C = full >> 16
    full = t[n] + C ;  t[n-1] = full & 0xFFFF ;  t[n] = t[n+1] + (full >> 16)

; t[0..n-1] now holds a·b·R⁻¹ mod N, but possibly in [N, 2N): conditional subtract
if t[n] != 0  OR  t[0..n-1] >= N:
    t[0..n-1] -= N
u = t[0..n-1]
```

The carry `C` always fits in one 16-bit word. The core 32-bit step `full = word + w1*w2 + C`
on 8086: `mov ax,w1 ; mul w2` (→ DX:AX) `; add ax,word ; adc dx,0 ; add ax,C ; adc dx,0`
then store AX as the low word and keep DX as the new C.

## How to test (iterate until correct)

```
cd tools/crypto-bench
python3 rsa_eval.py rsa_verify.inc
```

Must print `"ok": true`. The oracle is `pow(s, 65537, N)` for the fixed N/s baked into
`rsa_bench_harness.py` — any carry/indexing bug makes the 2048-bit result mismatch, so the
gate is unforgiving. `instrs` is reported as a rough proxy (expect a few million — that's
fine; real timing is on 86Box). A correct, plain CIOS is the goal; do not micro-optimize.

A trivial reference stub that assembles is `rsa_stub.inc` (it just `ret`s — wrong answer,
but shows the include wiring).
