# Real entropy + certificate authentication — feasibility scoping (4.77 MHz 8088)

Part of the real-crypto track. "Encrypted but not secure" today rests on THREE
deliberate sacrifices; ECDHE cost is measured separately (P-256 bring-up). This
file scopes the other two: **real entropy** and **server authentication**. Numbers
marked (est) are analytic 8088 cycle estimates; (measured) come from the harness.

---

## 1. Real entropy

### Today
`tls_seed_client_random_phase` (phases/tls_client_hello.inc:105) seeds a 16-bit
LCG from the BIOS tick (`0040:006c`) XOR the NIC MAC, then fills the 32-byte
ClientHello random with `x = x*25173 + 13849`. The same LCG is the only source
for the (currently absent) ephemeral scalar. This is **predictable**: tick
resolution is 54.9 ms, the MAC is public, and the LCG is trivially invertible —
an attacker who can guess the boot time recovers the "random".

### Real sources available on a 4.77 MHz PC (no RDRAND/RDSEED)
| source | quality | CPU cost | notes |
|---|---|---|---|
| **Inter-keystroke timing** | good | ~0 | the user TYPES the prompt; latch the 8253 PIT (ch0, port 0x40) at each `int 9`. Sub-tick jitter from human timing is genuine entropy. Already have the keypath (Build 11 ESC `int 9` hook). |
| **PIT vs BIOS-tick phase** | weak-moderate | µs | read the 8253 counter (≈1.193 MHz) latched against the 18.2 Hz tick; low bits drift with DRAM-refresh/bus contention on real HW. |
| **Floppy rotational latency** | moderate | ms (one seek) | time a sector read; spindle jitter. Costs a disk op. |
| **NIC arrival timing** | moderate | free-ish | low bits of the tick at each RX interrupt during DHCP/DNS. |

Recommended: a **pool** hashed by the SHA-256 we already have — mix PIT samples
at every `int 9` keystroke + every NIC RX + a floppy timing into a 32-byte pool,
`pool = SHA256(pool || sample)`. Extracting 32 bytes once per handshake is one
extra SHA-256 block ≈ **156 ms (measured)** — negligible vs the handshake.

### The catch: untestable on the emulator
86Box (no dynarec) is **cycle-deterministic** — PIT-vs-tick jitter and rotational
latency reproduce identically every boot, so the entropy is ZERO under test and
can only be validated on real hardware (or by statistical batteries on captured
real-HW samples). Keystroke timing is the one source that works even in the
emulator (human input is external). **Verdict:** cheap in CPU; the engineering
risk is quality + testability, not time budget. A keystroke + NIC + PIT pool is
the pragmatic path; claim entropy only after real-HW validation.

---

## 2. Server authentication (certificate chain + signature verify)

### Today
The Certificate handshake message is parsed for length and **drained, never
verified** (net_status_tls_certificate_drained). No signature check, no chain
walk, no hostname/validity check → fully MITM-able.

### What real auth requires
1. Parse the cert chain DER (leaf + ≥1 intermediate).
2. For each link: SHA-256 the TBSCertificate, then verify the issuer's signature.
3. Walk to a trust anchor (a pinned root — Seed would ship one or a few CA pubkeys).
4. Check validity dates + hostname (SAN).

The cost is dominated by the **signature verifications**. Cloudflare leaves are
typically **ECDSA-P256**, chained under RSA/ECDSA intermediates.

**Costs derived from the MEASURED P-256 field multiply** (137,625 cyc for one
256-bit `mul_mod`; one full ECDHE scalar mult = 110.8 s — see the P-256 results):

| verify op | core work | cost (8088 @ 4.77 MHz) |
|---|---|---|
| **RSA-2048, e=65537** | modexp = ~16 modsqr + 1 modmul of 2048-bit ints. A 2048-bit (128-word) schoolbook mul = 128² word-`mul`s = **64×** the 256 word-muls of the measured field-mul → ~5.9 M cyc; + Montgomery reduce ~6 M ⇒ ~12 M cyc/modmul × 17 | **~43 s per signature** |
| **ECDSA-P256 verify** | two 256-bit scalar mults (`u1·G + u2·Q`) + a mod-n inverse | **~2× one ECDHE scalar mult ≈ ~220 s** |
| SHA-256 over a ~1 KB TBSCert | ~16 blocks | ~16 × 156 ms ≈ **2.5 s** per cert hashed |

> Correction to an earlier guess: on a desktop, RSA *verify* is microseconds and
> "cheap", which misled an initial ~1 s estimate. On a 4.77 MHz 8088 the n² word-
> `mul`s dominate and RSA-2048 verify is **~43 s**, not ~1 s. It is still ~5×
> cheaper than ECDSA-P256 verify (~220 s), but both blow the window.

### Verdict
- **RSA-2048 verify ≈ 43 s/sig** (e=65537 keeps it to 17 modmuls — the *least bad*
  option). A 2-link RSA chain ≈ ~86 s of modexp + ~5 s of TBS hashing ≈ **~90 s**.
- **ECDSA-P256 verify ≈ 220 s/sig** — a chain is many minutes.
- Even the theoretical floor for RSA-2048 verify (only the raw `mul` opcodes, zero
  carry/reduce overhead) is ~15 s — i.e. *at* the window with an impossible-to-reach
  perfect implementation. There is no headroom.
- Pinning Cloudflare's intermediate (verify ONE signature, not a chain) halves it
  but ~43 s for one RSA-2048 verify still exceeds the 15 s window ~3×.

### Combined budget reality (measured)
All steps run **serially** in one handshake:
- ECDHE scalar mult: **110.8 s** (measured)
- cert-auth, cheapest realistic (1 pinned RSA-2048 verify + hashing): **~45 s**
- PRF: **~5 s** (→ ~3.3 s with the speed-track win)

⇒ a full real-security handshake is **~160 s ≈ 2.7 minutes**, ~11× over
Cloudflare's ~15 s patience. Full real security needs ONE of:
1. a self-hosted endpoint with a long/disabled patience window (not Cloudflare),
2. a one-time, user-opted "secure handshake" mode that tolerates minutes,
3. a documented partial: **real entropy (cheap, ~0.16 s) is the only one that
   fits** — ECDHE and cert-auth do not. Pinned-key transport (no chain walk) plus
   real entropy is the honest shippable middle ground; it is still not "secure".

**Honest-security bar (unchanged):** do NOT claim "secure" unless real ECDHE AND
real entropy AND cert-auth all land within a usable handshake. Measured: that is
out of reach on a stock 4.77 MHz 8088 against Cloudflare's window by ~11×. Real
entropy is the one affordable upgrade; the rest stays "encrypted but not secure",
labeled precisely.
