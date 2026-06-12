# Build 12 — 286 secure tier handover (real authenticated TLS)

Self-contained brief for a **fresh, dedicated session** to build the 286 secure tier —
the last and largest Build-12 objective. Read this + `docs/architecture.md` ("Capability
Tiers", "CPU And Crypto Budget") + `tools/crypto-bench/results/FINDINGS.md` (the measured
feasibility — the spine of this work). The prior sessions did the R&D + the prerequisites
but deliberately did **not** execute this (security-critical, multi-part, needs fresh rigor).

## Goal

On a **286-or-better CPU at 32 KiB**, run a **real, cert-authenticated TLS 1.2 handshake**
(real ECDHE key agreement + RSA-2048 cert-chain verify + real entropy) that fits the
provider's measured ~15 s window. The 16 KiB / 4.77 MHz 8088 floor stays honestly
**"encrypted, not secure"** — unchanged. "Secure" is a **286@8+ tier**; 286@6 fits only
with the fast SHA and ~1.2 s slack (flaky), 286@8 is the comfortable home (~4.6 s slack).

**This is the one Build-12 piece where getting it WRONG is worse than not shipping it:**
a cert-verify that accepts a forged chain is a *false* security claim. Correctness + an
honest trust model are the bar, not speed.

## Already done (the prerequisites + the R&D)

- **#2 CPU-class gate — LANDED (commit `700f267`).** `handoff_flag_cpu_286plus` (handoff
  flags bit 0x0010) is set at boot by `hardware_setup_detect_cpu` (the FLAGS bits-12-15
  test). **This is the gate** — the secure path keys off it. FPU/link-type/finer-class
  stay reserved (the FPU does NOT help crypto — measured; don't build an FPU path).
- **The dispatch-vector seam** (the NIC HAL's `nic_vtable` pattern + the per-tier phase
  loader) is the mechanism for routing the secure crypto path. The 32K floppy-free loop
  already preloads the handshake crypto; the secure crypto is another handshake-only module.
- **Fast SHA (r2_v25) is the 16K baseline; r4_v42 (4.64×) is the testbench winner.** The
  secure handshake LEANS on the SHA win (PRF+transcript 4.94 s → 0.66 s @286@6). Decide
  whether the 286 tier ships r4_v42 (it has the 32K arena room the 16K tier didn't).
- **The crypto-bench has the OPTIMIZED, OpenSSL-VERIFIED primitives** (testbench, NOT in
  the runtime): `tools/crypto-bench/variants/p256_combined.inc` (Karatsuba+Solinas+wNAF,
  2.55× field mul, scalar_mult==PEER_PUBLIC verified; 6.6 s ECDHE @286@6 measured) and
  `tools/crypto-bench/rsa_verify.inc` (s^65537 mod N, 19 CIOS modmuls, 6.37 s @6 / 4.78 s
  @8 measured, ck=54F2 verified). Oracles: `check-p256.py`, `rsa_eval.py`.

## What must be BUILT (the real work — three parts)

1. **Port the optimized real ECDHE into the runtime + wire it.** `core/p256.inc` is
   `%if 0`'d (only `p256_compute_server_premaster_secret`, the scalar-1 stub, is live —
   it copies the server's public X as the premaster, so there is NO key agreement). Land
   `variants/p256_combined.inc` (the optimized version) as the 286 ECDHE. Then WIRE it:
   generate a client ephemeral private key (needs entropy, below), compute the client
   public (scalar×G), send a REAL ClientKeyExchange (the client's public point — today the
   stub path sends a fixed point), and compute the shared premaster = client_priv ×
   server_public. This replaces the premaster stub in `tls.inc` (search `tls_premaster_secret`,
   `tls_curve_secp256r1`, `p256_compute_server_premaster_secret`). ~3.4 KiB code — must
   load as a **handshake-only, 286-only module** (see Layout), NOT resident (16K can't afford it).

2. **RSA-2048 cert-chain verify — the missing piece (build, don't just port).** The bench
   measured only the modexp (`s^65537 mod N`). The runtime has **no X.509 parse, no trust
   anchor, no PKCS#1 verify**. Build: (a) walk the TLS Certificate message's cert chain
   (already received — `net_status_tls_certificate_*`), (b) ASN.1-parse each cert's
   TBSCertificate, signature, and the issuer's RSA public key, (c) verify each signature
   with the modexp (`rsa_verify.inc`) against the SHA-256 of the TBSCertificate (PKCS#1
   v1.5 unpad + compare), (d) chain to a **pinned trust anchor** (Cloudflare's CA — decide:
   pin the leaf/intermediate's key, or a root). **The trust decision is the security crux**
   — a wrong/missing anchor = accepting anything. Keep it honest + minimal (pin what the
   provider actually serves; document it). This is the largest + most correctness-critical
   sub-task.

3. **Real entropy for the ephemeral key (~0.16 s, gated).** A SHA-256-mixed pool fed by
   keystroke timing / NIC arrival / PIT samples. NOTE: the emulator is cycle-deterministic
   — only keystroke timing yields entropy under test; the rest needs real-hardware
   validation. Entropy ONLY matters bundled with the real ECDHE (a real secret scalar);
   standalone it's cosmetic (see FINDINGS "Don't ship a cosmetic fix").

## Layout (32K + 286 only)

The secure crypto (P-256 ~3.4 KiB + RSA verify + cert parse) is **handshake-only** and
**286-only**. It must NOT be resident (the 16K/8088 tier never loads it) — load it as a
module (a phase, or the active-driver-slot pattern) into the handshake-only overlay band on
the 286 path, selected via the dispatch vector keyed on `handoff_flag_cpu_286plus`. On 32K
there is arena room; the 286 secure tier is inherently 32K (a 286 with ≥32K). Reuse the
overlay-zone model (handshake-only ⟷ chat scratch, max not sum). check-layout must model
the 286 module's band.

## The 286 test harness — an OPEN PROBLEM to solve first

The matrix is 8088 (16K sidecar / 32K direct). The crypto-bench booted a **crafted 360K
image on 86Box `ibmat` (286) with a hand-built CMOS** (the AT halts on blank CMOS; the XT
has none) — and the AT **rejects Seed's 160K single-sided image**. So validating the
product on a 286 needs one of: (a) a 286-capable 86Box profile that boots Seed's 160K image
(investigate the AT's floppy support / a different 286 machine model), (b) adapting Seed to a
360K image for the 286 tier, or (c) a real-hardware path. **Solve this before claiming the
tier works** — the bench's component measurements (ECDHE/RSA/SHA on `ibmat`) are the proof
the crypto FITS, but the integrated product handshake on a 286 must be demonstrated.

## Crypto-opt lever (optional — for 6 MHz slack)

@286@6 the full secure handshake is ~13.8 s (with the SHA win) — fits ~15 s but only ~1.2 s
slack (flaky). A **dedicated RSA squaring path** (the bench's RSA does squarings as full
multiplies) would drop 16 squarings to ~0.6× → RSA ~6.37 s → ~4.3 s → handshake ~11.7 s →
~3.3 s slack. "A future lever, not built." Ship 286@8+ as the comfortable tier first; the
6 MHz part is the boundary.

## Suggested increments (each build-green + validated; never commit broken)

1. **The 286 test harness** (solve the boot problem) — without it nothing else is
   validatable. Get Seed booting on a 286 86Box VM.
2. **Land the optimized real P-256** in `core/` (assembles 8086-clean, `check-p256.py`
   green), still gated OFF (present, not wired) — proves the port.
3. **Wire ECDHE + entropy** behind the 286 gate (the secure key agreement), validate the
   handshake completes + the keys match on the 286 harness.
4. **RSA cert-chain verify** (the trust-critical part) — ASN.1 parse + PKCS#1 + pinned
   anchor; validate it ACCEPTS the real chain and REJECTS a tampered one.
5. **Integrate + the 286 layout** (handshake-only module, dispatch-gated), validate the
   full real handshake fits the window on the 286 harness; re-validate 8088 16K/32K
   UNCHANGED (the secure path is 286-gated).
6. Optional: the RSA-squaring crypto-opt for 6 MHz slack.

## Honest-framing guardrails

- Keep **"encrypted, not secure"** for the 16K/8088 tier — do not soften it.
- Do NOT ship entropy or a half-wired ECDHE as a cosmetic "secure" — it must be real key
  agreement + real cert auth or it's not secure (FINDINGS is emphatic).
- The trust anchor is the crux — document exactly what is trusted and why.

## Validation

- Component proofs exist (crypto-bench, `ibmat` @6/8). The NEW bar: the **integrated
  product handshake on a 286 86Box VM** completing a real authenticated TLS exchange within
  the window, + the 8088 matrix 7/7 unchanged (the 286 path must not regress the 8088 tiers).
- `pkill -f 86Box` before any canary; read FULL build output; confirm fresh CORE.SYS md5
  before trusting a `--no-build` run (see [[feedback_verify_full_build_fresh_artifact]]).
