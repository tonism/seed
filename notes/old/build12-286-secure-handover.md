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

## Decisions locked (user, 2026-06-12)

1. **Ship TWO images — 160K AND 360K.** The 160K single-sided image stays as a
   first-class, **headline** target: the 1981 original IBM PC 5150 in its *weakest*
   config (4.77 MHz 8088, 16 KiB, single-sided 160K drive) must keep booting + running
   everything. The 360K double-sided image is ADDED for the 286 (the AT's 1.2 MB drive
   rejects the single-sided 160K geometry) and for DS-drive 8088s. Same CORE.SYS in
   both — only the FAT12 image geometry + the boot/loader/sidecar CHS differ (the boot
   chain, not the runtime). This *resolves* the "286 harness" open problem below: build
   the 360K image, the 286 boots that. (The architecture's "one artifact" principle
   bends here to "one runtime, two image containers" — a deliberate exception so the
   1981 weakest config stays the headline.)
2. **Test policy going forward (once crypto lands):** validate the secure tier on a
   **6 MHz 286** (the lowest secure CPU — the knife-edge), AND **ALWAYS** keep the
   **4.77 MHz 8088 / 16 KiB regression** test (the 160K headline must never regress).
   Both, every secure-tier change. (The 8088 path is gated off from the secure crypto,
   but the regression proves it.)
3. **"insecure" splash warning on pre-286 machines.** Once secure crypto ships, the
   splash shows a **dim/dark "insecure"** on the **second line**, RIGHT-aligned so the
   *tail* of "insecure" lines up with the tail of the "seed build 12" line above it —
   warning the user that everything runs but the channel is NOT secure. Gated on the CPU
   class: shown when `handoff_flag_cpu_286plus` is CLEAR (8088-class), hidden on a 286+
   (which gets the real secure channel). It is a deliberate, honest contrast that only
   makes sense once the secure tier exists, hence "once secure crypto is here."

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

## Increment 2 LANDED + the integration analysis (2026-06-12)

**Increment 2 DONE:** the optimized P-256 (`tools/crypto-bench/variants/p256_combined.inc`)
is now `core/p256.inc` (verbatim faithful copy of the bench-verified variant). Validated:
check-p256.py green; the default 16K/32K CORE.SYS is byte-identical (the file is NOT
`%include`d yet — landed, not wired).

**Key finding — it's a WIRE-UP of an absent subsystem, not a swap.** `core/p256.inc` was
never `%include`d; the runtime compiles NO P-256. The live "secret" is the insecure raw
server-X copy in `tls_parse_server_key_exchange` (tls.inc:1956-1960). The remaining work:
provide the data, house the code, wire the call, seed a real scalar.

**Authoritative external data set = `tools/crypto-bench/p256_data_bench.inc`** (~640 B, ALL
new to the runtime): 2 CONSTANTS `p256_prime` (16 LE words) + `p256_three` (verbatim) +
scratch `p256_jac_x/y/z`, `p256_s0..s8` (288 B), `p256_product` (72 B), `tls_server_ec_x/
y_words`, `tls_shared_x_words`, `p256_client_private`, the `*_ptr` vars. The wNAF/Karatsuba/
Solinas scratch (896 B, `p256_w_*`/`p256_k*`/`sol_acc`) ships INSIDE the variant's tail data
block — do NOT re-add. No baked G-table (built at runtime), no reduce-coeff table (Solinas
unrolled). `tls_premaster_secret` already exists (overlays `high_crypto_work`).

**Size: ~5 KiB code + ~1.5 KiB data** (measured, not the earlier 3.4 KiB guess) — too big
for the resident; needs the handshake-only overlay / 286-module (see Layout).

**Two security landmines (from the analysis):**
- **#3 (load-bearing):** `p256_client_private` MUST be seeded with a real per-session
  scalar. The `_is_one`/`_is_two` fast paths SILENTLY shortcut to today's insecure
  passthrough if it stays 1/2 — NO error. Forgetting to seed = false security.
- **#4 (aliasing):** place the P-256 scratch so NONE of `p256_jac_*`/`p256_s*`/`p256_product`
  /`sol_acc`/`p256_k*` overlaps `low_crypto_work` (==`ne_tx_frame`==0x0700) or a NIC RX buffer
  (this repo's recurring 0x0700 crypto-aliasing bug). The premaster compute runs once before
  key derivation (a no-NIC window) — safe there.

**Parser rewrite (increment 3):** `tls_parse_server_key_exchange` (tls.inc:1931-1972) — store
X→`tls_server_ec_x_words`, Y→`tls_server_ec_y_words` (point bytes at bx+5 / bx+5+32), then call
`p256_compute_server_premaster_secret` (leaves the be32 secret in `tls_premaster_secret`, CF=0).

**Offline correctness oracle:** the bench re-runs the actual 8086 code → `ck=D51E` (wordsum of
the correct shared X): `tools/crypto-bench/p256_bench.asm` via `run86box.py`, `-DP256_SRC`
pointed at `core/p256.inc`. (Plus check-p256.py for the math/constants.)

**Remaining increments:** 3 = data → data.inc (gated, no-alias) + the parser rewrite + real
client-scalar seeding/entropy; 4 = RSA-2048 cert-chain verify (BUILD from scratch — ASN.1 +
PKCS#1 + pinned anchor; the most trust-critical, the false-security crux — fresh rigor); 5 =
the 286-only overlay module + dispatch gate; 6 = the insecure splash.

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

## The 286 test harness — RESOLVED by Decision 1 (ship the 360K image)

The AT's 1.2 MB drive rejects Seed's single-sided 160K geometry, so the 286 boots the new
**360K** image (Decision 1). Build path: a DS/9-spt/2-head FAT12 image + a 360K boot-sector
BPB + 360K CHS in the loader; the crypto-bench's `bench_boot.asm` is the **360K BPB
precedent**. 86Box: the `ibmat` (286) needs a hand-built CMOS (the AT halts on blank CMOS;
the XT has none) — see the crypto-bench's `at286_ladder.py` / `class_matrix.py` for how it
crafted one + mounted a DS image. The 286 boots the 360K image; the 160K image stays for the
8088 (incl. the 16K sidecar). The bench proved the crypto FITS on `ibmat`; the NEW bar is the
integrated *product* handshake on a 286 booting the 360K image.

## Crypto-opt lever (optional — for 6 MHz slack)

@286@6 the full secure handshake is ~13.8 s (with the SHA win) — fits ~15 s but only ~1.2 s
slack (flaky). A **dedicated RSA squaring path** (the bench's RSA does squarings as full
multiplies) would drop 16 squarings to ~0.6× → RSA ~6.37 s → ~4.3 s → handshake ~11.7 s →
~3.3 s slack. "A future lever, not built." Ship 286@8+ as the comfortable tier first; the
6 MHz part is the boundary.

## Suggested increments (each build-green + validated; never commit broken)

1. **Build the two images + the 286 harness** (Decision 1) — add the 360K DS image
   alongside the 160K headline (FAT12 builder + boot BPB + loader/sidecar CHS; same
   CORE.SYS), and stand up the 86Box `ibmat` (286, crafted CMOS) booting the 360K image.
   Verify: 160K still boots the 8088 (16K sidecar + 32K direct), 360K boots an 8088
   DS-drive 5150 AND the 286. Nothing else is validatable without this.
2. **Land the optimized real P-256** in `core/` (assembles 8086-clean, `check-p256.py`
   green), still gated OFF (present, not wired) — proves the port.
3. **Wire ECDHE + entropy** behind the 286 gate (the secure key agreement), validate the
   handshake completes + the keys match on the 286 harness.
4. **RSA cert-chain verify** (the trust-critical part) — ASN.1 parse + PKCS#1 + pinned
   anchor; validate it ACCEPTS the real chain and REJECTS a tampered one.
5. **Integrate + the 286 layout** (handshake-only module, dispatch-gated), validate the
   full real handshake fits the window on the 286 harness; re-validate 8088 16K/32K
   UNCHANGED (the secure path is 286-gated).
6. **The "insecure" splash warning** (Decision 3) — once the secure tier works, add a
   dim "insecure" on the splash's second line, right-aligned so its tail aligns with the
   "seed build 12" line's tail, shown only when `handoff_flag_cpu_286plus` is clear
   (8088-class). Bounded UI change in `splash.inc`; gate on the CPU flag.
7. Optional: the RSA-squaring crypto-opt for 6 MHz slack.

## Honest-framing guardrails

- Keep **"encrypted, not secure"** for the 16K/8088 tier — do not soften it.
- Do NOT ship entropy or a half-wired ECDHE as a cosmetic "secure" — it must be real key
  agreement + real cert auth or it's not secure (FINDINGS is emphatic).
- The trust anchor is the crux — document exactly what is trusted and why.

## Validation

- **Test policy (Decision 2), every secure-tier change:** the **6 MHz 286** (`ibmat`,
  the lowest secure CPU + the ~1.2 s-slack knife-edge — the security gate) AND **always**
  the **4.77 MHz 8088 / 16 KiB** regression (the 160K headline must never regress; the
  secure path is 286-gated, the regression proves it). Component proofs exist (crypto-bench
  `ibmat` @6/8); the NEW bar is the **integrated product handshake on the 286** completing a
  real authenticated TLS exchange within the window.
- `pkill -f 86Box` before any canary; read FULL build output; confirm fresh CORE.SYS md5
  before trusting a `--no-build` run (see [[feedback_verify_full_build_fresh_artifact]]).
