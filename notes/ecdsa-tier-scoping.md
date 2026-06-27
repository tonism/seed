# Future ECDSA secure-tier — scoping note (design intent, NOT a current build)

## Why this exists
Recon for auto-recertify (2026-06-14) found `api.openai.com` is **dual-cert load-balanced** and
migrating to ECDSA. Forcing the 286's profile (`ECDHE-RSA` + `RSA+SHA256`) still returns an
**RSA-2048 leaf via GTS WR1** (valid to **2029-02-20**), but *default* clients now get a **P-256
leaf via WE1** (ECDSA), root GTS Root R4. The shipped 286 secure tier (ECDHE_RSA + leaf-key pin)
and the in-progress auto-recertify (verify-vs-pinned-WR1, RSA) both live entirely on the RSA path,
which survives only because the 286 deliberately forces it.

**This is fine until ~2029** (or until OpenAI stops offering the RSA leaf to RSA-only clients,
whichever comes first). If the RSA leaf disappears, recertify fails closed → DPI → the user must
act. This note captures what a real ECDSA path would take, so the decision isn't a cold start.

## What an ECDSA tier needs (vs today's RSA path)
The channel crypto (ECDHE P-256 key agreement, ChaCha20-Poly1305, SHA-256) is **already done** —
the 286 does real ECDHE today. The new work is purely **authentication**:

1. **Cipher/sigalg offer.** Advertise `ECDHE_ECDSA_*` (0xcca9, already half-supported — the
   ServerHello accept folds 0xcca8/0xcca9) + `ecdsa_secp256r1_sha256` signature_algorithms. The leaf
   then comes back as P-256/WE1.
2. **ECDSA signature verify (the new primitive).** Both the in-race SKE-sig verify AND the off-race
   cert-chain verify become **ECDSA-P256-verify** instead of RSA-PKCS1. ECDSA verify =
   `u1·G + u2·Q` (two scalar mults + a point add + an inversion of `s mod n`), vs RSA's one modexp.
   - The module ALREADY has P-256 scalar mult (`p256_scalar_mult_mixed`) and the field/group
     arithmetic (core/p256.inc). ECDSA verify reuses them; the new pieces are: a second scalar mult
     with a non-fixed base (Q = the pinned/leaf public point), Shamir's trick (or two separate
     mults), and a modular inverse mod the group order n (binary GCD or Fermat).
   - **Cost:** ~2 scalar mults ≈ 2× the ECDHE cost (~6.6s @6 each → ~13s for a verify). That's
     OVER the @6 budget for the in-race path. So an ECDSA tier likely needs the same off-race
     architecture (cache the leaf point, in-race verify the SKE sig against it = ~2 mults... still
     heavy). **This needs a fresh measurement spike** (tools/crypto-bench, like the RSA one) —
     ECDSA verify @6 may not fit the in-race window even once. Could force 8 MHz as the floor.
3. **Pin model.** Pin WE1's P-256 public key (the anchor) + cache the leaf P-256 point. Same
   off-race chain-verify shape: ECDSA-verify the leaf's signature (the leaf is signed
   `ecdsa-with-SHA256` by WE1) over the leaf TBS, vs the pinned WE1 point. The X.509 strict-DER
   parser from auto-recertify is REUSED as-is — only the sig-verify primitive swaps RSA→ECDSA, and
   the leaf SPKI is an EC point (id-ecPublicKey) not an RSA key. WE1 root chain: WE1→GTS R4 (P-256→
   P-384) — but we pin WE1 directly, so R4/P-384 isn't needed on-device.
4. **gen-rsa-pinned-key.py analogue** for EC: emit the pinned WE1 point (Gx,Gy) + leaf point — a new
   `gen-ec-pinned-key.py` (or extend the existing one).

## Rough size/risk
- New asm: ECDSA-verify (~the bulk; Shamir + modular inverse), EC-point SPKI parse (small), an EC
  pinned-anchor blob. Reuses p256.inc field/group ops + the X.509 parser.
- The K-window fit is the usual wall (15 sectors, no slack) — the ECDSA-verify code competes with
  the RSA-verify code; likely they can't both be resident. A 286 build might pick ONE auth path at
  build/config time, or overlay them (both are handshake-only).
- **Biggest unknown -- RESOLVED 2026-06-27, see "Measured spike" below:** ECDSA-verify @6 does NOT
  fit by field-level tuning (~15.1 to 15.9 s vs the ~15 s window); @8 does (~12.4 s). The live open
  question is now whether the in-race SKE-sig verify can be off-raced (the real @6 determinant).

## Measured spike (2026-06-27) -- does ECDSA-verify fit @6?

A fan-out optimization spike (11 agents; findings adversarially checked against the shipped code)
answered the "biggest unknown":

- **Field-level tuning does NOT make @6.** The best non-overlapping stack (Comba dedicated squaring
  -- 5 of 8 mul_mod in point-double are squares; tighter Shamir/JSF; a Solinas-reduction micro-tune;
  Montgomery batch-inversion) saves ~1.0 to 1.4 s, landing @6 at ~15.1 s (optimistic) to ~15.9 s
  (worst-credible) -- on or over the ~15 s window, not under it. And there is no room: the built
  p256_module.bin is exactly 24/24 sectors (0 B headroom), and the 3-sector gap to the loop-cache
  cap is already taken by the recertify leaf-capture buffer, so the new code does not fit without
  growing the band.
- **The fixed-base comb on G is off-race, not a window lever.** u1*G cannot beat Shamir (variable-base
  u2*Q dominates and is not comb-able); the comb's ~4-5 s win lands on the client d*G keygen in the
  ClientHello phase, before the window opens -- a cold-boot latency win, ~0 to the race.
- **Refined numbers.** Shamir's realistic interleave is ~1.58x (not the 1.3x first guessed --
  doublings dominate), so the verify is ~8.3 s and the in-race handshake (premaster 6.6 + verify 8.3
  + PRF 0.8) ~= ~15.7 s @6. The mod-n inverse (binary ext-GCD), wNAF window (w=4), 286 ISA, and the
  modular reduction are already optimal / baked into the measured 6.6 s.
- **THE high-leverage lever (unmodeled until now): off-race the SKE-sig verify.** In-race cost is two
  irreducible general scalar mults (premaster + the verify's u2*Q). Auto-recertify already off-races
  the cert-CHAIN verify; if the in-race SKE-SIGNATURE verify can be deferred the same way (cache the
  verified leaf point off-race, keep only a light in-race binding check), it removes ~one scalar mult
  (~8 s) -> @6 fits with large margin. This dwarfs every field-mul win. OPEN QUESTION -- now answered
  by the Off-race feasibility spike below (NO-GO as proposed): can the SKE sig be structurally
  separated from the leaf-chain verify the way RSA's was?
- **Fallback if not:** 286 @8 MHz is the clean ECDSA floor (~12.4 s). Minor unexplored micro-avenues:
  a lower-mul doubling formula (3M+5S vs 8-mul), fused multi-squaring, an inverse-free verify.

## Off-race feasibility spike (2026-06-27) -- NO-GO as proposed

The follow-up spike (8 agents; adversarial security + feasibility review) answered the open question:
off-racing the SKE-sig verify does NOT cleanly unlock @6.

- **Security: sound for confidentiality, but a real downgrade.** Deferring the SKE-sig verify behind a
  strict fail-closed app-data gate leaks no durable secret (the CKE ephemeral public is public by ECDH
  design; the client Finished is a per-session PRF MAC useless off-connection; the client keypair is
  fresh per handshake -> no key-reuse). BUT it is strictly weaker than today's authenticate-before-use:
  a MITM gets a COMPLETED session + the client Finished (an interactive oracle) before rejection -- a
  documented downgrade, not free. CODE GOTCHA: on 3c503/3c501 the app record (the API key) is sent
  BEFORE the server Finished (tls.inc:901-909) to win the window, so the gate must block app-data on
  EVERY NIC path, not merely "after the server Finished".
- **The "reuse auto-recertify's off-race hook" premise is FALSE.** Recertify verifies the cert-CHAIN
  sig DISCONNECTED between handshakes, no socket held (net_phase.inc:107) -- a connection-INDEPENDENT
  artifact (the leaf, stable ~90 days). The SKE sig is PER-CONNECTION (signs THIS handshake's ephemeral
  point), so off-racing it means HOLDING the live connection idle ~8 s before the first app send -- or
  aborting and paying a SECOND full handshake (another ~6.6 s premaster mult, erasing the win). It
  cannot inherit recertify's disconnected safety.
- **The decisive blocker is timing, and it is UNMEASURED.** The synthesis called NO-GO by extrapolating
  the wire-proven @6 fragility (a 3.3 s in-span slip already pushed the client Finished ~1.6 s late and
  the server closed the connection; ~8 s idle is ~2.4x worse). A dissenting reviewer countered that this
  extrapolates the wrong span -- the post-client-Finished idle budget (server holds the client Finished,
  awaits the request) is characterized nowhere and MUST be wire-measured (sudo-tcpdump, like tls-flow.py)
  before any held-connection deferral is trusted.
- **Conclusion: 286 @8 MHz (~12.4 s, no deferral, no downgrade) is the clean ECDSA floor.** Reviving @6
  via off-race would need BOTH a wire measurement showing the held connection survives ~8 s idle AND
  acceptance of the security downgrade -- not worth it, especially as a 2029 contingency.

## Recommendation
Track WR1's RSA leaf availability. Stay RSA while it's offered (through 2029 at the latest). When
motivated to start: (1) both spikes are done (see above) -- @6 is not reachable cleanly (field tuning
misses ~15.1-15.9 s; off-racing the SKE verify is a held-connection timing risk + a security
downgrade), so 286 @8 MHz (~12.4 s) is the floor; (2) reuse the X.509 parser + p256.inc; (3) decide
resident-vs-overlay -- the module is already 24/24 sectors, so overlay is likely forced. Until then,
no code.
