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
- **Biggest unknown:** does ECDSA-verify @6/@8 fit the time budget? Needs a measured spike before
  committing — the RSA path's ~6.4s modexp is the current knife-edge; 2× P-256 mults is worse.

## Recommendation
Track WR1's RSA leaf availability. Stay RSA while it's offered (through 2029 at the latest). When
motivated to start: (1) measure ECDSA-verify @6/@8 first (spike), (2) reuse the X.509 parser +
p256.inc, (3) decide resident-vs-overlay for the two auth primitives. Until then, no code.
