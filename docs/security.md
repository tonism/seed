# Security

Seed's TLS channel is **capability-tiered**: how secure the connection is depends on
the CPU it boots on, because real public-key crypto on these machines is a *speed*
problem, not a size one. This document is the reference for what protection Seed
provides on each tier and why it stops where it does. Its companion
[crypto-feasibility.md](crypto-feasibility.md) is the *story of how we measured that
boundary* — the benchmarks, the optimisation hunt, the levers ruled out; the system
mechanics (where the crypto lives, the handshake's place in the boot) are in
[architecture.md](architecture.md).

**The one line:** a stock 8088 is honestly **encrypted, but not secure** — no key
agreement, no authentication, so a passive eavesdropper recovers every session key. A
**286 is a real, authenticated secure channel** — real ECDHE, a pinned-key RSA
certificate verify, and silent re-pinning when the leaf rotates. *Secure is a 286
capability, never the 16 KiB / 4.77 MHz floor*, and the product says so to the user's
face rather than implying more than it delivers.

## The 8088 floor — encrypted, not secure

On a stock 4.77 MHz 8088 the handshake runs ChaCha20-Poly1305 and SHA-256 for real,
but the public-key steps are skipped — not for lack of RAM (the real primitives fit in
~3.4 KiB) but because a single P-256 scalar multiply is **110.8 s** at that clock and
the server closes the connection in ~15 s. Concretely:

- **No key agreement.** The boot substitutes a scalar-1 stub: the server's public X
  coordinate *is* the premaster, so no Diffie-Hellman happens and **anyone who captures
  the handshake derives every session key** (`tools/tls-decrypt.py` does exactly that).
- **No authentication.** Server-certificate verification is skipped too (RSA-2048 verify
  ~43 s, ECDSA-P256 ~220 s on the 8088 — both far past the window), so the peer is
  unverified and the channel is MITM-able.
- **Entropy would not save it.** With a public premaster the client random is only a
  nonce; making it unpredictable buys no confidentiality. Real entropy is a cheap
  *prerequisite* for a secure channel (~0.16 s), never a standalone fix, so it is not
  shipped standalone — that would be cosmetic.

So the 8088 tier is **encrypted, not secure**, and the label is precise, not
aspirational. A pre-286 machine shows a red **"insecure"** on the splash to say so. The
full measured case for *why* this can't be optimised across — the ~2.7-minute combined
handshake, ~11× over the window — is in [crypto-feasibility.md](crypto-feasibility.md).

## The 286 secure tier — real and authenticated

The 286 is the first processor whose integer `MUL` is fast enough (≈9× the 8088's) to
run a real authenticated handshake inside the provider's window. On it the secure
channel is **real, not skipped**:

- **Real ECDHE key agreement.** The optimised constant-time P-256 (Solinas + Karatsuba
  + wNAF, OpenSSL-verified, ~6.6 s/scalar-mult on the lowest 6 MHz part) is wired as a
  286-only handshake module. The client generates a genuine ephemeral keypair from an
  entropy pool (PIT / MAC / tick → SHA-256), sends its real public point, and derives
  `premaster = client_private × server_public`. No scalar-1 stub — the session keys are
  a real shared secret.
- **Real server authentication.** The 286 negotiates `ECDHE_RSA` and verifies the
  ServerKeyExchange's RSA-2048-PKCS#1 signature — the one in-race RSA verify — against a
  **pinned provider leaf public key**, proving the server holds that key. It is real
  authentication, not a cosmetic flag.

The 286-only crypto (P-256 + RSA verify + cert glue, ~10 KiB) lives in a handshake-only
module that **overlays the 32 KiB loop cache — 0 resident RAM on 16 KiB**; the hot path
never loads it. (`montsqr`, a Montgomery squaring shortcut for the RSA modexp, widens
the @6 margin ~19%; see crypto-feasibility.md.)

**Validated** on both the 6 MHz 286 (the knife-edge) and the 8 MHz: each completes a
full real-ECDHE + RSA-cert-authenticated handshake and reaches the model, and a
**one-bit-tampered pinned key is rejected** (the handshake fails) — the pin is enforced.
The handshake fits the ~15 s window even at 6 MHz, but on a ~1.2 s knife-edge that may
flake on a degraded link (the 8088's exact failure mode); **8 MHz is the comfortable
secure floor**.

### Why pin the leaf, not chain to the root

Pinning `api.openai.com`'s **leaf** key keeps authentication to *one* RSA verify, which
is what fits the lowest 286 — chaining to its RSA-4096 root would be ~3 verifies and
push back over the window. RSA over ECDSA for the same reason: ECDSA-P256 verify is
~2× an ECDHE scalar mult (see [the ECDSA tier](#the-future-ecdsa-tier--scoped-not-built)).
A pinned leaf would normally be brittle — leaves rotate ~90 days — but that rotation is
handled automatically (next section). The leaf itself ships as `SEED/LEAF.DER`; only the
durable CA anchor is baked into `SEED.SYS`.

## Silent re-pinning (auto-recertify)

A pinned leaf rotating every ~90 days would otherwise force a runtime rebuild every quarter, so
the 286 bakes a **durable** anchor — the issuing CA, **Google Trust Services WR1**
(RSA-2048, valid for years) — and ships the current leaf as `SEED/LEAF.DER`. On 286+,
Seed verifies that file against WR1 before opening a TLS socket. If the file is missing,
stale, or invalid, the in-race verify fails closed and the device runs a full X.509
chain-verify **off the ~15 s race**:

1. parse the freshly-presented leaf (strict DER),
2. confirm its SAN is exactly `api.openai.com`,
3. verify the leaf's signature against the pinned WR1, **and**
4. check the leaf is currently within its `notBefore`/`notAfter` window.

If all four pass, the new leaf is adopted as the pin and the handshake is retried. A dim
`> recertify` marks the pause (**mid-chat only** — silent during cold-boot loading), and
a mid-chat rotation keeps the conversation (history lives in RAM).

After a successful re-pin, Seed also tries to write the verified leaf DER back to
`SEED/LEAF.DER` on the boot medium. This is best-effort and silent: write-protected or
full media simply continue without the cache update. Later 286+ connects read that file before
opening a TLS socket, verify it through the same strict-DER, SAN, WR1-signature, and date
checks, and only then adopt it as the fast-path pin. The file is therefore not
trust-on-disk; the immutable WR1 anchor in `SEED.SYS` remains the trust root. A missing
or invalid file falls back to the normal live-leaf recertify path.

This is deliberately **not trust-on-first-use**: a leaf is adopted only if a CA we
*already* pinned signed it, for the *exact* host we expect, and only while it is in date
— anything else **fails closed** and falls through to the normal reconnect-failed path.

Two properties make the date check trustworthy:

- **An independent clock.** A 286-only setup phase syncs the CMOS RTC from NTP
  (`time1.google.com`) at boot, *before* any TLS, and the validity gate reads that RTC —
  so a hostile server cannot backdate the check via its own response. If NTP is
  unreachable the date check is skipped (best-effort), not failed.
- **Off-race timing.** The WR1 re-derive (~3.3 s on a 6 MHz part) runs *before* the
  reconnect opens its socket — off the server's window. It has to: when it ran between
  the SYN and the ClientHello instead, the 6 MHz client Finished landed ~1.6 s past the
  deadline and the server closed (wire-confirmed). Moving the derive ahead of the connect
  fixed the @6 re-pin.

WR1 itself rotates on the order of years and still needs a human re-pin then
(`tools/gen-rsa-pinned-key.py --mode anchor`). Like the rest of the secure tier this is
286-only — the captured leaf and the chain-verify run inside the handshake-only module
(the WR1 anchor is shrunk to its modulus, Montgomery constants re-derived on the fly), so
the 16 KiB hot path carries none of it.

## Trust model, in one place

```text
pinned leaf key    api.openai.com's RSA-2048 leaf from SEED/LEAF.DER or verified recertification
pinned CA anchor   Google Trust Services WR1 (RSA-2048) — the durable re-pin anchor
leaf DER file      SEED/LEAF.DER, shipped and refreshable; verified against WR1 before adoption
adoption rule      a new leaf is pinned ONLY if WR1 signed it, SAN == api.openai.com,
                   and it is in date — never trust-on-first-use
failure            fail closed: an unverifiable leaf is not adopted; reconnect-failed path
validity clock     CMOS RTC, NTP-synced at boot, independent of the authenticated peer
human re-pin       leaf: automatic (auto-recertify); CA (WR1): manual, ~yearly cadence
                   (tools/gen-rsa-pinned-key.py)
```

## The future ECDSA tier — scoped, not built

`api.openai.com` is **dual-cert load-balanced**: the 286's forced `ECDHE_RSA` profile
still gets an RSA-2048 leaf issued by WR1 (current shipped leaf: **2026-07-08** to
**2026-10-06**; WR1 anchor valid to **2029-02-20**), but default clients now get a P-256/WE1
**ECDSA** leaf. Today's RSA path survives only because the 286 forces it; if the RSA leaf
is ever withdrawn for our profile, recertify fails closed and the user must act. So an ECDSA
path is a tracked contingency, scoped by two fan-out spikes (the journey is in
[crypto-feasibility.md](crypto-feasibility.md#the-ecdsa-question--scoped-not-built); the raw
record is `notes/old/ecdsa-tier-scoping.md`):

- **Optimisation spike — field tuning can't make @6.** ECDSA verify is two scalar mults
  (~8.3 s with Shamir's trick); the best non-overlapping stack of field-level wins lands
  the @6 handshake at ~15.1–15.9 s — on or over the ~15 s window — and the 286 module is
  already 24/24 sectors full, with no room for the new code.
- **Off-race feasibility spike — NO-GO as proposed.** Deferring the SKE-signature verify
  the way auto-recertify defers the *chain* verify is sound for confidentiality (nothing
  durable leaks behind a strict fail-closed app-data gate) but a **security downgrade**: a
  MITM gets a completed session and the client Finished — an interactive oracle — before
  rejection. And it can't actually reuse the recertify hook: recertify verifies
  *disconnected between handshakes*, while the SKE signature is *per-connection*, so
  off-racing it means holding the live connection idle ~8 s (a wire-unmeasured timing risk
  the @6 window is unforgiving about).

**Verdict: 286 @8 MHz (~12.4 s, no deferral, no downgrade) is the clean ECDSA floor** if
the contingency ever fires — the same knife-edge precedent as the RSA tier. No code while
the WR1 RSA leaf is served.

## Reproduce / the record

- **Live validation:** `tools/run-286-86box.py` (286 @6/@8, networked, screenshots the
  greeting — accept, and the 1-bit-tamper reject).
- **The measurements:** `tools/crypto-bench/` and `results/FINDINGS.md` (the raw lab log
  behind crypto-feasibility.md).
- **Working records:** `notes/old/auto-recertify-attempts.md`,
  `notes/old/ecdsa-tier-scoping.md`, and
  `notes/old/build12-layout-redesign-attempts.md`.
- **Re-pin tooling:** `tools/gen-rsa-pinned-key.py` (`--mode anchor` for the CA),
  `tools/x509/` (the offline X.509 oracle + tamper matrix).
