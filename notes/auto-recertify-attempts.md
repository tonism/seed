# Auto-recertify — attempts / grind log

Plan: `notes/auto-recertify-plan.md`. Memory: `project_auto_recertify`. The goal: make a ~90-day
leaf rotation silent by verifying a freshly-presented leaf against the pinned issuing CA (GTS WR1),
off the ~15s race. This log is the grind; the polished spec is `tools/x509/PARSER_CONTRACT.md`.

## Phase 1 — X.509 offline oracle + tamper matrix (the trust-critical crux) — DONE, all green

Offline-first per the plan: build + prove accept-real / reject-tampered BEFORE any 286 wiring.

### Recon finding (important): api.openai.com is dual-cert load-balanced, and migrating to ECDSA
- The **live default** chain is now fully **ECDSA**: P-256 leaf issued by **WE1** (ECDSA), root GTS
  R4. NOT what the shipped leaf-pin tier uses.
- Forcing the 286's exact profile (`openssl s_client -tls1_2 -cipher ECDHE-RSA-... -sigalgs RSA+SHA256`)
  returns the **RSA-2048 leaf issued by WR1** — byte-identical modulus to the pinned/saved leaf
  (`fc61a1b4…`), fingerprint `dd107af0…` == the fp baked into `rsa_pinned_key.inc`. So the 286
  always lands in the WR1 RSA family because it only offers ECDHE_RSA. The dual-cert behavior is why
  the shipped tier validated today even though `s_client` defaults now show WE1/ECDSA.
- **WR1 = RSA-2048, valid until 2029-02-20** → the durable anchor the design wants. WR1's e = 65537,
  so the existing 128-limb `rsa_verify` modexp works directly for the chain-verify.
- Risk to flag (not a blocker): OpenAI prefers ECDSA generally now; the RSA leaf survives only
  because the 286 forces it. If GTS drops the RSA leaf, recertify fails closed + the user re-pins.

### What landed (`tools/x509/`)
- `x509_verify.py` — strict-DER X.509 parser + verify, **the authoritative oracle** the 286 mirrors.
  Positional walk, minimal-length DER, bounds, no-trailing, fail-closed. RSA verify = recover +
  reconstruct EMSA-PKCS1-v1.5 + full-256-byte compare (same as the shipped SKE verify). Gates:
  inner==outer==sha256WithRSAEncryption, sig-vs-WR1, leaf RSA-2048/e=65537, exactly-one-SAN with
  exact `api.openai.com`, validity. **ACCEPTS the real leaf** (TBS hash `166db20e…` matches openssl).
- `der_build.py` — minimal DER cert assembler + a deterministic (fixed-seed) synthetic RSA CA, so the
  tamper matrix can mint **valid-sig-but-policy-violating** certs (the only way to test the SAN /
  validity / single-SAN / adopt-key gates *independently of the signature*). Inverse of the parser.
- `tamper_matrix.py` — **27 cert vectors + TLV strict-DER unit tests, ALL GREEN**, each reject checked
  against the intended gate's *reason* (so "right answer, wrong reason" still fails):
  - real-leaf tampers vs WR1: sig bit/byte flip, TBS SAN/validity byte flip, truncate (×2), over-long
    (×2), BER non-minimal length, BER indefinite length, wrong anchor, sigAlg substitution, clock
    past/before validity.
  - synthetic valid-sig policy violations: SAN=evil / suffix attack / prefix attack / wildcard-only,
    expired, not-yet-valid, duplicate SAN, leaf e=3, leaf RSA-1024, sig flip, wrong anchor.
  - Frozen clock (`NOW=2026-06-14`) within the leaf's validity → the accept test stays green after
    the real leaf expires (committed `certs/leaf.der` is a frozen public fixture).

### Policy decisions made while building (oracle == device)
- **Exact SAN match only, wildcards NOT honored** — pinned host is fixed, real leaf carries the exact
  name; wildcard label-counting on a 16-bit MCU is pure attack surface.
- **Exactly-one-SAN gate** instead of general duplicate-OID rejection — the load-bearing
  parser-differential check, cheap on-device (count SANs), keeps oracle/device identical.
- **Unrecognized critical extensions: not rejected** — non-reachable threat under WR1-pin + exact host
  (attacker would already own api.openai.com); the allowlist would cost device code for no gain.

### gen-rsa-pinned-key.py — `--mode anchor` added
- New WR1/issuer anchor mode: splits the chain, pins cert[1] (WR1), emits **constants-only**
  `wr1_n/r2/one/n0inv` (no scratch — reuses the leaf-verify scratch; the two verifies never overlap).
  Generated `core/rsa_anchor_wr1.inc` (NOT yet `%include`d — that's the port).
- Leaf mode kept **byte-identical** (the shipped `rsa_pinned_key.inc` is untouched; regression diff
  clean). Closed the loop: `wr1_n` parsed back from the generated blob == WR1's real modulus, its
  Montgomery params check out, and the real leaf verifies against the blob-derived key.

### Net
The false-security crux is proven offline. No device code changed yet (CORE.SYS unaffected) — the
anchor `.inc` is generated but unwired. NEXT = Phase 2, the 286 port (see PARSER_CONTRACT.md
checklist): new module entry point, port the strict reader + positional walk, reuse `rsa_verify`
with WR1 constants, port the adopt math (n0inv Newton + r2 doubling), the recertify state machine +
`> recertify` line, fit the K window, then validate 286 @6/@8 + 8088/16K regression.

## Phase 2 — 286 port — NOT STARTED
