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

## Phase 2 — 286 port — IN PROGRESS

User picked "start the port now" + chose to set the clock from the network (HTTP Date header) into
the CMOS RTC so cert validity has a correct "now" (the VM clock is unreliable), and "scope an ECDSA
tier next" (captured in notes/ecdsa-tier-scoping.md).

### 2a — the strict-DER parser in asm — DONE, unicorn-green on the full matrix
`core/x509_verify.inc` (`x509_parse_leaf`): the strict TLV reader + positional Certificate/TBS walk
+ structural/policy gates (sigalg sha256RSA inner==outer, leaf RSA-2048/e=65537, exactly-one-SAN
with the exact host) + field extraction (tbs span, signature, leaf modulus, notBefore/notAfter).
The signature verify (vs WR1) and the validity-vs-RTC compare are the orchestrator's job, NOT the
parser's. Stack discipline: a BP frame so any reject is `mov sp,bp` (no per-site SP counting) +
balanced DER_DESCEND/DER_ASCEND macros on the happy path.

Offline-validated via unicorn (the project's pre-86Box rigor):
- `tools/crypto-bench/x509_bench_harness.py` assembles the REAL .inc + a caller, runs the parser on
  a cert in RAM, reads back accept/reject + the extracted field pointers.
- `tools/crypto-bench/x509_eval.py` runs it against the SAME 27 tamper vectors: **asm matches the
  oracle's parser-stage decision (parse_and_policy) on all 27**, and the asm-extracted TBS span /
  signature / modulus equal the oracle's on all 12 accept-vectors. Real leaf: tbs_off=4 tbs_len=1062
  sig_off=1086 mod_off=200, ~2462 instrs.
- Oracle refactor to stay faithful: parse extracts time STRUCTURE only (tag/len/Z); the date
  semantics (digit ranges) convert lazily in verify_leaf's RTC compare — matching the asm, which
  also leaves validity to the orchestrator. Added `parse_and_policy` (the parser-stage oracle).
  Tamper matrix re-run green after the refactor.

### 2b — the adopt math in asm — DONE, unicorn-green end-to-end
`core/rsa_adopt.inc` (`rsa_adopt`, in: SI = the 256-byte big-endian leaf modulus): byte-swap to the
128 LE limbs (rsa_n) + n0inv via 4-step Newton (16-bit) + r2 = 2^4096 mod n via 4096 modular
doublings. Installs rsa_n/rsa_n0inv/rsa_r2 = the new leaf, so the retry handshake's SKE verify uses
it (re-derived from WR1 each boot after a rotation; the floppy is read-only). CARRY DISCIPLINE: the
128-limb shift/subtract loops advance pointers with INC (preserves CF), never ADD.
`tools/crypto-bench/adopt_eval.py`: on the real leaf + 3 synthetic moduli, the derived n/n0inv/r2 all
match Python AND the strongest gate — running rsa_adopt then rsa_verify reproduces pow(sig,65537,n).
~3M instrs for the doublings (~2s @6, off-race, once per rotation — fine).

### 2c — the full chain-verify (standalone, asm) — DONE, unicorn-green
`core/x509_chain_verify.inc` (`x509_chain_verify`, in: SI=leaf DER, CX=len): x509_parse_leaf ->
SHA-256 over the captured TBS span -> load the baked WR1 constants -> rsa_pkcs1_verify. On accept,
x509_mod_ptr/nb_ptr/na_ptr are ready for the caller's validity-vs-RTC compare + rsa_adopt.
`core/rsa_pkcs1.inc` factors the EMSA-PKCS1-v1.5 reconstruct+256-byte-compare (+ the be<->LE
conversions) out of the shipped SKE path so both the in-race verify and the chain-verify share it
(the module's inline copy stays untouched for now; dedup happens at wiring time to avoid re-validating
the shipped path off-hardware). `tools/crypto-bench/chain_eval.py`: against the BAKED real WR1 anchor,
the real leaf ACCEPTS, and sig-bit-flip / TBS-tamper / non-WR1-CA / truncation all REJECT. ~7.1M
instrs (≈ one RSA verify ≈ 6.4s @6, off-race — fine).

### Trust core COMPLETE in asm + offline-proven: parse (2a) + adopt (2b) + chain-verify (2c).

### 2d-i — module wiring (the module now CONTAINS + EXPOSES the trust core) — DONE, 286 @8 greets
p256_module.asm gained 3 entry points + a fixed-offset result block; layout.inc the equates +
band-budget bump (24→26 sectors; loop cache is 27). Key low-risk move: `p256_ep_chain_verify_sig`
loads WR1 into the rsa_verify constants then `jmp`s into the SHIPPED, UNCHANGED SKE-verify routine
(it's modulus-agnostic), so no shipped crypto code was touched — only new entry points added:
- `p256_ep_parse_leaf` (+12): call x509_parse_leaf, copy the 6 field pointers to the result block.
- `p256_ep_chain_verify_sig` (+14): x509_load_wr1 (copy baked wr1_*→rsa_*) then jmp the SKE verify.
- `p256_ep_adopt_leaf` (+16): call rsa_adopt.
- result block at +18 (tbs_ptr/len, sig_ptr, mod_ptr, nb_ptr, na_ptr) for the resident orchestrator
  to read across the module boundary; build-asserted at offset 18.
%include'd x509_verify.inc + rsa_adopt.inc + rsa_anchor_wr1.inc into the module. (rsa_pkcs1.inc is
NOT in the module — the module reuses its own inline SKE verify; rsa_pkcs1.inc stays bench-only. A
future dedup could unify them, but that touches the shipped path → deferred.) Module 20→25 sectors
(878 B free in the 26 budget); check-layout OK; all offline evals still green. **286 @6 AND @8
BOTH GREET** (shipped flow unchanged, bigger module loads fine at both the knife-edge and the
comfortable clock = no regression). Big leaf-cert
RAM note: the leaf-capture buffer (~1.5 KB) can alias the top of the loop cache (p256_module_end,
above the 26-sector band, sectors 26-27) — handshake-only, 286-only, like the module itself.

### 2d-ii — resident orchestration (REMAINING — the flow that CALLS the entry points)
The shipped handshake DRAINS the Certificate into the 592 B tls_rx_copy and discards it
(tls.inc:tls_drain_server_certificate), so the leaf must be CAPTURED at drain time into a buffer
that survives to the off-race chain-verify. Then: on the in-race SKE verify failing
(tls.inc:2047, p256_ep_verify_ske_sig CF=1 = leaf rotated), run the off-race flow — call
p256_ep_parse_leaf(captured leaf) → resident SHA-256 over [result.tbs_ptr,len] →
p256_ep_chain_verify_sig(result.sig_ptr, hash) → validity-vs-RTC → p256_ep_adopt_leaf(result.mod_ptr)
→ retry the handshake (reuses the reconnect path) + the dim `> recertify` line (agent_endpoint.inc
`.render_dim_run` pattern). CAUTION: the resident K window has ~no slack — the orchestration code +
the result-readback live resident (they need sha256); measure the fit (golf if needed). This is the
intricate, shipped-path-touching, hardware-looped part.
- 2e network-time -> CMOS RTC (parse the HTTP Date response header) + the validity-vs-RTC gate (task
  7); cold-boot-before-first-response = validity best-effort.
- 2f K-window fit (golf -- 15 sectors, no slack) + hardware: 286 @6/@8 steady-state, a simulated
  rotation (pin an old leaf, present the real WR1-signed one) -> silent recertify -> greets; tampered
  -> reject; 8088/16K NIC-matrix regression. Read the FULL build output + confirm a fresh CORE.SYS
  md5 before any --no-build run.
