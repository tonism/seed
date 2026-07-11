# Auto-recertify — attempts / grind log

Plan: `notes/old/auto-recertify-plan.md`. Memory: `project_auto_recertify`. The goal: make a ~90-day
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
tier next" (captured in `notes/old/ecdsa-tier-scoping.md`).

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

**MEASURED GATE (2026-06-14): the K window has exactly 4 BYTES FREE** (15 sectors = 0x1800..0x3600 =
7680 B; trailing-zero bytes in CORE.SYS = 4). The leaf CAPTURE is unavoidably resident (it hooks the
resident drain) + the SKE-fail recertify trigger is resident — together ~50+ B that don't exist. So
2d-ii is BLOCKED on freeing resident bytes; genuine fork: (1) bit-exact golf ~50+ B out of the
K-window crypto (fragile — prior 74 B golfs flagged risky), (2) move a chunk of K-window code into a
demand-loaded phase to free resident space (architectural), (3) a leaner capture (minimum resident
footprint, stream to the high buffer). The orchestration BODY (parse→SHA→chain→adopt→retry) can be a
PHASE; only the capture + the fail-trigger are forced resident. This fit problem is the real 2d-ii
gate and wants careful, fresh attention.

**FIT LARGELY SOLVED (2026-06-14): the NUCLEUS has ~159 bytes free** (0x1000..0x1600 = 1536 B; last
nonzero at 1377; the 0x1600 active-driver slot is separately reserved). Put the capture ROUTINE
(~50-60 B) in the NUCLEUS (call it from the K-window drain via `phase_call_res`) and the
orchestration BODY in a PHASE — so the K window only needs the tiny CALL-SITE hook + SKE-fail
trigger. That cuts the golf from ~50-100 B of fragile crypto math down to **~10 B** of K-window hook
— far more tractable. Net 2d-ii: capture→nucleus; orchestration→a recertify phase; ~10 B K-window
golf; `> recertify` in the endpoint phase. Still intricate (fragmented-capture correctness, retry
wiring, rotation-sim hardware test, 8088 regression) but no longer fragile-crypto-golf-gated.
- 2e network-time -> CMOS RTC (parse the HTTP Date response header) + the validity-vs-RTC gate (task
  7); cold-boot-before-first-response = validity best-effort.
  **OFFLINE ORACLE DONE** (`tools/x509/http_date_rtc.py`, 2026-06-14, user said prototype it
  independently). Real header `Date: Sun, 14 Jun 2026 11:52:14 GMT` (RFC 7231 IMF-fixdate is
  FIXED-WIDTH → strict fixed-offset asm parse: month table + BCD). Produces the CMOS register writes
  (MC146818: 0x00 sec/0x02 min/0x04 hour/0x07 day/0x08 month/0x09 year, BCD via ports 0x70/0x71) AND
  the validity-compare spec: a byte-lexicographic `YYMMDDHHMMSS` compare of the RTC vs the cert
  notBefore/notAfter (real leaf window 260510011306..260808021049). 12 checks green incl. strict
  rejects (wrong zone/truncated/bad-month/non-digit/out-of-range → fail closed, clock stays unset).
  REMAINING (asm, integrates with 2d-ii): find "Date:" in the response (a phase in the response path,
  has room — not K-window-constrained), parse, write CMOS; the validity-vs-RTC compare in the
  recertify flow. The RTC SET (response path) and the RTC READ+compare (recertify) are decoupled.
### 2d-ii TURN-KEY EXECUTION PLAN (fully mapped 2026-06-14; every region located + sized)
Entangled + every-region-tight — best built mostly-whole and validated by the rotation-sim test
(below), with care to not regress the shipped @6/@8 greet. The pieces, with homes:
1. **Capture buffer** = `chat_arena_start` (~0x3dbf; on 32K the arena runs to loop_cache_start
   ~0x4400 = ~1.6 KB, EMPTY during the boot handshake; the ~1.3 KB leaf fits; 286-only, handshake-
   only, lifetime-disjoint with the chat). The captured leaf survives handshake-1's drain → the
   handshake-1 abort → `net_phase.retry` (nothing touches the arena in that path; the module reload
   at 0x4400+ is disjoint).
2. **Capture state** (recertify_needed flag, leaf_len, capture offset): need a home surviving
   drain→.retry. Reconnect-safe block (0x3c9c, tight — measure) OR a handshake-scratch var not
   clobbered between tls_probe-fail and .retry. ~5 bytes.
3. **Capture routine** → NUCLEUS (159 B free): 286-gated INTERNALLY (so each call site is a bare
   3-byte `call`), tracks the offset, skips the 6-byte cert framing (3-byte cert_list_len + 3-byte
   cert0_len), copies cert0 (the leaf) bytes to the arena bounded by cert0_len, across fragments.
   Reset at cert start. CAUTION: align EXACTLY to the drain's byte stream (tls.inc
   tls_drain_server_certificate: the initial tls_copy_current_payload + the .need_more loop) — the
   intricate correctness risk; the offsets must match what the drain sees.
4. **Drain hooks** (K window): a bare `call capture_leaf` at the drain points (~3-6 B). **SKE-fail
   flag** (K window): `mov byte [recertify_needed],1` at tls.inc:2047 CF=1 (~5 B). Total ~8-11 B in
   the 4-free K window → golf ~5-7 B (small; the stc;ret-consolidation route is blocked by short-jump
   reach, so hunt elsewhere — a redundant load/branch).
5. **Recertify orchestration** → a NEW PHASE loaded at .retry (room at 0x0700; calls K-window sha256
   + the module entries DIRECTLY like net_phase calls tls_probe, since both are loaded): parse
   (p256_ep_parse_leaf, captured leaf) → SHA-256 over [p256_x509_result_tbs_ptr,len] (K-window
   sha256) → p256_ep_chain_verify_sig(result sig_ptr, hash) → validity-vs-RTC (2e) → p256_ep_adopt_
   leaf(result mod_ptr). The orchestration could also live in net_phase (nucleus) but it + the
   capture routine together exceed the 159 free → put orchestration in the phase, capture in nucleus.
6. **net_phase.inc `.retry` branch** (net_phase.inc:80): BEFORE `dec reconnect_retries`, if
   recertify_needed: run the recertify phase (module still loaded from handshake-1's tls_client_hello
   at :65; leaf intact in the arena). Accept → clear flag, render `> recertify`, fall to retry
   (handshake-2 passes SKE with the adopted key). Reject → fail closed (continue to normal retry/fail).
7. **`> recertify` render** (endpoint phase, agent_endpoint.inc `.render_dim_run`): analogous to
   `> reconnect`; the text + a " done"/" failed" append.
8. **2e asm** (decoupled, oracle = tools/x509/http_date_rtc.py): in the RESPONSE path (a phase, has
   room) find "Date:" → fixed-offset parse → write CMOS (ports 0x70/0x71, BCD). The validity-vs-RTC
   compare (step 5) reads CMOS → YYMMDDHHMMSS → byte-compare vs notBefore/notAfter. cold-boot-before-
   first-response = validity best-effort (skip the gate if the RTC was never set this session).

### 2f hardware validation (the gate for the whole flow)
- **Rotation sim:** rebuild with a WRONG pinned leaf (`gen-rsa-pinned-key.py` from a different
  modulus into rsa_pinned_key.inc) so the real leaf's SKE sig fails the pin → recertify chain-verifies
  the real captured leaf vs WR1 → adopt → retry → **greet** (the silent re-pin). Then restore the pin.
- **Tamper:** present a leaf that doesn't chain to WR1 → recertify rejects → fail closed.
- **No-regression:** normal 286 @6/@8 greet (correct pin, no recertify path taken) + the 8088/16K
  NIC-matrix (the whole flow is 286-gated; the 8088 path is untouched).
- **GUARDRAIL: full build output + fresh CORE.SYS md5 before any --no-build run.**

## Phase 2 LIVE INTEGRATION (2026-06-26) — flow fully wired; rotation-sim fails, debugging next

COMMITTED + working: the capture (offline byte-exact + runs live during the real drain; 286 @8 greets,
no regression). ec979f4 / b186d47 / 2c88856. The no-op at tls.inc .need_more (read+write-back-same)
was removed to fund the ~9 K-window bytes for the two drain hooks (call a resident 286-gated trampoline
secure_capture_chunk -> the module's capture_leaf_chunk).

UNCOMMITTED (builds clean, correct pin = f3a984d4, nucleus 1496/1536; correct-pin path UNAFFECTED —
the recertify code is dormant when the in-race pin verify passes): the recertify trigger in
net_phase.inc `.retry` — recertify_prep -> SHA-256(TBS, resident K-window) -> chain_verify_sig (vs the
baked WR1) -> save the leaf modulus ptr + recert_flag (data.inc, reconnect_state block) -> re-adopt
before tls_probe (the module reload reverts rsa_n, so re-install). recert_flag boot-zeroed in
hardware_setup (a phase, not the nucleus). Two bugs found + fixed en route: (1) the module reload each
connect wiped the in-.retry adopt -> moved to a pre-tls_probe re-adopt from the saved modulus ptr
(which points into the still-resident captured leaf in the arena); (2) that overflowed the nucleus by
5 B -> moved the recert_flag zeroing to the hardware_setup boot-zero.

ROTATION-SIM (the validation) STILL FAILS: pin a WRONG (synthetic) leaf so the real leaf fails the
in-race pin verify; expect recertify -> greet. Result: "agent setup failed" net_error=0x0D
net_status=0x12 (18 = tcp_connected; the handshake fails in TLS and recertify does NOT rescue it).
The recertify path runs but something in it isn't succeeding. NEXT = net_status-milestone debug of the
.retry recertify (add a milestone after recertify_prep [leaf captured? capture_leaf_len!=0], after
chain_verify [sig chains to WR1 on-device?], after the re-adopt), boot the wrong-pin sim, read which
step it reaches. Likely culprits in order: the ON-WIRE capture (offline-proven with a constructed cert,
but the real fragmented drain may differ -> capture_leaf_len=0 -> recertify_prep CF=1 -> no recertify);
the on-device chain-verify; the re-adopt. ALSO: the arena leaf must survive .retry->the pre-tls_probe
re-adopt — agent_request builds in api_request_plain (0x3912), NOT the arena, so it should (for the
cold-boot first greet). Multi-turn needs the real capture home (task 12).

ROTATION-SIM PROCEDURE: `cp .../rsa_pinned_key.inc /tmp/...real`; WRONG=$(python3 -c "import sys;
sys.path.insert(0,'tools/x509'); import der_build; n,_,_=der_build.gen_rsa(2048,seed=0xBADB10C);
print(hex(n)[2:])"); `gen-rsa-pinned-key.py --modulus $WRONG --out .../rsa_pinned_key.inc`; make;
`run-286-86box.py --speed 8 --timeout 135`; RESTORE the real pin after.

## Phase 2 UPDATE (2026-06-26 cont.) — module path PROVEN; bug is the net_phase integration

Found + fixed a REAL bug the offline chain_eval couldn't catch: the module's p256_ep_chain_verify_sig
did `call x509_load_wr1` (whose rep movsw CLOBBER SI/DI) then `jmp p256_ep_verify_ske_sig_impl` (which
needs SI=sig, DI=hash) -> it verified garbage. Fixed by push/pop SI/DI around x509_load_wr1.
(chain_eval tests x509_chain_verify.inc, which reloads SI/DI after load_wr1, so it never hit this.)

New harness `tools/crypto-bench/recertify_eval.py` drives the REAL module .bin's entry points
(capture_reset/chunk -> recertify_prep -> chain_verify_sig) exactly as net_phase does, full visibility.
**ALL GREEN**: module capture == leaf.der, recertify_prep parses, result TBS span correct, and
chain_verify_sig CF=0 (chains to WR1, with the SI/DI fix). So the MODULE LOGIC IS PROVEN CORRECT.

But the hardware rotation-sim STILL fails (net_error 0D / net_status 18). 18=tcp_connected is the
handshake's last milestone and the clean recertify code doesn't touch net_status, so 18 is
UNINFORMATIVE about recertify. The bug is in the net_phase INTEGRATION that recertify_eval doesn't
replicate: the resident SHA-256(TBS) call (net_phase -> K-window sha256) and/or the pre-tls_probe
re-adopt (attempt 2). Localizing needs net_status milestones IN the .retry recertify -- but those
OVERFLOW the nucleus (the orchestration already fills it; the re-adopt fix was tight; +debug = +28 B).

NEXT (the unblock): MOVE the recertify orchestration (recertify_prep -> SHA -> chain_verify -> save)
OUT of net_phase (nucleus) INTO A PHASE -- (1) frees the nucleus (it's for the hot path, not a
between-handshakes op), (2) gives room for milestone debug. The phase loads at .retry (between
handshakes, floppy-OK) and calls K-window sha256 + the module entries directly (both loaded). Then
add milestones in the phase, boot the wrong-pin sim, localize the SHA/re-adopt bug, fix, greet.
The arena-as-temporary-capture-home still holds for the cold-boot first greet (agent_request builds
in api_request_plain, not the arena); the real home is task 12.

COMMITTED state: capture (ec979f4/b186d47/2c88856) + this WIP (SI/DI fix + the net_phase orchestration
+ re-adopt + recertify_eval). Builds green (correct pin), correct-pin path unaffected (recertify
dormant on a pin match). Rotation-sim pending the orchestration->phase + integration debug.

## Phase 2 UPDATE #2 (2026-06-26) — recertify CORE proven; blocker is the 286-secure RECONNECT (post-SKE)

Decisive debug pass. Added a TEMP net_status terminal in .retry (drops the re-adopt to fit the nucleus):
boot showed **net_status 0x43** = recertify_prep OK (0x41) AND chain_verify OK (0x43) ON HARDWARE. So
the recertify core (capture -> parse -> SHA(TBS) -> verify-vs-WR1) WORKS on the 286. recertify_eval
also now checks result_mod_ptr survives chain_verify (PASS, 0x28c8 before+after).

Tried TWO independent pin-restoration mechanisms for the retry:
  1. save+re-adopt (committed 250c21b): save result_mod_ptr in .retry; re-adopt pre-tls_probe after
     tls_client_hello reloads the module.
  2. skip-reload (experiment): adopt in .retry, gate tls_client_hello's module reload on recert_flag so
     the adopted pin survives (no fragile arena pointer).
BOTH fail IDENTICALLY at attempt 2's TLS: net_error_tls(0x0D) / net_status_tcp_connected(0x12=18, the
generic "TCP up, handshake failed"; tls_fail_error->net_fail_al sets only net_error, not net_status).
That two-different-mechanisms-same-failure is the tell: **the bug is NOT the pin mechanism -- it's
attempt 2's handshake itself = the 286-secure RECONNECT path.** Recertify just happens to be the first
thing that exercises a 286 secure reconnect.

RULED OUT (by reading + offline proof):
  - reconnect double-send: .done clears tls_app_len and the 286 path reaches .done (tls.inc:127-138).
  - stale keys: tls_transcript_start (tls.inc:463) zeroes tls_key_schedule_ready, and tls_probe calls
    it first (line 6), so attempt 2 re-derives fresh keys (the line-78 reuse-skip never triggers).
  - mod_ptr clobber: recertify_eval confirms result_mod_ptr survives chain_verify.
  - bad adopted rsa_n: adopt_eval proves adopt->rsa_n does correct modexp (s^e mod n reproduces the
    modulus == a correct RSA verify). So attempt 2's SKE verify SHOULD pass (rsa_n=leaf is correct).
=> by elimination the failure is POST-SKE in attempt 2's handshake (ECDHE premaster / master / key_block
   / Finished / app) -- a reconnect issue, NOT recertify. [NB: "SKE passes" is an INFERENCE; the
   hardware milestone that would confirm it OVERFLOWS -- see below.]

INSTRUMENTATION WALL: both the resident nucleus AND the K crypto window are MAXED (the 286 secure tier
left no slack). A net_status milestone in .retry overflows the nucleus (>1536); even ONE 5-byte
milestone in tls_probe overflows the K window ("LINK window overlaps high crypto scratch"). So hardware
step-localization needs room first.

NEXT (the real question -- does a 286 secure reconnect work AT ALL, independent of recertify?):
  (a) host WIRE CAPTURE: `sudo tcpdump -i <iface> host <api.openai.com ip> and port 443 -w cap.pcap`
      during a wrong-pin sim. Plaintext handshake msgs localize attempt 2's break: no ClientKeyExchange
      after the SKE = SKE-verify fail (wrong rsa_n, contradicts adopt_eval); CKE-then-Alert/FIN = post-
      SKE. (App data is real-ECDHE-encrypted, but the handshake frames + the RST/Alert are plaintext.)
  (b) free K-window/nucleus room (golf) for a single milestone -- risky on a maxed layout.
  (c) move the recertify orchestration to a PHASE to free the nucleus (orthogonal cleanup; doesn't help
      the K-window milestone, which is where the post-SKE step lives).
Committed base = 250c21b (save+re-adopt, degrades gracefully). The skip-reload experiment is reverted
(it crashes multi-turn: post-greet the loop cache overwrites the never-reloaded module).

## Phase 2 ROOT CAUSE (2026-06-26) — it's a pre-existing COLD-RECONNECT bug, NOT recertify

WIRE CAPTURE (host tcpdump on SLiRP, tools/analyze-tls-pcap.py parses it) settled it. The seed sent
EXACTLY ONE ClientHello (attempt 1 -> 162.159.140.245, ServerHello/Cert/SKE/ServerHelloDone then NO
ClientKeyExchange = SKE-verify fail on the wrong pin, exactly as expected). The other 3 "api.openai.com"
SNIs in the 24 MB capture are the host's own apps (no 0xcca8 fingerprint). So **attempt 2 NEVER
re-handshakes** -- my "post-SKE" inference was WRONG. The retry dies in SETUP.

net_status milestones (in the PHASES, which have room -- unlike the maxed nucleus/K-window) walked it
back: attempt 2 reaches agent_request (0x84) and fails INSIDE it, before any net_status write. The only
agent_request failure that leaves net_status untouched is `.selected_agent_is_openai` (it checks
seed_agent_id spells "openai", no net_status on fail). Capturing seed_agent_id[0] on that failure showed
**0x6A ('j'), not 0x6F ('o')** -> seed_agent_id is CLOBBERED between attempt 1 and attempt 2.

WHY: `seed_agent_id equ hmac_prepared_outer_state + (16*2)` (data.inc:298). **The seed_* config block
(agent_id 0x3b1f / model 0x3b2b / key 0x3b6b / endpoint 0x3c2b) OVERLAYS the TLS HMAC/PRF crypto
scratch.** sha256.inc:260 writes hmac_prepared_outer_state on every PRF/HMAC during the handshake, so
attempt 1's handshake clobbers the config. attempt 1's agent_request read it intact BEFORE the
handshake; the cold-reconnect attempt 2 re-reads it AFTER -> "openai" check fails -> agent_request
returns CF -> .restore. NO reconnect. The recertify CORE is fine (already proven 0x43 + recertify_eval);
it just can't complete because the cold-reconnect path it triggers is broken.

KEY INSIGHT: the WARM/mid-chat reconnect (handoff_status==ready) takes a DIFFERENT agent_request path --
it SKIPS .selected_agent_is_openai (line 17 `je .session_ready`) and reuses chat_key_cache /
chat_model_cache (safe copies, not the clobbered seed_*). So a **mid-chat** leaf rotation would recertify
+ reconnect fine; only the **cold-boot** rotation-sim hits this. (Reasoned, not yet HW-confirmed -- a
mid-chat sim is the confirm.)

This is INDEPENDENT of recertify -- ANY cold reconnect (not just a rotated-leaf one) re-reads the
handshake-clobbered config. It was latent because the cold greeting normally succeeds (config read once,
before the handshake) and a cold-greeting FAILURE historically went straight to the fatal screen; the
recertify is the first thing to systematically retry a cold connect.

FIX OPTIONS (genuine design fork -- pending user):
  (a) Cache the cold-path config (agent_id/key/model) into a safe region on the FIRST connect (gated on
      reconnect_retries==3, before the handshake) + have the cold reconnect read the cache. Mirrors the
      warm path's chat_*_cache.
  (b) Re-load the config (re-run the agents_cfg/agent_setup phase) at the top of .rebuild_and_connect.
  (c) Move the seed_* config OUT of the crypto-scratch overlay (root fix; needs RAM on a tight layout).
  (d) Accept it: recertify works mid-chat (confirm with a mid-chat sim); treat the cold-reconnect
      config-clobber as a separate robustness item.
Tree reverted to the committed 250c21b base (builds green, correct-pin 286 greets, no regression). New
tool tools/analyze-tls-pcap.py (pure-Python pcap + TLS-handshake walker, no deps).

## Phase 2 DONE (2026-06-26) — AUTO-RECERTIFY GREETS END-TO-END ON HARDWARE

The cold-reconnect bugs the rotation-sim surfaced are both fixed, and the wrong-pin sim now GREETS:
  1. CONFIG CLOBBER (cache-reuse fix, agent_request.inc + agent_cache.inc): on a cold RECONNECT
     (reconnect_retries<3) agent_request now reuses chat_key_cache/chat_model_cache (safe copies the
     handshake never touches -- they sit above the critical-scratch tail) and SKIPS the redundant
     .selected_agent_is_openai recheck (seed_* overlays the TLS PRF scratch and is handshake-clobbered;
     the agent was already validated on attempt 1). agent_cache also skips re-parsing on a cold reconnect
     (cache already valid from attempt 1). The first connect (retries==3) is byte-unchanged.
  2. STALE RX RING (RX-flush fix, tcp_connect.inc): the cold reconnect re-does full ARP but didn't flush
     the RX ring first (the warm reconnect's tcp_reopen_cached_target already does), so the re-ARP's
     reply landed behind attempt 1's leftover handshake frames and was missed (net_error_arp 09 /
     arp_request_sent 0A). Added ne_flush_receive_frames before the cold tcp_connect_target on a
     reconnect (gated reconnect_retries<3). First connect unchanged (boot ring is clean).
Both were PRE-EXISTING cold-reconnect bugs, latent because a cold-greeting failure historically went
straight to the fatal screen -- recertify is the first thing to systematically retry a cold connect.

VALIDATED on hardware (all 286 @8 unless noted):
  - WRONG-pin rotation-sim -> recertify -> cold reconnect -> **GREETS** ("seed build 12" + the greeting).
    The full silent re-pin works: rotated/stale leaf -> SKE verify fails -> chain-verify the real leaf
    vs the pinned WR1 (off-race) -> adopt -> reconnect+re-handshake -> greet. (The 09/0A ARP failure was
    confirmed deterministic across a re-run before the flush fix.)
  - CORRECT-pin 286 -> greets (recertify dormant; no regression on the normal secure path).
  - 8088 ne2k8 (16K) -> greets with the dim "insecure" splash (shared agent_request/agent_cache/
    tcp_connect path unaffected; the gates skip on the first connect). Other NIC families pending a
    broader matrix pass, but the first-connect path is byte-identical so regression risk is ~nil.
Fail-closed (a leaf that does NOT chain to WR1 is rejected) was already proven offline (tamper matrix)
+ on hardware (the Build-12 1-bit-tamper REJECT); the recertify reuses that same chain-verify.

Committed on work/scaling: 250c21b (flow) + 1db972a (eval) + c825daf (root cause) + this commit
(the two cold-reconnect fixes). NOT pushed (user does the single push). Remaining polish: the dim
`> recertify` mid-chat status line (cosmetic), the captured-leaf's real (non-arena) home (task 12),
and a full 7-NIC 8088 matrix pass for completeness.

## Phase 3 (2026-06-26) — streaming leaf capture (task 12: mid-chat-safe home), DESIGN + OFFLINE-VALIDATED

Goal: stop buffering the whole ~1.3 KB leaf in the arena (a mid-chat recertify clobbers the live
conversation). Instead, as the cert streams off the wire, hash the TBS incrementally and keep only the
two fields we can't recompute -- modulus (256 B) + signature (256 B) = 512 B -- in a small
handshake-transient slot (NOT the arena), so mid-chat is safe.

Real-leaf structure (tools/crypto-bench shows): leaf 1342 B; TBS element = leaf[4 .. 8+tbs_clen]
(tbs_clen from leaf[6:8]); modulus = the UNAMBIGUOUS `02 82 01 01 00` INTEGER (exactly 1 in the leaf,
followed by `02 03 01 00 01` e=65537); signature = after the TBS + the short-form sha256RSA sigAlg
SEQUENCE + the `03 82 01 01 00` BIT STRING. The chain-verify (sig over SHA(TBS) vs WR1) authenticates
the whole cert; the modulus is extracted from that authenticated TBS, and any extraction error fails
closed (attempt-2 SKE verify fails) -- a MITM can't exploit it (their leaf won't chain to WR1).

OFFLINE-VALIDATED: tools/crypto-bench/streaming_eval.py models the streaming extraction (fragment the
cert, carry state across chunks) and proves sha/modulus/sig MATCH a full parse on: the real leaf @
592/256/1500-byte frags; 3 rotated synthetic leaves (different keys + subject lengths -> different
modulus offsets, 705-819 B); and a tampered byte changes the hash (verify rejects). ALL GREEN.

ASM PLAN (x509_capture.inc rewrite, the next focused effort -- a rigor-sensitive cross-fragment state
machine, so kept separate from the now-committed cold-boot win):
  1. Read tbs_clen from the TBS header (first fragment) -> the TBS span; sha256_init when the TBS starts.
  2. Per fragment: sha256_update the TBS-overlap span; roll a 5-byte window scanning for `02 82 01 01 00`
     (within the TBS) -> capture the next 256 B (modulus), carrying the capture across fragments; after
     the TBS, skip the sigAlg + BIT-STRING header and capture 256 B (signature), carrying across frags.
  3. The recertify path (net_phase.retry) uses the streamed SHA + captured modulus/sig directly --
     recertify_prep's full-leaf parse is dropped (the parse work moved into the streaming capture).
  4. leaf_capture_buf: 512 B in the loop-cache tail (p256_module_end..loop_cache_end), 286/handshake-
     transient, NOT chat_arena_start -> mid-chat safe (the arena was the TEMPORARY validation home).
  5. Validate: extend recertify_eval to drive the streaming capture (oracle-gate) THEN hardware
     (rotation-sim greets + correct-pin + 8088 + a mid-chat reconnect leaves the conversation intact).

## Phase 3 DONE (2026-06-26) — mid-chat-safe leaf home, via RELOCATE (simpler than the streaming plan)

The streaming design (Phase 3 above) turned out HARDER than it looked (a streaming X.509 parser + a
second SHA context juggled against the handshake transcript SHA = handshake-corruption risk, on a maxed
layout). A much simpler path achieves the same goal -- and it's what I shipped:

  1. SHRINK THE WR1 ANCHOR to just wr1_n (256 B). The baked wr1_r2/wr1_one/wr1_n0inv (~514 B) are gone;
     x509_load_wr1 now copies wr1_n -> rsa_n, sets rsa_one=1 (the shared constant), and jumps to a new
     `rsa_adopt_derive` entry (rsa_adopt minus the byte-swap) to compute r2 + n0inv on the fly. ~2s, fully
     off-race. (rsa_adopt_derive is the proven adopt math; adopt_eval still green.)
  2. That frees the module to 24 sectors (12100 B, was 12634) -> the slot above it in the loop cache
     grows to 1536 B >= the leaf (1342).
  3. leaf_capture_buf moves from chat_arena_start to the TAIL (p256_module_load + p256_module_max_len ..
     loop_cache_end). MID-CHAT SAFE: every 286 connect's tls_client_hello sets loop_cache_count=0 (the
     chat loop then demand-loads), so the cache tail there -- including prompt_id_cache/prompt_compact_
     cache -- is already invalid when the capture overwrites it; the live conversation arena is untouched.

No streaming parser, no dual-SHA, full rigor preserved (the same x509_parse_leaf + chain-verify, just
relocated; the SAN check is intact). streaming_eval.py is kept as a documented fallback if the module
ever outgrows the slot.

VALIDATED: offline recertify_eval + chain_eval (real leaf ACCEPT, every forgery REJECT, via the DERIVED
WR1 constants) + adopt_eval all green; hardware 286 @8 wrong-pin rotation-sim GREETS (leaf in tail +
adopt-derived WR1), correct-pin 286 GREETS, 8088 ne2k8 GREETS w/ insecure splash -- no regression. The
chain_eval bench needed rsa_adopt.inc included + rsa_one=1 set in x509_load_wr1 (the module bakes
rsa_one; the bench didn't). Task 12 (captured-leaf real home) = DONE.

## Recertify-polish: the dim `> recertify` status line (2026-06-26) — DONE + validated

The orchestration (recertify_prep -> SHA -> chain_verify -> save mod_ptr + recert_flag in net_phase
.retry) + the pre-tls_probe re-adopt were already wired; the remaining UX piece was the status line so
the user SEES a silent re-pin happen. Added to the endpoint phase (agent_endpoint.inc), the first phase
re-run on .rebuild_and_connect, so the line lands BEFORE attempt 2's crypto:
  - new `.render_recertify` branch gated on `recert_flag` (set in net_phase when a captured leaf chains
    to WR1), checked just AFTER the retries==0 "failed" gate and BEFORE the "> reconnect" logic, so a
    recert overrides the reconnect line.
  - new string `recertify_msg_text db '> recertify'` (recertify_word_len=11). EXACTLY 11 chars == the
    "> reconnect" line, so on a MID-CHAT recert it cleanly overwrites the earlier "> reconnect" on the
    same row (reads as reconnect->recertify transitioning, not two stacked lines). On a COLD recert
    (handoff not ready) no "> reconnect" was drawn, so it's a clean single "> recertify".
  - on exhaustion the shared retries==0 path appends " failed" to whatever is parked -> "> recertify
    failed" if the parked line was the recert one. No new failed-string needed.
Endpoint phase fit (clean build, check-layout OK 17 bands / 19 overlays; CORE.SYS 66dff81b, 42496 B).

VALIDATED against the fresh real-pin binary (all 286 @8 / 8088 ne2k8):
  - ROTATION-SIM (wrong baked pin): dim "> recertify" renders top-left -> "seed build 12" -> greet. The
    new line works end-to-end (attempt 1 fails on the wrong pin -> off-race chain-verify accepts the
    captured leaf -> recert_flag set -> "> recertify" -> attempt 2 greets).
  - CORRECT-PIN 286: NO "> recertify" (recert_flag stays 0 -> the cmp/jne is inert) -> normal greet. The
    added instruction is confirmed inert on the hot path when the pin matches.
  - 8088 ne2k8: NO "> recertify" (the recertify orchestration is 286-gated, recert_flag never set) ->
    insecure splash + greet. No 8088 regression on the shared endpoint phase.

NB a TRUE mid-chat rotation sim can't be authentically staged: the pin is baked at build time, so the
device can't "rotate" it between connects at runtime, and a wrong baked pin fails the cold connect too
(can't first-greet to get mid-chat). But the .retry recert path is IDENTICAL cold vs mid-chat (gated on
recert_flag, not handoff_status); the only mid-chat delta is "> reconnect" drawn at attempt 1 then
overwritten, + the chat-history-survives concern, which is the existing reconnect machinery (recertify
touches only recert_flag/recert_mod_ptr/the leaf buffer, never the in-RAM history). So the cold sim
covers the render + mechanism; mid-chat history-survival is inherited. Task 10 (> recertify render) = DONE.

## @6 RECERTIFY FIXED — two reconnect bugs the hang masked (2026-06-27; 3616a4e)

The @6 rotation-sim hung (dim 'o', no greet/fatal even at 540s); @8 greeted, and the @6 secure TIER
(correct pin) greeted — so it was NOT the crypto budget. Method: short-circuit bisection (same-size
`stc;ret;nop` patches to skip a routine and watch the hang move) + a host wire-capture (sudo tcpdump on
the SLiRP egress, walked by tools/tls-flow.py, which prints per-connection "server sent CCS+Finished?").

(1) cx-clobber (the HANG). Every receive/timeout path was bounded, yet it hung. Bisection put it in
tls_read_server_finished_with_retry's resend. `tls_resend_second_flight` does `mov cx,[tls_stream_skip_
remaining]` — clobbering CX, which IS with_retry's retry counter; the pre-fix `pop cx` ran BEFORE the
resend, so after it CX was the flight length, not the countdown -> the loop never hit 0 -> infinite
resend+read on ANY lost server-Finished. Hit @6-reconnect: the slow first read fails -> resend -> clobber.
@8 greeted because the Finished arrived on the first read (no resend). Fix: keep the counter on the stack
across the resend (now bounded 3x). Helps all configs.

(2) re-adopt-in-window (the NO-GREET). With (1) fixed it failed gracefully (fatal screen) but still didn't
greet. Wire @6 (CONN 2 = attempt 2): ClientHello at +3.3 s after the SYN (vs attempt 1's +0.1 s), client
CCS+Finished at +16.6 s, server FIN at +15.0 s -> RST. The ~3.3 s pre-ClientHello gap was the leaf
re-adopt: rsa_adopt_derive (R^2 mod N for the recertified modulus) ran between tcp_connect (SYN) and
tls_probe (ClientHello), INSIDE Cloudflare's ~15 s window. Fix: moved the re-adopt (net_phase.inc) before
tcp_connect -> ClientHello prompt -> Finished fits -> server completes -> greet.

Validated @6: recertify greets, secure-tier greets; @8 recertify greets (no regression). montsqr (RSA
squaring) + #21 (loading-silent "> recertify", gate chat_context_used>0 not handoff_status) landed
alongside. Commits 3616a4e / 81e8a69 / 9b1d781 on work/scaling.
