# Build Scope

Status: latest tagged release is Build 11 (release hardening: draining-FIFO transport, robust
reconnect, real LLM compaction, ESC-to-interrupt, tool-directive rendering), `build-11`. Build 12 —
the capability-tiered memory-layout redesign **and the 286 secure tier** (real ECDHE + pinned-key RSA
cert auth, with silent re-pinning on leaf rotation) — is built and validated on `work/scaling`, not
yet tagged. See the build sections for shipped features and "Forward-looking ideas" for the backlog.

Seed's loading marker has four semantic states plus the final splash:

```text
none         boot sector, loader, CORE.SYS load
"." dark     hardware then internet: CORE.SYS entry, display baseline, hardware detection, adapter init, handoff, then IP configuration, DNS, and reachability proof
"o" dark     TLS handshake: selected endpoint setup and the TLS 1.2 handshake
"o" normal   local crypto: TLS key schedule and key-material derivation
"o" bright   agent/environment: API validation, model/session, and environment handoff
splash       ready handoff animation; no loading work happens here
```

`retry` returns to the dark `"."` hardware phase; it does not reread floppy sectors or rerun the
boot-sector/loader path. A build maps to a user-visible readiness goal — it can be larger than its
internal checkpoints, and commits inside it can still be small.

## Current Map

```text
build 1   boot floppy proof
build 2   minimal boot presentation: centered marker and fast-type banner
build 3   no-marker bootstrap: loader boundary, display baseline, handoff block, retry boundary
build 4   "." dark phase: hardware setup, adapter autodetect/fallback questions, hardware handoff
build 5   internet readiness under the "." phase: IP config, DNS, reachability proof
build 6   "o" dark + normal + bright phases: TLS handshake, credentials, minimal provider API proof
build 7   ROM BASIC 16 KiB entry and windowed-nucleus release target
build 8   Default Prompt Interface chat loop
build 9   minimal context management for agentic continuity
build 10  minimal tool calling through controlled RAM access
build 11  release hardening: FIFO budget, robust reconnect, real compaction, ESC, tool-directive rendering
build 12  capability-tiered layout (one CORE.SYS, NIC HAL, 32K floppy-free loop, 2-image) + 286 secure tier (real ECDHE + pinned RSA cert auth, auto-recertify)
```

Builds 1–4 are the boot-presentation and hardware-setup milestones listed above; the substantive
builds get a short section each below.

## Build 5 — internet readiness

Brings the network up from cold and proves outbound reachability without starting TLS (the dark
`"."` phase). Intentionally broad: NE-family packet init, Ethernet TX/RX, DHCP (discover/offer/
request/ack plus subnet/router/DNS capture), DNS-server ARP, DNS A-resolution of the `NET.CFG`
probe host, subnet-aware next-hop ARP, and a TCP connect to port 80. Validated across the 5150 NIC
families: 3c501, 3c503, NE1000/NE2000, Novell NE1000, WD8003.

## Build 6 — TLS handshake + minimal provider API

Connects to a selected provider and completes a minimal request/response (the `"o"` phases). From
the FAT12 floppy + CORE.SYS: agent config (AGENTS.CFG, built-in openai/anthropic/google, USER.CFG
for secrets), DNS + TCP 443, a hand-rolled TLS 1.2 ClientHello (P-256 ECDHE / ChaCha20-Poly1305),
the full handshake through ServerHelloDone, 8086 P-256 field/point/scalar primitives (OpenSSL-cross-
checked), a SHA-256 transcript + TLS-PRF key schedule, ChaCha20-Poly1305 records, and a minimal
OpenAI Responses request that returns `ok`. Validated on all seven 4.77 MHz NIC profiles.

Honest caveat: this path substitutes a scalar-1 stub for the ECDHE scalar (the premaster
becomes the server's public X), so no real key agreement runs — fast boot, not a secure channel.
Closed at the 286 in Build 12 (real ECDHE + pinned-key RSA cert auth, silent re-pin on leaf
rotation); the stock-8088 floor stays this way.

## Build 7 — 16 KiB entry contract

The same floppy supports two entry modes: ≥32 KiB BIOS-boots CORE.SYS directly; below 32 KiB the
user types a generated ROM BASIC sidecar helper that loads the same CORE.SYS. One image, one visible
`CORE.SYS`, one code path after entry. Implemented as a windowed nucleus — a tiny resident control
plane plus reloadable cold/post-answer windows, with one no-floppy provider-critical window held
from TLS start to the answer. Validated: all seven 16 KiB BASIC-sidecar NIC profiles returned `ok`;
no-card CGA/MDA profiles fail cleanly. (Literal 24 KiB 86Box 5150 profiles stop in POST before ROM
BASIC, so 16 KiB is the release entry target.)

## Build 8 — Default Prompt Interface

The first usable chat loop on the 16 KiB entry: an initial model greeting, a `">"` prompt, bright
user text / normal model text, readable streamed responses, and multiple turns per boot session.
Each prompt may still be a fresh request (no semantic context yet); no tool calling. Validated 7/7
NICs across multi-turn short / long / idle-reconnect runs; the long-render flake was fixed with
keep-alive reuse + a completion fallback. DPI is a disposable starter interface, not the final
user/agent environment.

## Build 9 — minimal context management

Gives continuity across turns without a writeable boot medium. Each request is four layers: identity
(static, on the floppy) + ledger (machine facts from the handoff block) + conversation (a
model-compacted rolling window) + the current prompt. The request streams as chunked TLS records so
the prefix needn't fit one send buffer; the conversation is compacted by the model (never local
heuristics), reconnect-safe in RAM reclaimed from the stack reserve, and shares that pool with a
user/agent arena. The model is held to plain ASCII (the CP437 terminal can't render UTF-8). Validated
7-NIC: recall survives a compaction collapse, and the keep-alive held a 20-minute render.

## Build 10 — minimal tool calling

The first controlled tool surface, on top of the Build 9 context path:

```text
$r ADDR LEN   - read up to 32 B of RAM (seg 0); the bytes flow back into the window
$w ADDR BYTES - write RAM (seg 0)
$x ADDR       - CALL a seg-0 address; AX/CF flow back into the window
RAM detection - int 0x12 in the loader, so the pool scales with the machine (~49 KiB at 64 KiB+)
arena advert  - the ledger carries a@ = the free seg-0 arena base for a safe $w + $x
agentic loop  - a fired tool auto-continues (capped at 8 hops), then control returns to the user
```

Validated 7/7 NICs, and the capstone: the model wrote `b8 34 12 c3` (`mov ax,0x1234; ret`) into the
arena, ran it with `$x`, and read back `AX=0x1234`. `$x` is a bare CALL with no sandbox — the agent
owns the crash, reboot from trusted media recovers (Authority Model / Recovery Boundary).

## Build 11 — release hardening

Hardens the first public release on top of Build 10. The FIFO redesign led — it freed the memory
budget the rest depended on.

```text
draining-FIFO receive + RX shrink - one streamed receive path keeping incremental per-record
  Poly1305 (app-data stays MAC-verified) + an RX-buffer shrink 1460->592 via a SYN MSS option.
robust reconnect - one dim "> reconnect", up to 3 silent rebuilds, then "> reconnect failed" + a
  soft-fail to DPI. Root-caused the idle-close asymmetry to a chunk-1 double-send and fixed it.
real LLM compaction (note-as-memory) - a model-maintained terse note + a verbatim recent-dialogue
  tail replaces the sliding-window trim; static prompts stream off the floppy. Fixes small-machine amnesia.
ESC to interrupt - single ESC gracefully stops a render ("> stopped"); Ctrl+ESC hard-escapes
  ("> panic stopped", reconnect next turn). An int 9 hook gated on a live DPI.
history-echo - the carried window stores each turn role-labeled (" User: .. You: ..") so the model
  tells its own prior answers from user text.
tool-directive rendering - a '$' renders DIMMED (not hard-cut) and only when it starts a line, matching
  a whole-line execution gate (runs only if the line is just the directive). Multiple directive lines run
  in order; in-sentence mentions stay inert prose.
```

Validated 7/7 NICs (boot+greeting) on the final transport state; the compaction, ESC, and
tool-directive paths deep-validated on ne2k8 @ 16K/32K with wd8003e + 3c501 spot-checks. Working
record in `notes/build11-hardening-attempts.md`.

## Build 12 — capability-tiered layout + the secure tier

A RAM-layout redesign that lets one `CORE.SYS` scale from the 16 KiB floor up to the 286 — and, on
the headroom it buys, makes the channel genuinely secure on a 286.

```text
capability-tiered layout - one CORE.SYS, two build-time-fixed layouts dispatched through vectors;
  lifetime-ordered bands + a reconnect-safe block; layout.inc is authoritative and tools/check-layout.py
  enforces it on every build. Fast crypto is the 16K baseline (the slow path deleted).
NIC HAL - a boot-populated dispatch vtable + four floppy-loaded driver modules (ne / wd8003 / 3c503 /
  3c501); only the detected family loads into a resident slot, so inactive drivers cost 0 RAM.
32K floppy-free chat loop - the K window + identity/compaction prompt streams preload into a high cache,
  so per-turn floppy I/O drops ~25 -> 0 sectors. The 16K floor still demand-loads.
two-image build - 160K (headline) and 360K (for the 286) from one CORE.SYS that auto-detects floppy
  geometry from the boot-sector BPB. Seed boots on the 286.
286 secure tier - real ECDHE key agreement (optimised constant-time P-256) + RSA-2048 server-cert auth
  against a pinned api.openai.com key; a 286-only handshake module overlays the 32K loop cache (0 resident
  RAM on 16K). A pre-286 machine shows a dim "insecure" splash.
auto-recertify - silent re-pin on leaf rotation: pin the issuing CA (Google Trust Services WR1) as a
  durable anchor, off-race X.509 chain-verify a freshly-presented leaf against it (+ exact-SAN), then
  adopt + retry behind a dim "> recertify". Fail-closed, never trust-on-first-use.
montsqr - a Montgomery squaring shortcut for the RSA-2048 verify's 16 squarings (~19% fewer instrs),
  widening the @6 secure-tier margin; golfed back into the 24-sector module, so it costs no context.
```

Validated on the 6 MHz (knife-edge) and 8 MHz 286 — a full real-ECDHE + RSA-cert handshake reaches the
model, a one-bit-tampered pin is rejected, and a wrong-pin rotation sim recertifies and greets at both
clocks; the 16 KiB / 4.77 MHz 8088 matrix is unchanged (encrypted-not-secure, "insecure" splash).
Getting recertify to greet at 6 MHz took two reconnect-path fixes the hang had masked — a retry-counter
clobber (`tls_resend_second_flight` overwrote `with_retry`'s `CX`, an infinite loop on any lost
server-Finished) and the leaf re-adopt's ~3.3 s `rsa_adopt_derive` running *inside* the server's ~15 s
handshake window (moved before the connect; the @6 client Finished had landed ~1.6 s late, wire-confirmed).
Working records in `notes/build12-layout-redesign-attempts.md` and `notes/auto-recertify-attempts.md`; the
secure-tier crypto budget + the tier split is in `docs/architecture.md` (CPU And Crypto Budget).

## Forward-looking ideas

Not yet built — the backlog beyond what ships today. The render-room and handshake-speed items
unblock others, so they lead their groups.

Deliberately out of scope — left to the user/agent environment: rich UI on top of the minimal DPI,
e.g. displaying the model's reasoning/thinking. DPI is the disposable starter interface; the agent
can pull its own reasoning from the API and render it in the environment it builds. (It would also
cost the maxed render-phase budget and has no clean MDA treatment — no dim attribute to set it apart.)

Polish:

```text
smart linebreaking - collapse the loop-hop blank lines + cursor-aware wrapping. Four render groups
  (dpi prompt, model response, tool calling, system messages like "> reconnect"): no blank line within
  a group, exactly one between different groups. Today the "$r .." + "> read from .." block abuts the
  prose with no blank line before and too many after. BLOCKED on render-phase room (below).
render-phase room (enabler) - the render phase is one full sector and cannot grow in place: a 2-sector
  phase below the nucleus lands inside the NIC packet buffer at 0x0700 (read up to ~1.5 KB during a
  receive). Shrink the RX read window to one MSS-frame - the receive already caps payload at 592, so it
  is consistent - to free a safe 2-sector slot. Unblocks smart linebreaking + future renderer work.
  Touches the transport/handshake receive path, so it needs handshake + multi-NIC re-validation.
apostrophe glyph - the model's occasional curly apostrophe (UTF-8) renders as CP437 garbage.
  Mitigated: the identity prompt now gives a concrete example (map non-ASCII to ', not curly). A
  guaranteed fix is a render-level non-ASCII->ASCII map, which needs the render-phase room above.
situational awareness + identity prompt - strengthen the situational map (curb the 0ADD doodle) and
  review/expand the identity prompt so the agent better understands where it lives, its opportunities,
  and its risks. (The ledger arena/context sizes are auto-computed - a@ = chat_context_start + the live
  window length - so the 592-byte RX shrink needed no manual recalc; a@ has been advertised since Build 10.)
```

Bigger bets and research:

```text
environment save/load - persist the runtime environment (conversation + the arena the agent builds
  in) to writable media + restore it at boot, so the agent accumulates across restarts. A writable-
  media capability tier, orthogonal to the RAM/CPU tiers; the self-contained, high-value centerpiece.
  CHARTER: notes/env-save-load-brief.md (design-intent, not started).
true security on larger / faster machines (separate exploration, CPU-gated) - MEASURED to be CPU-gated,
  not RAM-gated (spike: tools/crypto-bench/, results/FINDINGS.md + entropy_certauth_scoping.md). The
  4.77 MHz / 16 KiB target makes deliberate, documented sacrifices; each was measured:
  - real ECDHE: the dormant constant-time P-256 (%if0 in core/p256.inc, never previously assembled) was
    brought to life + verified vs OpenSSL. One real scalar mult = 110.8 s on the 8088 - 7.4x over the
    ~15 s window (the field multiply's 16x16 hardware muls are 97% of it; even a perfect schoolbook mul
    floors at ~26.6 s). Fits 16 KiB easily (~3.4 KiB). So it is the CPU, not the size.
  - server-cert authentication: RSA-2048 verify ~43 s/sig (e=65537, the cheap option), ECDSA-P256 verify
    ~220 s/sig - both blow the window; a chain is minutes.
  - real entropy: ~0.16 s (a SHA-mixed keystroke/NIC/PIT pool) - the ONLY affordable upgrade, but
    timing-jitter sources are untestable on the cycle-deterministic emulator (keystroke timing works).
  A full real-security handshake is ~2.7 min on a stock 8088 => out of reach. The threshold on faster
  CPUs was then MEASURED (spike branch spike/crypto-speed, results/FINDINGS.md): the FPU does NOT
  unlock it (SHA is FPU-immune; the P-256 reduction/carry work dominates the FMUL win), but security
  begins at the 286. An optimized real ECDHE (Solinas+Karatsuba+wNAF P-256, OpenSSL-verified) runs in
  6.6 s on the lowest 6 MHz part, and a full cert-authenticated handshake (ECDHE + RSA-2048 verify
  6.37 s + fast PRF) fits the ~15 s server window: ~13.8 s @6 MHz (a knife-edge, only with the 4.64x
  SHA win) and a comfortable ~10.4 s @8 MHz. This shipped in Build 12: the secure 286 tier greets at
  6 MHz (still a knife-edge) and comfortably at 8 MHz; the 6 MHz slack was since widened by montsqr — a
  Montgomery squaring shortcut for the RSA verify, ~19% fewer instrs (see crypto-feasibility.md, Follow-up).
  The stock-8088 product stays honestly
  "encrypted but not secure" (per-record app-data IS MAC-verified after the FIFO collapse - record
  integrity, not a secure channel); real entropy + a pinned key is the honest middle ground there.
reach / perf - beyond segment 0 (>64 KiB); render-rate optimization for very long replies; drop the
  floppy reads in the 32K+ chat loop; TLS 1.3 (not a memory play - record-size caps are ignored on 1.2/1.3).
full TCP retransmit (survive a genuinely bad link) - an unacked-byte buffer + RTO timers + ACK tracking +
  receive reordering, so a dropped packet is a fast resend instead of a ~15 s re-handshake. The client
  handshake-send slices (SYN, ClientHello, CKE+CCS+Finished flight) already retransmit; loss testing
  showed the heavy-loss bottleneck is the server->client DOWNLOAD (the Certificate / response), not client
  sends, so a client retransmit layer is insurance for a rare case - below the two levers that follow. It
  also does NOT remove the reconnect (an idle-closed session has nothing to retransmit).
handshake speed (crypto optimization) - MEASURED (spike: tools/crypto-bench/, results/FINDINGS.md).
  The ~15 s handshake sits only ~0.2 s inside the server's ~15 s patience. The CKE->Finished gap is the
  8088 grinding the TLS-PRF: measured 4.92 s (SHA-256 block 156 ms; bit-at-a-time rotr + memory-to-memory
  32-bit math dominate). A 20-variant evolutionary search (byte rotation -> inline sigmas -> register-fold
  the round body -> state base-ptr+disp8 -> xchg register-rename rotates) got SHA-256/PRF to 4.64x on real
  86Box hardware (PRF 4.92 s -> 1.06 s), output bit-exact. This LANDED in Build 12 as the 16K crypto
  baseline (the slow path was deleted): the faster SHA is bigger, so it took the predicted sector —
  high_crypto_scratch base-raised ~512 B, paid from the conversation arena at the 16 KiB floor, free at
  32 KiB (see architecture.md, "The honest 16K cost"). It is also load-bearing for the 286 secure
  handshake fitting the window. The spike's verified variant is tools/crypto-bench/variants/r4_v42.inc.
receive-side loss tolerance - a bigger receive wait so the seed out-waits the server's RTO under heavy
  loss (the wire-proven heavy-loss bottleneck is the dropped server->client download). The high-value
  heavy-loss lever; the client-retransmit slices do not address it. Trade-off: a genuinely dead link then
  fails slower, but the never-blank reconnect already covers that gracefully.
```

## Public Release Gate

The first public release should include Builds 8, 9, and 10, not Build 8 alone.

Minimum public release criteria:

```text
Build 8 chat loop stable across repeated prompt/response turns
Build 9 minimal context management stable enough that prompts are not fresh each turn
Build 10 minimal RAM read/write/execute tool calling stable
supported NIC matrix documented
known security and hardware constraints documented honestly
16 KiB ROM BASIC entry documented
32 KiB and larger direct floppy boot documented
one write-protected 160 KiB FAT12 floppy image remains the recovery boundary
one visible CORE.SYS remains the runtime artifact
```
