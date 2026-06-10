# Build Scope

Status: latest tagged release is Build 10 (minimal tool calling: `$r/$w/$x` + the agentic loop),
`build-10` at `2eee16d`. Build 11 (release hardening) is largely implemented on `work/draining-fifo`
— see its section for the shipped features and "Forward-looking ideas" for the backlog.

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

Honest caveat: the shipped path substitutes a scalar-1 stub for the ECDHE scalar (the premaster
becomes the server's public X), so no real key agreement runs — fast boot, not a secure channel.
Closing that is tracked under Forward-looking and in the README security status.

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
budget the rest depended on. (On `work/draining-fifo`; not yet tagged.)

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
  A full real-security handshake is ~2.7 min => out of reach on a stock 8088; it needs a faster machine
  (286/386+) or a self-hosted long-patience endpoint. Per-record app-data is already MAC-verified after
  the FIFO collapse - record integrity, not a secure channel. The small-machine product stays honestly
  "encrypted but not secure"; real entropy + a pinned key is the honest middle ground.
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
  86Box hardware (PRF 4.92 s -> 1.06 s), output bit-exact. Catch: +595 B of code and the K crypto window
  has 9 B free, so landing it is a sized follow-up - free ~590 B in the K window, or bump
  high_crypto_scratch_start ~600 B (free at 32 KiB, costs conversation arena at the 16 KiB floor; needs
  7-NIC + 16K re-validation). The verified variant is tools/crypto-bench/variants/r4_v42.inc.
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
