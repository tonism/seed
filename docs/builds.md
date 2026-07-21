# Build Scope

Status: latest tagged release is Build 11 (release hardening: draining-FIFO transport, robust
reconnect, real LLM compaction, ESC-to-interrupt, tool-directive rendering), `build-11`. Build 12 —
the capability-tiered memory-layout redesign, native Responses tool calling, environment save/load,
the full memory-scaling ladder through 386 unreal mode, and the 286 secure tier (real ECDHE +
pinned-key RSA cert auth, with silent re-pinning on leaf rotation) — is patched and validated on
`work/compaction-fix`, not yet tagged. Build 13 starts by renaming the runtime to `SEED.SYS`,
moving NIC drivers to external files under `SEED/DRIVERS/`, and making driver
packaging optional. See the build sections for shipped
features and "Forward-looking ideas" for the backlog.

Seed's loading marker has four semantic states plus the boot splash:

```text
none         boot sector, loader, SEED.SYS load
"." dark     hardware then internet: SEED.SYS entry, display baseline, hardware detection, adapter init, handoff, then IP configuration, DNS, and reachability proof
"o" dark     TLS handshake: selected endpoint setup and the TLS 1.2 handshake
"o" normal   local crypto: TLS key schedule and key-material derivation
"o" bright   agent/environment: API validation, model/session, and environment handoff
splash       boot banner after display/CPU-class setup; no driver or network validation happens here
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
build 12  capability-tiered layout (one runtime file, NIC HAL, 32K cached chat loop, 2-image),
          native Responses tools, env save/load, 8088 far + EMS + 286 HMA/native extended +
          386 unreal memory scaling, and the 286 secure tier (real ECDHE + pinned RSA cert auth,
          auto-recertify)
build 13  SEED.SYS runtime rename, SEED/ directory layout, optional external
          SEED/DRIVERS/*.DRV NIC files with metadata-based selection, splash before
          driver loading
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
the FAT12 floppy + runtime file: agent config (AGENTS.CFG, built-in openai/anthropic/google, USER.CFG
for secrets), DNS + TCP 443, a hand-rolled TLS 1.2 ClientHello (P-256 ECDHE / ChaCha20-Poly1305),
the full handshake through ServerHelloDone, 8086 P-256 field/point/scalar primitives (OpenSSL-cross-
checked), a SHA-256 transcript + TLS-PRF key schedule, ChaCha20-Poly1305 records, and a minimal
OpenAI Responses request that returns `ok`. Validated on all seven 4.77 MHz NIC profiles.

Honest caveat: this path substitutes a scalar-1 stub for the ECDHE scalar (the premaster
becomes the server's public X), so no real key agreement runs — fast boot, not a secure channel.
Closed at the 286 in Build 12 (real ECDHE + pinned-key RSA cert auth, silent re-pin on leaf
rotation); the stock-8088 floor stays this way.

## Build 7 — 16 KiB entry contract

The same floppy supports two entry modes: >=32 KiB BIOS-boots the runtime directly; below 32 KiB the
user types a generated ROM BASIC sidecar helper that loads the same runtime. One image, one visible
runtime file, one code path after entry. Implemented as a windowed nucleus — a tiny resident control
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
(static, on the floppy) + ledger (compact tool memory map from runtime state) + conversation (a
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
arena advert  - the ledger carries a@/r= for the safe seg-0 arena base/ceiling
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
record in `notes/old/build11-hardening-attempts.md`.

## Build 12 — scaling + capability tiers

Build 12 is the current untagged `work/compaction-fix` build. It turns Seed from a
fixed 16 KiB survival exercise into one runtime file that scales by detected
capability while keeping the 16 KiB ROM BASIC sidecar and 32 KiB direct boot
green.

```text
layout + HAL      capability vector, lifetime-ordered bands, one active NIC driver loaded
32K cache         normal chat turns avoid floppy I/O; 16K still demand-loads
native tools      Responses function_call loop with local store:false replay
env save/load     optional ENV.DAT when the boot medium is writable
memory ladder     8088 far conventional, EMS, 286 HMA/native extended, 386 unreal
secure tier       286+ real ECDHE + pinned RSA auth, auto-recertify, pre-286 "insecure"
UI polish         grouped render spacing, word-wrap near the right edge, ASCII guardrails
```

Validation summary: the 16 KiB and 32 KiB tool loops are green with a uniform
4-byte read/write cap; far conventional and EMS high-address mapping are green;
tracked 286 and 386 representative profiles exist before their memory tiers are
used; generated 286 @6 and @8 runs complete real authenticated TLS and reject a
tampered pin. The 286 post-DPI runner is still less mature than the
16K/32K/EMS harnesses, so 286 validation should keep pairing tracked profile
boot evidence with targeted/generated secure-path evidence until that runner is
hardened.

Detailed records now live in the focused docs: memory maps in `docs/memory.md`,
runtime structure in `docs/architecture.md`, security/trust in `docs/security.md`,
and working logs in `notes/old/build12-layout-redesign-attempts.md`,
`notes/old/build12-memory-scaling-attempts.md`, and
`notes/old/auto-recertify-attempts.md`.

## Build 13 — runtime/drivers split

```text
SEED.SYS          visible root runtime file
SEED/             runtime-owned directory for shipped config, prompts, and optional local state
SEED/DRIVERS/     optional external one-sector NIC driver files scanned at boot
driver ABI        vtable header, SDRV metadata, family mask, and shared helper addresses
driver selection  one suitable driver autoloads; multiple suitables ask; none fails cleanly
build switches    INCLUDE_NIC_DRIVERS=0 omits all drivers; INCLUDE_NIC_DRIVER_NE,
                  INCLUDE_NIC_DRIVER_WD80X3, INCLUDE_NIC_DRIVER_3C503, and
                  INCLUDE_NIC_DRIVER_3C501 omit individual files
FAT12 builder     nested 8.3 directory support for the scoped runtime layout
splash order      draw the CPU-class splash before driver loading/failure handling
floppy policy     startup reads only; user save/config writes only when requested
leaf DER          ship SEED/LEAF.DER as the fast-path leaf file; verify it against
                  WR1 before pre-socket adoption, refresh it after verified re-pin
NE.DRV            shared NE/DP8390 driver validated on 16-bit NE2000 and Novell NE2000
WD80X3.DRV        shared WD80x3 driver covers WD8003E/EB and WD8013EBT
3c501 receive     keep the single-buffer sample below the response phase, preserve ES,
                  and ignore truncated TCP payloads instead of ACKing partial data
```

This is the first Build 13 checkpoint. `SEED.SYS` remains the first FAT data file
so the reserved loader and ROM BASIC sidecar still share the same runtime image.
Driver additions or driver fixes can now replace `.DRV` files without replacing
the monolithic runtime when the resident driver ABI is unchanged. A floppy can
also intentionally ship without drivers; a NIC-present boot then reaches the
same hardware phase and reports `driver setup failed` with retry/restart. New
hardware detection, new shared helpers, or ABI changes still require a matching
`SEED.SYS` update.

## Forward-looking ideas

Not yet built. Shipped Build 12 items are no longer listed here; their details
belong in the focused docs linked from the Build 12 section.

Polish:

```text
render-phase room - free a safe 2-sector render phase for glyph mapping and future renderer work;
  likely by tightening the RX read window. This touches receive/handshake behavior, so it needs
  handshake and multi-NIC re-validation.
apostrophe glyph - the model's occasional curly apostrophe (UTF-8) renders as CP437 garbage.
  Mitigated in prompt text; a guaranteed fix needs render-level non-ASCII->ASCII mapping.
```

Bigger bets and research:

```text
full TCP retransmit - unacked-byte buffer, RTO timers, ACK tracking, and receive reordering.
receive-side loss tolerance - wait longer for server retransmits under heavy download loss, balanced
  against slower failure on a genuinely dead link.
render-rate optimization - improve very long replies without weakening ACK/render pacing.
ECDSA contingency - scoped but unbuilt; only needed if the RSA leaf disappears from the 286 profile.
TLS 1.3 - a cleaner handshake; research-stage.
64-bit host memory - long mode / no-BIOS path reaching beyond 386-era memory tiers.
```

Rich UI on top of DPI remains out of scope for the boot runtime. DPI is the
starter interface; richer reasoning and workspace views belong to the
user/agent environment Seed can build after boot.

## Release Gate

Any tagged build should keep these properties green:

```text
16 KiB ROM BASIC sidecar boots and reaches DPI
32 KiB direct boot reaches DPI
memory/tool gates match the advertised tier caps
supported NIC matrix is documented or explicitly scoped
security limits are stated honestly
one write-protected 160 KiB FAT12 floppy image remains the recovery boundary
one visible SEED.SYS remains the root runtime artifact
external NIC driver files remain under SEED/DRIVERS/
```

Build 8-10 release-floor criteria remain the baseline for the public chat/tool
experience:

```text
Build 8 chat loop stable across repeated prompt/response turns
Build 9 context management prevents fresh-prompt amnesia
Build 10+ tool calling stable enough that local crashes recover by reboot
supported NIC matrix documented
```
