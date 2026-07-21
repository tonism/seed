# Seed Architecture Contract

Seed is a bootstrapping control plane, not a protected operating system.

The product goal is to give a memory-constrained machine a working agent API
path, publish the live hardware and memory contract, then leave the machine
open for user and agent-built local tooling. Seed should stay small enough that
the user and the agent keep as much of the machine as possible.

The whole design follows from one decision: **Seed is 16 KiB-shaped on purpose,
and every byte of headroom above 16 KiB belongs to the user, not to Seed.** A
bigger machine does not get a bigger Seed; it gets a bigger conversation and a
bigger arena to build in. That principle is the spine of everything below.

> **Status.** This contract describes the Build 13 runtime/driver split on top of
> the Build 12 capability-tiered architecture: lifetime-ordered low memory, one
> `SEED.SYS` runtime, external NIC driver files, native function tools, RAM
> scaling from the 16 KiB floor through EMS / 286 native extended / 386 unreal
> mode, and CPU-tiered security beginning at the 286. Byte-level maps for the
> 16 KiB floor and profile examples for larger tiers are in [`memory.md`](memory.md).
> Measured numbers below are from the current tree and the crypto spike
> (`tools/crypto-bench/results/FINDINGS.md`).

## Core Shape

Seed owns the parts that are painful, fragile, or timing-sensitive to build
from bare metal:

```text
boot entry
basic hardware discovery
text UI and recovery path
network setup
provider TLS/API bootstrap
compact memory map and handoff state
minimal handoff into the user/agent environment
```

Seed should not grow into a general hardware abstraction layer or restrictive
runtime. Local tool formats, loaders, ABIs, workspaces, and result handling
belong to the user/agent environment. Seed's job is to get that environment to
the point where it can exist, not to become the environment itself.

Protected mode is not part of the current product direction. Even on later
machines, Seed should not become a protected supervisor unless the product
direction explicitly changes.

## Capability Tiers

Seed scales by a small, boot-detected **capability vector**, not by shipping
different products. The vector's primary dimensions today are **RAM / memory
reach**, **CPU class**, and **NIC family**. Everything that
can scale, scales by tier off this one vector.

There are exactly **two boot shapes, locked**, and several additive reach /
capability tiers above them:

```text
16 KiB  — the baseline and the canonical shape. EVERY feature works here,
          including the fast crypto. This is the recovery/identity floor and
          the shape the whole system is designed around. Inviolable.

32 KiB  — the convenience tier. The chat loop no longer reads the floppy
          mid-conversation (it preloads its working set and tools schema at
          boot), and the rest of the headroom becomes a larger low
          arena + conversation window.
          No new REQUIRED functionality — only performance and headroom.

>64 KiB conventional — far seg:off memory, directly readable/writable/executable
          below the video/ROM hole. The direct arena claims the low executable
          far memory and the canonical context relocates above it, growing with
          conventional RAM.

EMS       — 8088/V30-class path past the 1 MiB real-mode ceiling. Seed drives the
          EMS board's bank registers directly; EMS is windowed/data, not direct
          executable memory.

286 HMA/native extended — A20 exposes HMA as a direct range; native extended
          memory above HMA is reached by `int 15h AH=87h` block moves.

386 unreal — BIOS-compatible real mode with 4 GB segment limits. High memory is
          flat direct memory instead of an EMS or `int 15h` window.

286+     — a CPU-class capability, orthogonal to RAM: the first processor fast
          enough to run a real, authenticated TLS handshake inside the
          provider's window (see [security.md](security.md)). "Secure" is a 286 tier,
          never the 16 KiB / 4.77 MHz floor.

persistence — if the boot floppy accepts a requested save write, Seed can save
          and restore the conversation window, arena, and screen. Startup does
          not probe writeability.
```

Functional parity is at 16 KiB. Larger memory and faster CPU tiers add performance,
headroom, wider address reach, persistence when requested writes succeed, and — on the 286 —
real confidentiality; they do not make the basic agent/tool loop unavailable on the
floor. A feature that cannot degrade to the 16 KiB shape is a design failure.

## Current Target Snapshot

The active implementation target is an IBM PC 5150-class machine:

```text
CPU              8088-compatible, 4.77 MHz (baseline); 286 enables the secure tier
RAM tiers        16 KiB (ROM BASIC sidecar entry), 32 KiB direct boot, far conventional,
                 EMS, 286 HMA/native extended, 386 unreal
media            160 KiB headline FAT12 floppy image; 360 KiB profile image for 286 work
video            BIOS text mode, CGA or MDA
network          3c501, 3c503, NE1000/NE2000, Novell NE1000, WD8003 families
runtime file     one visible SEED.SYS plus optional external SEED/DRIVERS/*.DRV NIC files
```

Current measured image (`tools/core-sys-info.py`, this tree):

```text
SEED.SYS total bytes:        51712
SEED.SYS total sectors:      101
resident nucleus sectors:    4   (2048 B; 1494 nonzero B)
phase count:                 29
provider-critical K window:  15 sectors / 7680 bytes (0x1800..0x3600)
```

The resident nucleus is still fixed at four sectors; Build 12's growth is cold
phases and optional high-memory overlays, not a larger always-resident Seed.

## Boot Artifact

The floppy is a small FAT12 image with a reserved boot loader and one normal,
visible runtime file plus runtime-owned subdirectories:

```text
160 KiB FAT12 floppy
|
| sector 1       boot sector with BPB
| sectors 2-5    reserved loader
| sectors 6-7    FAT copies
| sectors 8-11   root directory
| sector 12+     file data
|                SEED.SYS is the first FAT data file
|                SEED/ holds AGENTS.CFG, optional USER.CFG, IDENTITY, COMPACT, TOOLS
|                SEED/LEAF.DER may be created as a verified recert cache
|                SEED/DRIVERS/ optionally holds one-sector NIC .DRV files
```

`SEED.SYS` is one file-backed runtime. The build splits its source into NASM
include files and cold phases, but the release artifact remains one visible root
runtime. **One runtime artifact ships every tier** (see The One-Artifact
Relocation Model). NIC drivers are the scoped exception: per-family `.DRV` files
live under `SEED/DRIVERS/` and are scanned after hardware detection. Seed loads
one suitable driver into the active-driver slot, asks the user when multiple
suitable drivers are present, and uses the normal retry/restart failure path
when no suitable driver is available. The only thing that would ever justify a second image is a
fundamentally different ISA — an ARM/RISC port where binary reuse is literally
impossible. Compile-time multi-build per tier is out.

`IDENTITY`, `COMPACT`, and `TOOLS` are static prompt/schema assets: the agent's
identity, the compaction contract, and the native tool schema. They live on the
floppy and are streamed into the request mid-chat rather than baked into a phase
image. On the 32 KiB+ loop-cache tier, `IDENTITY` and `TOOLS` are also preloaded
into high RAM so ordinary turns do not read the floppy.

## Entry Paths

Seed has two entry paths into the same resident nucleus. Both end by jumping to
`0000:1000` with the capability inputs (RAM top, boot drive) in place.

```text
32 KiB and larger  (direct floppy boot)
---------------------------------------
BIOS loads boot sector at 0000:7c00
  -> stage 1 reads the reserved loader to 0000:0600
  -> loader reads the SEED.SYS root entry and FAT chain
  -> loader reads only the resident SEED.SYS sectors to 0000:1000
  -> loader detects RAM (int 0x12), passes RAM top + "SEED" magic + boot drive
  -> jump 0000:1000

16 KiB path  (ROM BASIC sidecar)
--------------------------------
machine enters ROM BASIC
  -> user pastes the generated SEED24A.BAS / SEED24B.BAS sidecar text
  -> BASIC pokes a tiny 8086 loader at 0000:3a00
  -> helper reads the resident SEED.SYS sectors from the Seed floppy
  -> helper passes AX = RAM top, BX/CX = "SEED" magic, DL = boot drive
  -> jump 0000:1000
```

The BASIC loader at `0x3a00` is entry-time only and is deliberately placed in
memory that later becomes Seed critical scratch. Once it jumps to `SEED.SYS`,
the BASIC runtime and sidecar loader are abandoned. RAM top is the first input
to the capability vector — it selects the 16 KiB or 32 KiB layout.

## The One-Artifact Relocation Model

A single `SEED.SYS` runs every tier, and the capability vector selects what
loads and where. The foundational question is *how* a tier's code is placed —
and the answer is **hybrid: two build-time-fixed layouts inside one image,
selected at boot, with the few tier-varying entry points reached through a small
fixed dispatch-vector table.**

Because the tiers are locked at two, both layouts are fully known at build time,
so "relocation" never needs runtime address arithmetic:

```text
16 KiB layout   the canonical shape (below). Demand-loads phases and tools schema from floppy.
                Zero relocation tax — the hot path keeps fixed addressing.

32 KiB layout   the SAME shape, plus a few optional modules placed at
                build-time-fixed high addresses: the chat loop's working set,
                tools schema, and (on a 286) the real-crypto modules.
                Everything else above is arena.

>32 KiB         the 32 KiB layout plus detected memory-reach backends. Module
                addresses do not move; only the arena/context map grows.
```

The handful of entry points that differ by tier — the phase loader's
preload-vs-demand decision, the active NIC driver, and (on a 286) the secure
crypto path — are called **indirectly through a fixed low vector table** that
the boot fills from the capability vector. The calls are coarse-grained
(per-phase, per-record, per-handshake), so the indirection costs a few bytes and
a few cycles, never a per-instruction tax. The 16 KiB hot path — a full nucleus
at 2033/2048 bytes, and crypto inner loops with no spare registers — pays none
of it.

**Why not runtime-relative addressing.** Setting region bases at runtime (a base
register or segment per region) is maximally flexible and would let code load
anywhere. But on the 8088 it taxes exactly the two most-constrained resources in
the system: the resident nucleus (no room for relocation prologues) and the
register-starved crypto inner loops (the 286 secure handshake is already on a
~1 s knife-edge). It buys geometry-flexibility that the *locked two-tier* model
has defined away — even the 286 secure tier is "the 32 KiB layout plus more
modules in the same high region," not new geometry. Fixed placement is the
correct design when the number of layouts is small and known; runtime-relative
solves a problem this contract does not have.

**The seam for the >64 KiB tiers.** The vector table *is* the escape hatch.
Most hot code still calls near pointers inside segment 0; far conventional, EMS,
286 native extended, and 386 unreal mode sit behind memory-HAL helpers and the same
native tool / context-streaming call sites. The 64-bit/no-BIOS runtime remains later work.

## Memory Shape: Lifetime-Ordered Bands

The old layout accreted region by region; reuse was a web of hand-reasoned
aliases ("this region is dead here, so borrow it") whose correctness lived in
comments. The redesign replaces that with **regions ordered by lifetime**, so
the user's arena is one large contiguous block and reuse is provable and
build-checked.

Every region declares `{owner, size, lifetime, load-policy}`, where lifetime is
one of:

```text
boot-only            used during bring-up, dead afterward
handshake-only       TLS key schedule / transcript / Finished; idle during chat
per-turn             transient scratch for one request/response
session-resident     needed every turn (cannot be reloaded mid-chat)
reconnect-survives   must persist across a mid-session handshake (keys, context)
```

Reuse is allowed **only across provably-disjoint lifetimes, and the build
asserts it** — killing the alias-bug class that recurred through Build 11. The
16 KiB shape, bottom to top:

```text
BIOS + handoff (capability vector)                 boot-only / session
phase load window  (demand-loaded phases land here) per-turn          ← stays small = more arena
resident nucleus   (loader, NIC TX/RX, UI prims)    session-resident  ← scrutinized, minimal
session-resident crypto  (ChaCha20 + Poly1305)      session-resident  ← every record, can't reload mid-chat
overlay zone  ── handshake-only crypto              handshake-only ⟷ per-turn
                 (SHA/HMAC/PRF, +P-256/RSA on 286)
                 ⟷ chat-loop transient scratch
──────────────────── reconnect-safe line ────────────────────
session keys · reconnect caches · keepalive · ESC   reconnect-survives
USER/AGENT ARENA  (executable, at the low base)     session-persistent
conversation window / context  (above the arena) ►  session-persistent → ram_top
stack guard / stack
```

Three ideas carry the weight:

- **The reconnect-safe line.** Everything that must survive a mid-session
  reconnect — the session keys, the rolling conversation window, the user/agent
  arena — sits *above* the line, one contiguous block to `ram_top`. Everything
  transient or rebuildable sits *below* it, where a reconnect can re-run the
  handshake and rebuild it without ever touching the user's context. The
  reclaimable crypto sits *below* the resident chat set, so a reconnect reload
  can never disturb the chat set or the arena above it.

- **The overlay zone (max, not sum).** The handshake-only crypto and the chat
  loop's per-turn scratch share one address range, because their lifetimes are
  disjoint: the crypto runs during the handshake, the scratch during the chat.
  They cost `max(size)`, not `size + size`. This is the principled successor to
  the old `poly_rx_save = tls_master_secret` aliases — same mechanism, now
  declared and asserted instead of reasoned in a comment. It is also what lets
  the bigger fast crypto land (below) without pushing the reconnect-safe line up
  and shrinking the user's arena.

- **Arena-first placement.** Within the user region the executable arena sits at
  the low base and the conversation context above it — and this holds on *every*
  tier. Where a machine has slower windowed or extended memory (EMS, 286
  native-extended, 386 high memory), the context relocates to the top of *that*
  tier so the arena can claim all the fast, directly-executable low memory. The
  rule is uniform: executable workspace as low as possible; the context — only
  ever streamed out as data — takes the highest, slowest memory. Two consequences
  fall out of it: the arena base is the same low address whether or not the
  context has moved up, and the context is size-capped so every surplus byte on a
  bigger machine flows to the arena, not the window.

The win this shape buys: on 16 KiB the arena stops being the scrap left at the
top and becomes *everything above one line*; on 32 KiB and up, essentially all
headroom flows straight into it. Adding a feature becomes declaring its lifetime
and attaching it to the right band — additive, build-asserted, no hand-scrounged
bytes.

## Floppy Policy

The floppy is **read-only** (the recovery boundary; see below) and demand-loading
from it is *preferred on every tier* whenever it buys arena — code that lives on
the floppy is RAM that goes to the user instead. Seed minimizes its resident
footprint everywhere. There are exactly **two no-floppy zones**:

```text
1. the snappy chat loop   — no mid-conversation floppy latency
2. the ~15 s crypto race  — no floppy I/O between handshake start and finish
```

Outside those two windows, read freely — even on a 32 KiB machine. The critical
nuance is *timing, not prohibition*: a floppy read **before** the crypto race
starts is fine; only reads **during** the windowed handshake are forbidden. So a
mid-session reconnect first reloads its handshake crypto from floppy, *then*
opens the connection and runs the race floppy-free.

The tiers differ only in what they pin:

```text
16 KiB   demand-loads its phases in-loop (no room to preload). Acceptable: the
         loop reads between turns and before the race, never during either zone.

32 KiB   preloads ONLY the normal chat loop's working set (its phases + the streamed
         IDENTITY prompt) so ordinary turns are floppy-free. The rare COMPACT prompt
         can still stream from floppy. It does NOT
         greedily preload everything it could — the rest stays on floppy and
         that RAM becomes arena. Boot-time reads are encouraged when they buy
         loop-time RAM.
```

> **Implemented (Build 12).** On a 32 KiB direct boot, the boot reads the loop's working set —
> the chat-loop phases, the resident crypto (K) window, and the IDENTITY prompt — into a
> high RAM cache once (`loop_cache`, above the arena/context pool and below the stack). The
> phase loader (`load_core_sectors_at`) and the prompt streamer then serve ordinary turns from RAM, so a
> normal chat turn reads **no floppy** (per-turn I/O ~25 sectors → 0). The rare compaction turn may still
> stream the COMPACT prompt from floppy. The arena/context ceiling drops to the cache
> base, and the ledger advertises that as the RAM ceiling so an agent write never lands in the cache.
> 16 KiB is untouched: the path is gated on `ram_top`, and the 16 KiB loop demand-loads as before.

## Runtime Step Order

The resident nucleus is a small scheduler plus shared hardware, UI, filesystem,
network, and state primitives. It reloads cold phases from the same `SEED.SYS`
file as needed.

```text
entry normalize
  -> set stack from BIOS path or BASIC-provided RAM top
  -> clear low and high runtime scratch
  -> record boot drive + RAM top in the handoff (capability vector seed)

hardware phase "."
  -> H: display, handoff, CPU/memory/media/NIC discovery (sets the capability vector;
        conditionally runs 0 for 286 HMA/native extended-memory layout)
  -> B: draw the seed build splash and CPU-class warning before driver/network setup
  -> 2: scan SEED/DRIVERS/*.DRV and load a suitable detected-family NIC driver
  -> Z: 386 unreal setup when present
  -> I: packet I/O initialization

internet phase (still ".")
  -> D: DHCP setup
  -> N: NTP/RTC setup for certificate validity checks

agent phase "o"
  -> A: SEED/AGENTS.CFG load/parse or built-in fallback
  -> U: SEED/USER.CFG load/parse
  -> Q: prompt for any missing agent/server/key/model/reasoning values
  -> E: selected-agent endpoint and DNS name preparation
  -> V: selected-agent cache setup
  -> R: request construction
  -> G/J: context mirror or extended-memory context chunk reads when required
  -> K: load the provider-critical crypto window
  -> L: build TLS ClientHello and low crypto constants
  -> C: TCP connect to the selected provider on port 443
  -> K: TLS server proof, key schedule, encrypted request, application receive
  -> T: parse the received application-data chunk for the returned answer
  -> S: best-effort SEED/USER.CFG save if values changed

prompt loop "Default Prompt Interface"
  -> render the model greeting, then take prompts on the live (reused) TLS session
  -> each turn builds the request, streams the reply, then cold native-tool phases run any
     function_call (`read_mem`, `write_mem`, `exec`, `save_env`, `load_env`) and replay the
     function_call_output back to the model (see "Demo" below)
  -> reconnect (reload-before-race, then retry) only on a real drop

failure
  -> F: mark the current phase red, type the error, offer retry/restart
  -> retry returns to the hardware "." phase without rereading resident sectors
```

The same TCP connect phase serves selected provider connections and reconnects;
it is loaded into the network setup window each time it is needed.

## Phase Windows

`SEED.SYS` starts with a resident nucleus and a phase table. The phase loader
addresses phases by sector offset inside `SEED.SYS`, so keeping `SEED.SYS` first
in the FAT data area is part of the boot contract. The phase table is build
metadata (tools and the header read it); runtime dispatch is by sector offset,
and *which* copy a phase runs from — demand-loaded low, or preloaded high on
32 KiB — is the capability-vector decision routed through the dispatch table.

Current 29-phase layout (regenerate with `make inspect` / `tools/core-sys-info.py`):

```text
id  sectors  load addr  responsibility
K   15       0x1800     provider-critical crypto: SHA-256, ChaCha20-Poly1305, TLS, API
F   2        0x0700     failure action UI
H   4        0x0700     hardware/display/NIC discovery
2   2        0x0700     scan/load suitable NIC driver from SEED/DRIVERS/*.DRV
0   1        0x3600     286 HMA/native extended-memory layout
Z   1        0x0700     386 unreal-mode setup/refresh support
I   1        0x0700     packet I/O initialization
D   3        0x0900     DHCP setup
N   2        0x0900     NTP/RTC setup for certificate validity
C   3        0x0900     TCP connect
L   3        0x0700     TLS ClientHello, low crypto constants, recert cache
E   1        0x0700     selected-agent endpoint setup
A   2        0x0700     SEED/AGENTS.CFG provider config
U   2        0x0700     SEED/USER.CFG persisted user values
Q   2        0x0700     agent selection and missing-value prompts
G   1        0x0700     context mirror into the far canonical log
J   1        0x0700     extended/windowed context read chunk
R   3        0x0900     API request construction
V   1        0x0700     agent/endpoint cache
X   3        0x0900     application-data stream (encrypted send/receive)
T   2        0x0900     agent response parse and function_call capture
B   1        0x0700     boot splash/banner display
Y   1        0x0700     Default Prompt Interface chat loop
M   3        0x0700     native tool calling: parse function_call and dispatch helper
1   1        0x0700     previous function_call replay helper
O   4        0x0700     memory tools: read_mem/write_mem/exec backends
S   2        0x0700     best-effort SEED/USER.CFG save
P   3        0x0700     restore ENV.DAT into conversation/arena/screen
W   2        0x0900     save ENV.DAT prep/write helper
```

Phases that do network I/O — `D`, `N`, `C`, `R`, `X`, `T`, `W` — load at
`0x0900` when they need to coexist with the TCP/NIC scratch or share that larger
network window between turns. The 286 extended-layout phase `0` loads at `0x3600`
because it runs while the high scratch band is still available. Most remaining
cold phases load at `0x0700`. This
phase-streaming design is what lets a TLS 1.2 record path — ChaCha20-Poly1305,
SHA-256, HTTP/1.1, SSE streaming — run in 16 KiB on a 4.77 MHz 8088: only the
nucleus and the crypto window stay resident, while the other phases stream from
the floppy and take turns in one small window. (The P-256 key agreement real TLS
also needs is the one piece that doesn't fit on the 8088 — see CPU And Crypto
Budget.)

## Demo: A Tool-Called Request

What every part of the machine touches when the cloud model runs code on the
1981 PC:

```text
user types a prompt -> DPI captures it into the conversation window
R  build request: instructions (native tool contract) + ledger (arena ranges, save state,
     and c@ context-cap knob) + tools schema + the JSON-escaped window + the prompt,
     always with store:false
X  application-data stream: encrypt with the resident crypto window (ChaCha20-Poly1305)
     and send over the live (reused) TLS session, then receive the streamed reply. If the
     model emits text, the renderer draws it. If it emits a native function_call, the
     receive scanner captures call_id/name/arguments and suppresses prose rendering.
M  tool phase (cold, loaded between turns): parse the structured call and execute
     read_mem / write_mem / exec / save_env / load_env. It renders a dim action line,
     stores the structured output, and the next request locally replays the user item,
     function_call, and function_call_output. The model then answers or calls another tool.
```

Worked example (validated): asked to write and then read four bytes in the arena, the model calls
`write_mem`, then `read_mem`, Seed executes both locally, sends `function_call_output` items, and
the model answers from the returned bytes. The current memory tools intentionally cap
`read_mem`/`write_mem` at four bytes per call on every tier while the native tool loop is hardened.
The write/execute authority model is unchanged: four hand-aimed bytes (`mov ax,0x1234; ret`) can be
placed into the arena and run. There is no sandbox; a bad `exec` hangs the machine, and recovery is
a reboot from trusted media (see Authority Model and Recovery Boundary).

## CPU And Crypto Budget

The other half of the constraint is the processor. A 4.77 MHz 8088 is a 16-bit,
sub-MIPS part with a slow multiply and no crypto acceleration, and the provider
path asks it to run modern TLS 1.2. That splits into two very different costs.
The *symmetric* crypto — ChaCha20-Poly1305 record encryption and SHA-256 (the
handshake transcript and the PRF key schedule) — runs for real on the 8088. The
*asymmetric* step — a P-256 scalar multiply for ECDH key agreement — is the
killer: one real scalar multiply is **110.8 s** measured here (the dormant
constant-time primitives, verified against OpenSSL), so the baseline build skips
it. Notably it is **not a size problem** — the real P-256 fits in ~3.4 KiB —
purely a speed one: the 8088's slow `mul` is the wall.

The 8086/8088-class resource profile, measured by packet-capture timing across two boots (the
gaps between the VM's packets *are* the 8088's compute), holds the surprise
about which resource dominates:

```text
FIRST BOOT  -  power-on to first response     (handshake + reply measured, 2 boots)

       |setup|------TLS 1.2 handshake------|reply
  t/s  0   2   4   6   8   10  12  14  16  18  20
  CPU  ░░▒▒▒▓██████████████████████████████   ░▒░
  NET  ░▒▓▓▒░▓                          ▒▒ ░ ▓▓▒░
  NIC   ░▒░  ▒                               ░▓▓▒
  DSK  ▒██▓░                                 ░▒
  RAM  ░▒▓███████████████████████████████████████
       (blank) idle   ░ light   ▒ medium   ▓ busy   █ saturated     NIC = 8088 PIO

  ──────────────────────────────

CHAT / TOOL-CALL TURN  -  session reused, no handshake     (model-wait bound)

       -thinks--reply
  t/s  0 1 2 3 4 5 6
  CPU            ░▓▒
  NET  ░        ▓▓▓▒
  NIC           ░▓▓▒
  DSK           ▒
  RAM  ██████████████
```

That monitor remains valid for the 8086/8088 path. It is the
encrypted-not-secure path: no real public-key work, no certificate
authentication, and a red `insecure` splash on pre-286 machines.

The 6 MHz 286 secure path spends roughly the same boot phases on the screen, but
the CPU profile is different: the public-key work is real, and it is the
knife-edge. This is a budget-shaped monitor from the measured component timings
in [crypto-feasibility.md](crypto-feasibility.md), not a replacement for the
packet-capture trace above:

```text
286 @6 FIRST BOOT  -  secure path     (real ECDHE + RSA auth + reply)

       |setup|P-256 ECDHE | RSA verify |reply
  t/s  0   2   4   6   8   10  12  14  16  18  20
  CPU  ░░▒▒▒▓█████████████████████████▓ ░░▒░
  NET   ▓▒▒▒▒                         ▒ ▓▓▓▓▓▓▓
  NIC    ░ ▒▒                         ▒ ▓▓▓▓▓▓
  DSK  ▒████▓
  RAM  ░▒▓█████████████████████████████████████
```

The 286 loads its secure overlay only on 286+ machines, uses real entropy, runs
the genuine P-256/RSA path, and NTP-syncs the validity clock for cert checks.
At 6 MHz the authenticated handshake greets but is still the tight path; at
8 MHz it has comfortable room.

On the 8088, the TLS handshake is ~14.5 s of the CPU pinned flat-out — SHA-256 hashing the
2.8 KB certificate into the transcript, the PRF key schedule, and ChaCha — in
two ~7 s halves that come out identical run to run (fixed arithmetic on fixed
input). Everything else is small: the model thinks and replies in ~2.5 s, a
round trip is 7 ms, the ClientHello builds in 0.27 s. The contrast is the point:
the expensive crypto is paid **once**, at boot. Every turn after reuses the open
session, so a chat or tool-call turn is mostly the 8088 idle while the model
thinks, then a ChaCha decrypt, a render, and — for a tool call — a CALL into the
arena. On a 4.77 MHz part, modern TLS is a symmetric-arithmetic cost, and it is
the single biggest line item in the whole boot.

What keeps the symmetric side tractable:

- **An ARX record cipher.** ChaCha20-Poly1305 is add-rotate-xor, no S-boxes or
  large tables, so it needs no AES hardware and stays cheap on the 8088.
- **Reused HMAC state.** Prepared HMAC-SHA256 ipad/opad pads are kept across the
  TLS PRF, so the key schedule does not recompute blocks it already has.
- **Pace the stream to the renderer.** On the most constrained NICs, response
  text uses render-before-ACK pacing so the network does not outrun the
  renderer (see `networking.md`).

**The fast crypto is baseline now — one implementation, everywhere.** An
evolutionary search produced a family of byte-granular-rotate + register-resident
SHA-256/PRF rewrites, all bit-exact. Seed ships **r2_v25 — ~4.3× faster
(PRF 4.92 s → ~1.14 s), bit-exact** (gated by `evaluate.py` + `check-tls-prf` +
`check-chacha-poly1305`). It is the only crypto Seed ships — no slow fallback —
because it works on the 16 KiB baseline, where every feature must. The faster
`r4_v42` (~4.64×) was measured but *not* shipped: it is one sector larger and buys
the last ~0.3× only behind a fragile 74 B bit-exact golf of working TLS code, for
the same 16K cost — not worth the handshake risk.

**The honest 16K cost.** The fast SHA is bigger than the slow one, so it grows the
resident K window by one sector (14 → 15). The earlier hope was that an "overlay
zone" would let the handshake-only SHA share space with chat scratch and *never
touch the arena* — but at the 16K byte level that does not hold: there is no
~2 KB hole free *during the handshake* (it uses all of low scratch, including the
packet TX buffer), so the SHA must stay resident. Conservation of bytes then wins:
on a full 16 KiB machine the extra sector comes from the only elastic upper pool.
In the current native-tool layout that final pool is 192 B, split into a 96 B
conversation window and a 96 B arena. **32 KiB is unaffected** — the extra RAM is
buying the cached chat/tool loop, and the 512 B SHA cost is noise there. Faster
crypto everywhere, paid for at the 16 KiB floor, is the real shape of the trade.
It is also *load-bearing for the 286 secure tier* (below).

And the part that is *not* tractable on the 8088 — the honest gap, and where it closes —
is **capability-tiered security**, covered in full in [security.md](security.md). In short:

- **On the 8088 the channel is encrypted but not secure.** The P-256 key exchange is
  skipped (a scalar-1 stub: the server's public X *is* the premaster, so no key agreement
  happens — anyone capturing the handshake derives every session key), and certificate
  authentication is skipped too (RSA/ECDSA verify is tens of seconds to minutes here). Real
  entropy would not help on its own. A pre-286 machine shows a red **"insecure"** on the
  splash to say so.
- **Security begins at the 286 (Build 12).** The 286 runs a *real* authenticated handshake —
  real ECDHE key agreement (the optimised P-256, ~6.6 s/scalar-mult @6), a pinned-key
  RSA-2048 certificate verify, and **silent re-pinning** when the leaf rotates — inside a
  handshake-only module that overlays the 32 KiB loop cache (0 resident RAM on 16 KiB; the
  hot path never loads it). The fast SHA above is load-bearing for it. The full handshake
  fits the provider's ~15 s window even at 6 MHz (a ~1.2 s knife-edge; 8 MHz is the
  comfortable floor), tamper-rejecting a bad pin.

The trust model, the off-race re-pin mechanics, the NTP-synced validity clock, and the
scoped-but-unbuilt ECDSA contingency are all in [security.md](security.md).

The handshake race is also why the chat loop reuses one session instead of
reconnecting per turn — a fresh mid-chat handshake can lose the race:

```text
  fresh TLS handshake on the 8088   ├──────────────── ~15 s ────────────────┤ done
  provider reconnect window         ├─────────────── ~15 s ───────────────┤ ✗ closed

  So the chat loop:
    · holds ONE TLS session open and reuses it for every prompt; a keep-alive ping holds
      it open through long renders, so an engaged session reuses snappily, no reconnect
    · if the completion marker is missed but the text already rendered, accepts the answer
      rather than forcing a new (racing) handshake
    · when reuse DOES fail — idle long enough that the provider closed the socket — it
      reloads handshake crypto from floppy BEFORE opening the connection (never during the
      race), then reconnects behind a single dim "> reconnect" line and retries up to 3x;
      if all three lose the race it appends " failed" and drops to the prompt (never a
      blank turn)
  The ~15 s handshake is normally paid once, at boot — never per reused turn.
```

Both constraints are answered the same way: do the irreducible work once, keep
it resident only as long as its lifetime requires, and lean on algorithm and
layout choices that suit a small, slow machine instead of fighting them.

## Extensibility: HAL, Drivers, and the Capability Layer

New NIC families, new link types, new CPU paths arrive as the target world grows
(an AT-class machine wants far more NIC drivers; modern adapters add Wi-Fi, which
needs its own UI). The architecture absorbs them without another byte-scrounge
because **almost all of it is floppy-loaded code selected by the capability
vector** — inactive drivers cost zero resident RAM.

A NIC driver is a self-contained module behind a known **HAL vtable**. The boot
detects the family, loads the active driver, and fills the vtable; only the
*active* driver's hot-path TX/RX is resident (it runs every turn), in a
bounded **active-driver slot**. New families grow the floppy, not the resident
footprint — one driver is ever live.

> **Implemented (Build 13).** The NIC families are packaged as external driver
> files — `NE.DRV` (ne1000/ne2000/Novell), `WD8003.DRV`, `3C503.DRV`, `3C501.DRV`
> under `SEED/DRIVERS/` when included. The shared DP8390 ring is one macro source
> compiled into the three ring cards; `3c501` is fully custom. The boot scans
> `.DRV` files, validates the `SDRV` metadata, ABI version, one-sector size, and
> family mask, then reads one suitable driver into the active-driver slot. One
> match loads automatically; multiple matches show a `which driver?` chooser; no
> match fails as `driver setup failed` through the normal retry/restart path. The
> driver's 10-byte vtable header is copied into the resident dispatch vector
> (`nic_vtable`); the resident TX/RX/enter/restore/rx_fallback path then dispatches
> through it. Inactive or omitted drivers cost zero resident RAM and can be
> replaced on the floppy without replacing `SEED.SYS` when the driver ABI is
> unchanged. The Makefile includes all current drivers by default; set
> `INCLUDE_NIC_DRIVERS=0` to omit all drivers, or set an
> `INCLUDE_NIC_DRIVER_*` switch for a per-driver image.

Wi-Fi is the stress test, and it decomposes cleanly into the existing bands:

```text
driver hot path           -> the resident active-driver slot
scan / SSID-select /       -> floppy-loaded UI phases, loaded only when a Wi-Fi
  passphrase / association     adapter is present (additive, like any phase)
SSID + passphrase          -> a config-model extension (same shape as seed_* values)
WPA2 crypto (PBKDF2, AES)  -> the handshake-only overlay band (setup-time, not
                              per-record — same lifetime as the TLS handshake crypto)
```

So "thinking ahead a few steps" is concrete and cheap: make three seams
extensible now and build the drivers later. (1) The capability vector carries
NIC-family *and* link-type (wired/Wi-Fi), alongside CPU class and FPU. (2) A
driver is a floppy module with a known vtable. (3) The config model grows
without reshaping. The active-driver slot is currently **one sector (512 B)** — it
fits today's worst-case driver (3c503, ~448 B); a larger future driver, or Wi-Fi
(whose scan/SSID UI is additive floppy phases and whose WPA crypto lives in the
handshake-only band), is the case that would size it to two sectors, which on 16K
would cost arena. That sizing is the remaining seam decision, not code to write now.

## Hardware And Handoff Contract

Seed publishes machine state through the handoff block at `0000:0600`. The
target-specific binary layout is in `targets/ibm_pc_5150/HANDOFF.md`. The
handoff is also where the **capability vector lives and grows** — it carries
`ram_top`, NIC family, CPU-class flags, FPU-present, HMA, and
unreal-mode availability. Link type remains a future extension.

```text
build/runtime identity
entry flags
boot drive
video mode and detected text columns
seed text column
NIC base, family, IRQ, and MAC when known
network status and error code
IPv4 address, router, DNS, and subnet
detected RAM top
CPU class, FPU present, HMA, unreal mode
```

On IBM PC 5150-class real-mode hardware, Seed cannot enforce memory protection.
Reserved ranges are contract boundaries, not sandbox walls. Everything outside
Seed-owned ranges is available to the user and agent. Tools may use BIOS calls,
I/O ports, RAM, video memory, NIC registers, disk services, or other hardware
directly when that is the right implementation.

If a tool writes into Seed-owned memory or otherwise violates the published
contract, the tool owns the crash. Seed is not expected to defend itself from
trusted bare-metal tooling.

## User/Agent Environment

The Default Prompt Interface is Seed's disposable starter UI. It is useful
enough to prove repeated chat after boot, but it is not the future environment
and should not accumulate terminal, shell, or operating-system responsibilities.
Each turn assembles minimal local context — a model-compacted rolling note plus the
recent dialogue and current prompt — and the native tool path lets the model call
`read_mem`, `write_mem`, `exec`, `save_env`, and `load_env`. Tool results flow back
as structured `function_call_output` items, not synthetic user prompts.

Seed-owned context management is compact and volatile on the 16 KiB target:
recent prompt/response state, a small rolling summary, and tool-result slots. It
does not depend on writeable boot media and does not turn the hot prompt loop
into a floppy-bound path. This is exactly where the headroom goes: above the
reconnect-safe line, the conversation window and arena are the user's, and they
are what grows on a bigger machine — more context, more room to build.

Long-term semantic agent memory is a later environment concern. Persistent
notes, preferences, project state, and durable workspaces should use formats and
storage chosen by the user/agent environment, with Seed publishing enough memory
and storage facts for that environment to decide for itself.

The remote agent should not be in tight hardware timing loops — network and
model latency make live step-by-step control unreliable on small machines. The
intended post-Seed model is asynchronous:

```text
Seed boots and establishes the provider API path
Seed publishes memory, hardware, and recovery contracts
Seed hands control to the user/agent environment
the environment decides what local tool is needed
the environment owns tool format, loading, calling, and result handling
the tool runs locally at machine speed
the environment uses Seed-published state and any retained API service surface
```

Seed may provide the first handoff mechanism and may retain a tiny service
surface for things that are hard to reconstruct or timing-sensitive (the
provider API channel, published hardware state). It should not own a general
local-tool execution runtime. The machine does not need an underlying OS, shell,
compiler, or command library for Seed itself to fulfill its contract.

## Persistence

Everything the user and agent build at runtime — the conversation, and whatever the
agent pokes into the arena — lives in RAM and is wiped on every restart. When the
boot medium accepts an explicit save write, Seed can persist that state and restore it
at the next boot, so the agent *accumulates across restarts* instead of booting fresh.
Startup does not probe writeability; read-only media remains a clean recovery boundary,
and failed save writes are reported as best-effort status. Save and restore are cold
phases (≈0 resident bytes), so persistence costs nothing on 16 KiB.

**One clean unit: the contiguous user region.** The lifetime-ordered layout already
isolates everything the user/agent owns into one contiguous block above the
reconnect-safe line — the conversation window plus the arena — free of live code,
hardware, and session state by design. That block is exactly what persists. Everything
else in segment 0 is machine-specific and rebuilt every boot:

```text
IVT + BIOS data area         this boot's live vectors, tick/keyboard/disk state
handoff / capability vector  this boot's detected RAM, NIC, IP, MAC, drive
nucleus / driver / crypto    freshly loaded code for this machine's NIC and build
TLS keys / scratch / stack   the session is dead after power-off — must re-handshake
loop cache (32 KiB)          code, rebuilt at boot
```

**Boot as self, restore after the splash.** A literal full-RAM dump would be wrong: it
would clobber the booting machine's live state with a dead snapshot. Instead Seed boots
the machine *as itself* — a normal boot rebuilds the HAL, the network, and a fresh TLS
session — then drops the saved user region into the already-configured pool. There is
therefore **no capability-vector matching on restore**: the machine configures itself
for whatever hardware it has, and only the user bytes come from the file. Restore
**preloads memory; it does not resume a session** — a TLS session cannot survive a
power-off, so a restore boot opens no connection and the user's first message carries
the restored context into a fresh (cold) handshake. Because restore is a *read*, it
works even from write-protected media; `save_env` is the operation that attempts writes.

**Redisplay repaints the literal screen.** Seed also snapshots the video text buffer
(char+attr cells) and paints it back verbatim at restore, so the user lands on the
exact screen they left — prose, dim tool lines, prompts, wrapping and all. This is
deliberately not reconstructed from the conversation window, which is the model-facing
serialization and would look unfamiliar. The paint runs only when the saved column
count matches this machine's; a 40↔80 mismatch clears the screen instead (the window
still restores).

**Triggers.** The native tools `save_env` and `load_env` drive it, and boot auto-loads
`ENV.DAT` when present. `save_env` writes the snapshot to the boot drive (room-checked,
best-effort — a status line if the medium cannot be written or is full); `load_env` is a
mid-session revert that discards the current arena/context pool, restores the saved one, and
redisplays.

**Leaf DER.** The security path owns one separate refreshable file:
`SEED/LEAF.DER`. Standard images ship the current `api.openai.com` RSA leaf there, but it
is not trusted just because it is on the floppy. Before opening a 286+ TLS socket, Seed
reads the file, verifies strict DER, SAN, WR1 signature, and validity dates against the
baked WR1 anchor, and only then adopts it as the leaf pin. After an auto-recertification
verifies a freshly captured leaf, Seed tries to write that DER back to the boot medium.
Missing, stale, malformed, full-media, or write-protected cases fall back to the normal
live-leaf recertify path.

**The restore fit gate** is two tiers. A *silent fail-safe* on magic / format version /
checksum — a corrupt, foreign, or incompatible file is ignored and the machine boots
clean, never bricking the boot and never showing a menu. Then a *memory-fit* check of
the saved region against this machine's arena+context span:

```text
equal                 restore + redisplay silently        (the common same-machine case)
smaller than machine  restore at the saved context cap, warn (surplus becomes arena)
larger than machine   will not fit — error: { new, restart }
```

The warning on a bigger machine exists because restored arena programs keep their
absolute addresses. Seed restores the arena prefix at the same low addresses and keeps
the saved context cap at the far end of the current pool; surplus RAM lands in the
arena.

**Trust.** `ENV.DAT` is the agent's own non-secret state, on a medium that already
holds the plaintext key in `SEED/USER.CFG`. So it uses a checksum for corruption plus the
version/magic gate against foreign files, and no cryptographic integrity (no key
survives a read-only boot, and it is not a secret). One correctness guard: Seed
neutralizes any line-start tool directive in the restored window so last session's
calls cannot re-fire. The byte format is in [`memory.md`](memory.md), "ENV.DAT Snapshot
Format."

## Recovery Boundary

The boot floppy is the trusted recovery boundary. A user must be able to restart
the machine from known Seed media after an agent-built tool hangs the machine,
corrupts RAM, or leaves hardware in a bad state.

Write-protected Seed media is a valid and desirable deployment mode — the floppy
is read-only by policy (see Floppy Policy). Local configuration writes are
convenience only; failed writes must not prevent boot or agent/API use. Faster
boot from `SEED/USER.CFG` is useful when the medium is writable, but read-only media
remains the cleanest physical kill switch.

## Authority Model

Seed is not a security boundary between the user, agent, and machine. If the
user allows an agent-built tool to run, that tool has bare-metal authority. This
is intentional: Seed optimizes for recovery, transparency, and freedom on small
machines rather than for multi-user isolation.

```text
Seed can reboot from trusted media.
Seed can say where it lives and what it needs.
Seed can provide a working agent API path.
Seed can hand off to the user/agent environment.
The environment owns local tooling.
The user and agent get the machine outside Seed-owned ranges.
```

## Guard Philosophy

Memory guard is an execution uncertainty budget, not reserved space for
arbitrary third-party applications. Seed's closed contract removes the classic
need to protect against unknown programs casually stepping on the runtime.

The structural guard in the new shape is the **build-time lifetime checker** (see
One Source of Truth): aliasing is safe because disjoint lifetimes are *asserted*,
not assumed. The runtime guard that remains is the stack reserve — useful for
stack depth, BIOS side effects, packet timing, worst-case config values, and
emulator-versus-hardware variance. For the 16 KiB target it is a measured, thin
execution reserve (~256 B, run thin), accepted only because the collision risk is
covered actively — explicit bound checks, visible loader failure, and a runtime
stack high-water tripwire in validation — rather than by a large idle cushion.

Unused low memory is not reserved for future features by default. Future
features should either fit the published contract or belong to the user/agent
environment.

## One Source of Truth

The memory map should have one authoritative source that generates the
constants, the docs map, and the budget/lifetime checks. `layout.inc` is already
the de-facto source — `tools/memory-map.py` parses its equates and
`tools/core-sys-info.py` reads the `SEED.SYS` header. Build 12 closes the two
real leaks: the Makefile constants duplicated by hand (the budget view can drift
silently), and the per-phase `%error` caps scattered across `core.asm`. Both
fold into one region/lifetime checker driven by `layout.inc`, so the owned
regions of the Memory Shape are checked at build time and nothing drifts.

## Larger Machines

Seed keeps one floppy, one visible `SEED.SYS`, external NIC driver files, and one product contract across
small and larger machines. Larger machines reuse the 32 KiB shape and grow the
arena; they do not become alternate products.

```text
larger conversation window and arena (the default home for headroom)
preloaded normal-turn working set (the cached 32 KiB chat loop)
far conventional, EMS, HMA/native extended, and unreal-mode memory reach
real, authenticated TLS on a 286-class CPU
later: more NIC families and link types, additively
```

The >64 KiB Build 12 path is additive through the relocation seam (near→far dispatch
vectors, above), not a rewrite. EMS bank-switching, 286 HMA/native extended memory, and
386+ unreal mode are Build 12 tiers. TLS 1.3 and the 64-bit, no-BIOS runtime are later work.
