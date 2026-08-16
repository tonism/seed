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

> **Status.** This contract describes the TLS 1.3 integration currently under
> validation: lifetime-ordered low memory, one self-selecting `SEED.SYS`,
> external NIC drivers, native function tools, and RAM scaling from the 16 KiB
> floor through EMS / 286 native extended / 386 unreal mode. The 8088 and 286
> TLS routes are linked, but live original-speed product acceptance is still
> running; PoC measurements are labeled as such. Byte-level maps are in
> [`memory.md`](memory.md), and the exact security claims are in
> [`security.md`](security.md).

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
16 KiB  — the baseline and the canonical shape. Every user-facing product
          function works here, including the agent loop and memory tools.
          This is the functional/recovery floor and the shape the whole
          system is designed around. Transport confidentiality and
          authenticated peer identity remain separate CPU-tier capabilities.
          Inviolable.

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

286+ / 512 KiB — the fully standards-conforming TLS 1.3 tier: genuine
          X25519MLKEM768, P-256 certificate authentication, and a top-relative
          64 KiB conventional-RAM crypto reservation. CPU class and RAM are
          both admission gates.

persistence — if the boot floppy accepts a requested save write, Seed can save
          and restore the conversation window, arena, and screen. Startup does
          not probe writeability.
```

Product-function parity is at 16 KiB. Larger memory and faster CPU tiers add
performance, headroom, wider address reach, persistence when requested writes
succeed, and the fully conforming hybrid TLS route; they do not make the basic
agent/tool loop unavailable on the floor. The 16 KiB route has its own
credential-release boundary, but is not a standards-conforming hybrid. A
user-facing business function that cannot degrade to the 16 KiB shape is a
design failure. Product-function parity must not be read as a claim of equal
transport security across CPU tiers.

## Current Target Snapshot

The active implementation target is an IBM PC 5150-class machine:

```text
CPU              8088-compatible, 4.77 MHz 8088 profile;
                 286 at 6 MHz enables the conforming profile
RAM tiers        16 KiB (ROM BASIC sidecar entry), 32 KiB direct boot, far conventional,
                 EMS, 286/512 KiB conforming floor, HMA/native extended, 386 unreal
media            160 KiB FAT12 product image
video            BIOS text mode, CGA or MDA
network          3c501, 3c503, NE/WD80x3, PCnet/LANCE, DEC Tulip, RTL8139,
                 and EPIC/100 families across the documented ISA/MCA/VLB/PCI paths
runtime file     one visible SEED.SYS plus optional external SEED/DRIVERS/*.DRV NIC files
```

Current TLS 1.3 integration image (`tools/core-sys-info.py`; live product
validation pending):

```text
SEED.SYS total bytes:        150016
SEED.SYS total sectors:      293
resident nucleus sectors:    4   (2048 B; 1495 nonzero B)
ordinary phase entries:      29
application K executable:    10 sectors (inside its 15-sector physical slot)
8088 TLS 1.3 cold pack:      130 sectors, file sectors 45..174
286 TLS 1.3 tail:            82 sectors, file sectors 212..293
  module cache:              44 sectors / 22528 bytes
  root / entropy / hello /
    flight / auth / footer:  38 sectors
```

The resident nucleus is still fixed at four sectors; current growth is cold
phases and high-memory modules, not a larger always-resident Seed. The
15-sector K slot retains five sectors of geometry headroom; those padded file
sectors are not executable arena. The current 160 KiB composition uses 308 of
309 FAT data sectors: 293 runtime sectors plus 15 auxiliary sectors. One FAT
data cluster (one sector on this image) remains free as a required packaging
guard. Consequently, the current universal `SEED.SYS` has zero usable
sector-growth headroom even though the FAT itself has one unallocated cluster.

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

TLS trust state is part of `SEED.SYS` or volatile RAM: the 8088 route uses an
immutable exact-leaf object, while the 286 route bakes the WE1 P-256 issuer
point and generates the leaf tables on the target. No `LEAF.DER` file is
packaged and no writable-medium trust cache is required.

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
  -> helper atomically redirects INT 1Ch to the resident IRET at 0000:15ff
  -> helper passes AX = RAM top, BX/CX = "SEED" magic, DL = boot drive
  -> jump 0000:1000
```

The BASIC loader at `0x3a00` is entry-time only and is deliberately placed in
memory that later becomes Seed critical scratch. Once it jumps to `SEED.SYS`,
the BASIC runtime and sidecar loader are abandoned. RAM top is the first input
to the capability vector — it selects the 16 KiB or 32 KiB layout.

ROM BASIC also owns the BIOS timer callback at INT 1Ch. Seed reclaims BASIC's
workspace, so leaving that vector live would let the 18.2 Hz callback interpret
overwritten BASIC state as its own. After the complete resident prefix is in
RAM, the sidecar disables interrupts, publishes `0000:15ff` as the complete
INT 1Ch vector, and enters Seed without re-enabling interrupts. The target byte
is a permanent `IRET` in the final byte below the active NIC-driver slot; it is
loaded by every entry path and is never overwritten. Direct boot does not
rewrite INT 1Ch.

## The One-Artifact Relocation Model

A single `SEED.SYS` runs every current x86 tier, and the capability vector
selects what loads and where. The foundational question is *how* a tier's code
is placed — and the answer is **hybrid: two build-time-fixed low entry shapes,
cold CPU/TLS packs inside the same file, and tier-varying entry points reached
through a small fixed dispatch-vector table.**

Because the tiers are locked at two, both layouts are fully known at build time,
so "relocation" never needs runtime address arithmetic:

```text
16 KiB layout   the canonical shape (below). Demand-loads phases and tools schema from floppy.
                Zero relocation tax — the hot path keeps fixed addressing.

32 KiB layout   the SAME shape, plus a few optional modules placed at
                build-time-fixed high addresses: the chat loop's working set,
                tools schema, and low decoded-module overlay.
                Everything else above is arena.

>32 KiB         the 32 KiB layout plus detected memory-reach backends. Module
                addresses do not move; only the arena/context map grows.

286/512 KiB     the same low entry plus a 64 KiB top-relative conventional
                reservation. The complete cold pack is cached high; one module
                at a time decodes into the fixed low overlay.
```

The handful of entry points that differ by tier — the phase loader's
preload-vs-demand decision, the active NIC driver, and the two TLS routes —
are called **indirectly through a fixed low vector table** that
the boot fills from the capability vector. The calls are coarse-grained
(per-phase, per-record, per-handshake), so the indirection costs a few bytes and
a few cycles, never a per-instruction tax. The 16 KiB hot path — a three-sector
shared resident span plus a one-sector active NIC driver, followed by crypto
inner loops with no spare registers — pays none of it. The final shared byte is
the permanent ROM-BASIC timer `IRET`, so the last-nonzero envelope intentionally
reaches the end of that three-sector span without consuming executable-code
headroom.

**Why not runtime-relative addressing.** Setting region bases at runtime (a base
register or segment per region) is maximally flexible and would let code load
anywhere. But on the 8088 it taxes exactly the two most-constrained resources in
the system: the resident nucleus (no room for relocation prologues) and the
register-starved crypto inner loops (the 286 secure handshake is already on a
~1 s knife-edge). It buys geometry-flexibility that the locked entry model has
defined away. The 286 TLS 1.3 route adds a top-relative conventional-memory
reservation and fixed low module overlay, but still enters through the same
resident nucleus. Fixed placement remains appropriate for the bounded low
windows; high-memory buffers are described through explicit segment:offset
descriptors.

**The seam for the >64 KiB tiers.** The vector table *is* the escape hatch.
Most hot code still calls near pointers inside segment 0; far conventional, EMS,
286 native extended, and 386 unreal mode sit behind memory-HAL helpers and the same
native tool / context-streaming call sites.

**Future ISAs and no-BIOS entry.** “One product” does not require one native
instruction stream across x86 and ARM. A future distribution can keep the
user-facing zero-choice experience by using the smallest firmware-native entry
shim to detect the ISA/firmware and load the matching payload from one package.
The current floppy remains one x86 `SEED.SYS`; 64-bit addressing and a
no-BIOS/UEFI path remain later work and must not enlarge the 16 KiB nucleus.

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
asserts it** — killing the recurring alias-bug class. The
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

The floppy is the **read-only recovery boundary**. Demand-loading immutable
code from it is preferred whenever that gives RAM back to the arena. Neither
TLS tier needs writable media, persistent tickets, a precomputed private key,
or help from another machine.

Timing-sensitive spans are explicitly preloaded:

```text
16 KiB   cold-loads each bounded TLS 1.3 phase when its lifetime begins. The
         fresh deadline phase preloads its exact code/data set. Later proof
         phases may read the floppy while no credential is reachable; a
         credential-free dialogue or same-boot ticket can bridge connection
         closure without turning disk into mutable state.

32 KiB   preloads ONLY the normal chat loop's working set (its phases + the streamed
         IDENTITY prompt) so ordinary turns are floppy-free. The rare COMPACT prompt
         can still stream from floppy.

286      reads and validates the complete 44-sector asymmetric module pack into
         its top-relative 64 KiB reservation before opening TCP. Before each
         live connection it also stages the immutable 12-sector 8088
         symmetric image in the high record quarantine, verifies its already-
         canonical SHA initial-state operand, and restores the canonical
         288-byte SHA tail before publishing that stage READY. The final
         connection additionally derives
         the ticket-only early secret and generates the public nine-polynomial
         ML-KEM A^T matrix before TCP. Only one decoded module occupies the low
         overlay at a time.
```

On a 32 KiB direct boot, the boot reads the loop's working set — the chat-loop
phases, application-record window, and IDENTITY prompt — into a high RAM cache
once (`loop_cache`, above the arena/context pool and below the stack). The phase
loader and prompt streamer then serve ordinary turns from RAM. The rare
compaction turn may still stream COMPACT from floppy. The arena/context ceiling
drops to the cache base, and the ledger advertises that ceiling so an agent
write cannot land in the cache. The 16 KiB path remains demand-loaded.

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
  -> B: draw the seed build splash and 8088 security note before driver/network setup
  -> 2: scan SEED/DRIVERS/*.DRV and load a suitable detected-family NIC driver
  -> Z: 386 unreal setup when present
  -> I: packet I/O initialization

internet phase (still ".")
  -> D: DHCP setup

agent phase "o"
  -> A: OpenAI declaration from SEED/AGENTS.CFG or built-in fallback
  -> U: SEED/USER.CFG load/parse
  -> Q: prompt for any missing OpenAI key/model/reasoning values
  -> E/V: fixed OpenAI endpoint and validated config cache
  -> R: request construction
  -> G/J: context mirror or extended-memory context chunk reads when required
  -> dispatch by CPU/RAM capability:
       8088 profile:
         escrow config -> collect local floppy timing -> cold-load K14 phases
         -> connect -> provisional TLS 1.3 Finished + bounded ticket receipt
         -> full FO + exact dated-leaf/CV proof
         -> one-shot resumed 0-RTT HEAD + authenticated liveness
         -> atomic credential unlock
       286 / 512 KiB conforming route:
         N: silently obtain a coherent platform-UTC RTC value and preserve the
            prompt working set in an arena-excluded RAM shadow
         -> cache/validate 286 pack -> acquisition connection
         -> stage the immutable symmetric image before opening acquisition TCP
         -> provisional hybrid proof, client Finished, literal credential-free
            HEAD, and authenticated tentative NewSessionTicket
         -> offline full FO comparison plus WE1/leaf/time/CV validation and
            table generation; promote the same-boot ticket
         -> no-0RTT PSK-DHE resumption with independent X25519MLKEM768 keys,
            a real binder, selected_identity=0, and pre-TCP symmetric-image,
            early-derived, and public-matrix caches
         -> after ServerHello, consume the public matrix for complete full FO
            decapsulation, then accept only a strict
            EncryptedExtensions-to-Finished flight
         -> send client Finished and publish application keys/credentials
  -> K/X: TLS 1.3 application records, encrypted request, application receive
  -> T: parse the received application-data chunk for the returned answer
  -> S: best-effort SEED/USER.CFG save if values changed

prompt loop "Default Prompt Interface"
  -> render the model greeting, then take prompts on the live (reused) TLS session
  -> each turn builds the request, streams the reply, then cold native-tool phases run any
     function_call (`read_mem`, `write_mem`, `exec`, `save_env`, `load_env`) and replay the
     function_call_output back to the model (see "Demo" below)
  -> on a human no-text failure, rebuild one fresh route and resend once
  -> never replay a tool continuation or partially rendered response

failure
  -> F: mark the current phase red, type the error, offer retry/restart
  -> retry returns to the hardware "." phase without rereading resident sectors
```

The same resident TCP/NIC callbacks serve both TLS routes. The current provider
and hostname are fixed to OpenAI; alternate `AGENTS.CFG` entries do not select
an alternate security path.

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
K   10/15    0x1800     10-sector TLS 1.3 application executable in a 15-sector slot
F   2        0x0700     failure action UI
H   4        0x0700     hardware/display/NIC discovery
2   2        0x0700     scan/load suitable NIC driver from SEED/DRIVERS/*.DRV
0   1        0x3600     286 HMA/native extended-memory layout
Z   1        0x0700     386 unreal-mode setup/refresh support
I   1        0x0700     packet I/O initialization
D   3        0x0900     DHCP setup
N   2        0x0900     platform RTC + diskless loop-cache shadow parent
C   3        0x0900     TCP connect
L   3        0x0700     fixed TLS 1.3 286 bootstrap
E   1        0x0700     OpenAI endpoint setup
A   2        0x0700     SEED/AGENTS.CFG OpenAI config
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

Phases that do network I/O — `D`, `C`, `R`, `X`, `T`, `W` — load at
`0x0900` when they need to coexist with the TCP/NIC scratch or share that larger
network window between turns. The 286 extended-layout phase `0` loads at `0x3600`
because it runs while the high scratch band is still available. Most remaining
cold phases load at `0x0700`. This
phase-streaming design is what lets a TLS 1.3 record path — ChaCha20-Poly1305,
SHA-256, HTTP/1.1, SSE streaming — run in 16 KiB on a 4.77 MHz 8088: only the
nucleus and the crypto window stay resident, while the other phases stream from
the floppy and take turns in one small window. The public vault and
provisional/quarantine schedule are what keep the full 8088 route from
displacing the 96/96-byte user pool.

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

A 4.77 MHz 8088 cannot complete every asymmetric operation inside one
provider connection deadline. The architecture no longer treats that as a
binary choice between a fast insecure handshake and a standards-complete one.
It keeps credentials unreachable while the same original machine finishes the
proof in cold-loaded phases.

### 8088: bounded work before credential release

The 8088 profile has three timing domains:

```text
before TCP
  collect and condition local read-only floppy timings
  generate the ML-KEM-768 keypair
  resolve the fixed OpenAI target and preload the deadline phase

fresh provider deadline
  send TLS 1.3 ClientHello
  verify protected flight and exact server Finished under the provisional candidate
  send client Finished and attempt one literal credential-free HEAD
  retain one bounded tentative same-boot ticket; an authenticated
    ticket-bearing close is a quarantined receipt, not liveness

after the deadline, still on the 8088
  complete full ML-KEM FO validation and traffic-secret comparison
  verify possession of the image's dated exact leaf and the saved CertificateVerify
  resume with fresh KEM work and the one-shot tentative ticket
  send the same fixed HEAD as 0-RTT and authenticate its response
  restore/scrub volatile state, then publish credential access status-last
```

The wire group is `X25519MLKEM768`, but the 8088 fixes X25519 to `u=9`.
Consequently this is effective ML-KEM-only key exchange and not a
standards-conforming hybrid. The fixed HEAD is a real but credential-free
external effect; no key, prompt, context, redirect, or tool continuation is
reachable before full commit. The complete rationale is in
[`security.md`](security.md).

The date is trusted image provenance, not a target-time check: the 8088 has no
trusted runtime clock. Leaf rotation or the image object's validity end
requires a refreshed trusted image.

The exact-floor route must put fresh client Finished on the wire before the
provider close. Credential-free liveness may complete on that socket or on the
immediately paired resumed 0-RTT connection after an authenticated ticket/close
receipt and offline proof. These are measured compatibility boundaries, not a
service SLA; the provider's observed close is near 15 seconds and may vary.

The route stays inside 16 KiB by loading one immutable phase at a time and
placing 3,328 bytes of public objects in a guarded video-RAM vault. On MDA the
guard combines output-disable with one-column scanout redirected to a zeroed
out-of-page quarantine; ordinary scanout returns only after the visible page
is scrubbed. The vault
is neither NIC RAM nor writable-floppy scratch. Its 867-byte stateless access
leaf is duplicated or staged by consuming phases, and all vault state is
zeroized at route completion or failure. The user-facing low pool remains a
96-byte executable arena plus 96-byte context window.

### 286: conforming hybrid with certificate work off the timer

The 6 MHz / 512 KiB tier reserves the top 64 KiB of conventional RAM. Its
remaining far pool is `0x10000..0x70000`, 384 KiB split into a 192 KiB
executable arena and 192 KiB context window. Certificate validation still
does not fit comfortably inside the provider's observed close, so the route
uses a same-boot ticket as a quarantined bridge between acquisition and the
credential-bearing connection:

```text
acquisition connection
  independent ML-KEM-768 + X25519 key generation
  use the exact ML-KEM candidate only provisionally
  verify protected records and server Finished
  capture ordinary Certificate + CertificateVerify
  send client Finished and the immutable credential-free HEAD
  authenticate the HTTP response and one NewSessionTicket
  publish that ticket only as TENTATIVE

offline, no provider timer
  perform complete ML-KEM FO decapsulation and constant-time candidate compare
  validate platform-UTC certificate dates, api.openai.com, purpose, and WE1
  verify acquisition CertificateVerify and generate P-256 G/leaf tables
  promote the same-boot ticket only after every proof succeeds

final credential-bearing resumption
  consume the promoted ticket before reading its PSK or identity
  stage the immutable 12-sector symmetric image before opening TCP
  generate an independent ML-KEM-768 + X25519 attempt
  send a real PSK binder with no early_data and require selected_identity=0
  derive the ticket-only early secret and precompute the public nine-polynomial
    ML-KEM A^T matrix before TCP
  after ServerHello, consume the matrix and complete full ML-KEM FO
    decapsulation plus X25519 shared-secret derivation
  accept only EncryptedExtensions followed by Finished
  verify server Finished, send client Finished and the credential-free HEAD
  require a complete authenticated ticket plus an allowed HTTP status
  publish application keys with the consumed server-record sequence; a missing
    response-header terminator does not hold credentials indefinitely
  only now make the API key and business request reachable
```

The final route is no-0RTT PSK-DHE resumption: the PSK authenticates the
same-boot ticket, while the independent genuine `X25519MLKEM768` exchange
provides fresh hybrid key agreement. There is no compressed certificate,
persisted ticket, persisted leaf, mutable trust file, early data, or no-time
bypass. The immutable trust object is the WE1 P-256 point. A coherent BIOS RTC
is used silently as the machine's configured platform UTC clock, as on a
conventional TLS client. Invalid, incoherent, or out-of-range values fail
closed. Unauthenticated NTP and user confirmation are not trust inputs.

The three pre-TCP caches are scheduling devices, not deferred security checks.
The symmetric image is published only after all twelve read-only floppy reads
complete, consumed before it is copied low, relocated, and checked by its
existing image CRC. The 32-byte resumption early-derived value is stored beside
its bytewise complement, published status-last, consumed before import, and
wiped in full. The 4,608-byte public ML-KEM matrix is likewise published
status-last and consumed once before cached decapsulation. Missing, torn, or
replayed status fails before the corresponding consumer runs. Matrix payload
corruption cannot skip FO: the cached path still performs the complete FIPS 203
ciphertext comparison and branchless implicit-rejection selection, so a wrong
cache produces the rejection secret and cannot pass server Finished. The
record-open path retires the staged public bytes before authenticated plaintext
uses the quarantine, and abort/restart scrubs the reservation.

Exact 6 MHz, 512 KiB tick-aligned target measurements show why this schedule is
useful: public matrix generation costs 45 ticks / 2.4716 s before TCP; full FO
costs 43 ticks / 2.3618 s with the cache versus 88 ticks / 4.8334 s without it.
The current conservative serialized CPU windows are 162 ticks / 8.8979 s for
acquisition and 168 ticks / 9.2275 s for final resumption. The exact-floor
read-only live reconnect capture independently measures all four fresh/resumed
critical intervals below nine seconds and returns authenticated OpenAI text.

The candidate ML-KEM path is deliberately not an authority boundary. The
offline full FO comparison, X.509/hostname/time/WE1/CV checks, and
status-last ticket promotion all precede the final credential connection.
Offline component and serialized timing gates remain structural evidence, not
a substitute for the live pcap. The integrated 6 MHz / 512 KiB single-profile
wire/reconnect trace and the injected CPU/RAM/time/entropy/auth/Finished/FO/
pack/abort gates pass. Physical entropy characterization and additional
provider-edge repetition remain open.

### Entropy and validation boundary

Both routes generate private material on the target and work from a
write-protected floppy. The 8088 route SHA3-conditions PIT-bracketed floppy-read
timings. The 286 route performs no entropy-only disk reads: it polls the AT
RTC's 4,096 Hz periodic flag, samples that independent oscillator against PIT
channel 0, applies online health tests, then uses SHA3 and HMAC_DRBG. Emulator
runs receive zero entropy credit. Representative physical traces,
source-specific conservative min-entropy estimates, and calibrated health
cutoffs remain open before a secure-floor claim.

### Session reuse and bounded reconnect

After commit, ordinary turns reuse one live session and pay only record crypto.
If a human request fails before any response text appears, Seed retires the
channel, cold-builds one fresh tier route, reconstructs the same prompt, and
sends it once more. A second failure returns to the prompt. Text-seen responses
and tool/agent-loop continuations are never automatically replayed.

Thus resumption and reconnect improve availability but never extend the trust
boundary: every fresh route repeats its tier's mandatory proof, and tentative
tickets cannot make application credentials reachable.

### Integration risks and open questions

- The provider close near 15 seconds is observed behavior, not an SLA. Both
  exact-floor routes have current live margin evidence but need more repetition
  across cold boots and edge variation. The 8088 profile requires fresh
  Finished plus bounded ticket/close receipt before the
  paired resumed 0-RTT liveness exchange; the conforming route still requires
  its complete acquisition/HEAD/ticket exchange. Both need further live
  margin characterization.
- Emulator entropy has zero credit. The physical 8088 floppy source and 286
  RTC/PIT source may not support their provisional min-entropy assumptions or
  health cutoffs.
- The 8088 exact-leaf route lacks trusted runtime time and general issuer-based
  rotation. Its image object has an operational expiry/update requirement.
- A ticket may be absent, malformed, rejected, or expire before offline proof
  completes. The route must fail closed or reacquire within its bounded policy;
  it must never fall back to a credential-bearing provisional connection.
- The 160 KiB image retains one unallocated FAT data sector as a required
  packaging guard, leaving zero usable `SEED.SYS` sector-growth headroom.
  Further cold code needs deletion/compression, a larger media profile that
  does not fragment the user experience, or revised package geometry.
- The video-RAM vault has extensive CPU-emulated hostile gates and clean 86Box
  CGA/MDA active-hold plus post-scrub redraw evidence. Physical adapter scanout
  behavior remains unverified. MDA intentionally has no changing live UI
  during the vault lifetime; any binary/random glyph screen is an acceptance
  failure.
- The product 8088 profile passes all seven original-speed NIC profiles;
  this does not grant permission to disturb the stable driver surface. Shared
  TCP/TLS changes continue to require the documented NIC regression matrix.
- OpenAI is the only current wire profile. Adding a provider is an explicit
  certificate/protocol/timing architecture task, not another config row.

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

> **Implemented.** The NIC families are packaged as external driver
> files — `NE.DRV` (NE1000/NE2000/Novell), `WD80X3.DRV`, `3C503.DRV`,
> `3C501.DRV`, `PCNET.DRV`, `TULIP.DRV`, `RTL8139.DRV`, and `EPIC100.DRV`
> under `SEED/DRIVERS/` when included. The shared DP8390 ring is one macro
> source compiled into the three ring cards; the other families have their
> own device paths. The boot scans
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
without reshaping. The active-driver slot is currently **one sector (512 B)** —
every current driver image is exactly one sector; a larger future driver, or Wi-Fi
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

**TLS trust is not persisted.** TLS 1.3 ships no mutable leaf file. The 8088
exact-leaf point and the 286 WE1 issuer point are immutable program assets.
Captured certificates, generated P-256 tables, tentative tickets, attempt
bundles, and traffic keys are same-boot RAM state and are scrubbed or lost on
restart. A restored environment therefore repeats a complete cold tier route
before its first request.

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
`tools/core-sys-info.py` reads the `SEED.SYS` header. The current implementation closes the two
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
64 KiB top-relative TLS reservation on the 286/512 KiB conforming tier
later: more NIC families and link types, additively
```

The >64 KiB path is additive through the relocation seam (near→far dispatch
vectors, above), not a rewrite. EMS bank-switching, 286 HMA/native extended
memory, 386+ unreal mode, and TLS 1.3 are current integrated tiers under
validation. The 64-bit, no-BIOS runtime remains later work.
