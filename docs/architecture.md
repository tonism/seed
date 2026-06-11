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

> **Status.** This contract describes the capability-tiered architecture being
> implemented as Build 12 on `work/scaling`. The shape — tiers, lifetime-ordered
> memory, the capability vector, the relocation model — is settled here and is
> what new code is built against. The redesign lands in staged, matrix-green
> increments (no big-bang); the byte-level maps are regenerated into
> [`memory.md`](memory.md) once the boundaries are drawn and the new shape runs.
> Measured numbers below are from the current tree and the crypto spike
> (`tools/crypto-bench/results/FINDINGS.md`); they are re-measured as Build 12
> runs.

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
different products. The vector's primary dimensions today are **RAM** and **NIC
family**; it also *holds* (carries, even where nothing acts on them yet) **CPU
class** and **FPU present**, so future code can switch on them without another
handoff change. Everything that can scale, scales by tier off this one vector.

There are exactly **two RAM tiers, locked**, plus one CPU-class capability:

```text
16 KiB  — the baseline and the canonical shape. EVERY feature works here,
          including the fast crypto. This is the recovery/identity floor and
          the shape the whole system is designed around. Inviolable.

32 KiB  — the convenience tier. The chat loop no longer reads the floppy
          mid-conversation (it preloads its working set at boot), and the rest
          of the headroom becomes a much larger conversation window + arena.
          No new REQUIRED functionality — only performance and headroom.

>32 KiB  — NOT a third tier. Reuses the 32 KiB shape and simply keeps growing
          the contiguous arena up to detected ram_top. There were only ever two
          configurations to boot (16 KiB and 32 KiB, confirmed on hardware).

286+     — a CPU-class capability, orthogonal to RAM: the first processor fast
          enough to run a real, authenticated TLS handshake inside the
          provider's window (see CPU And Crypto Budget). "Secure" is a 286 tier,
          never the 16 KiB / 4.77 MHz floor.
```

Functional parity is at 16 KiB. The 32 KiB and 286 tiers add performance,
headroom, and — on the 286 — real confidentiality; they never add functionality
the baseline lacks. A feature that only works above 16 KiB is a design failure.

## Current Target Snapshot

The active implementation target is an IBM PC 5150-class machine:

```text
CPU              8088-compatible, 4.77 MHz (baseline); 286 enables the secure tier
RAM tiers        16 KiB (ROM BASIC sidecar entry) and 32 KiB (direct floppy boot)
media            160 KiB 5.25-inch FAT12 floppy image, write-protected
video            BIOS text mode, CGA or MDA
network          3c501, 3c503, NE1000/NE2000, Novell NE1000, WD8003 families
runtime file     one visible CORE.SYS
```

Current measured image (`tools/core-sys-info.py`, this tree):

```text
CORE.SYS total bytes:        27648
CORE.SYS total sectors:      54
resident nucleus sectors:    4   (2048 B; 2033 B used — effectively full)
phase count:                 19
provider-critical K window:  14 sectors / 7168 bytes (0x1800..0x33f7)
K-window slack to scratch:   9 bytes  (the forcing function — see below)
```

That 9-byte slack is why the layout is being redesigned rather than extended:
the verified crypto speedup the baseline now requires does not fit the shape it
inherited. See Memory Shape and CPU And Crypto Budget.

## Boot Artifact

The floppy is a small FAT12 image with a reserved boot loader and one normal,
visible runtime file:

```text
160 KiB FAT12 floppy
|
| sector 1       boot sector with BPB
| sectors 2-5    reserved loader
| sectors 6-7    FAT copies
| sectors 8-11   root directory
| sector 12+     file data
|                CORE.SYS is the first FAT data file
|                AGENTS.CFG, optional USER.CFG, then IDENTITY + COMPACT follow
```

`CORE.SYS` is one file-backed runtime. The build splits its source into NASM
include files and cold phases, but the release artifact remains one visible
`CORE.SYS`. **One artifact ships every tier** (see The One-Artifact Relocation
Model). The only thing that would ever justify a second image is a fundamentally
different ISA — an ARM/RISC port where binary reuse is literally impossible.
Compile-time multi-build per tier is out.

`IDENTITY` and `COMPACT` are the two static system prompts (the agent's identity,
and the compaction contract). They live on the floppy and are streamed into the
request mid-chat rather than baked into a phase image — portable,
hardware-agnostic text that never names the machine it runs on.

## Entry Paths

Seed has two entry paths into the same resident nucleus. Both end by jumping to
`0000:1000` with the capability inputs (RAM top, boot drive) in place.

```text
32 KiB and larger  (direct floppy boot)
---------------------------------------
BIOS loads boot sector at 0000:7c00
  -> stage 1 reads the reserved loader to 0000:0600
  -> loader reads the CORE.SYS root entry and FAT chain
  -> loader reads only the resident CORE.SYS sectors to 0000:1000
  -> loader detects RAM (int 0x12), passes RAM top + "SEED" magic + boot drive
  -> jump 0000:1000

16 KiB path  (ROM BASIC sidecar)
--------------------------------
machine enters ROM BASIC
  -> user pastes the generated SEED24A.BAS / SEED24B.BAS sidecar text
  -> BASIC pokes a tiny 8086 loader at 0000:3a00
  -> helper reads the resident CORE.SYS sectors from the Seed floppy
  -> helper passes AX = RAM top, BX/CX = "SEED" magic, DL = boot drive
  -> jump 0000:1000
```

The BASIC loader at `0x3a00` is entry-time only and is deliberately placed in
memory that later becomes Seed critical scratch. Once it jumps to `CORE.SYS`,
the BASIC runtime and sidecar loader are abandoned. RAM top is the first input
to the capability vector — it selects the 16 KiB or 32 KiB layout.

## The One-Artifact Relocation Model

A single `CORE.SYS` runs every tier, and the capability vector selects what
loads and where. The foundational question is *how* a tier's code is placed —
and the answer is **hybrid: two build-time-fixed layouts inside one image,
selected at boot, with the few tier-varying entry points reached through a small
fixed dispatch-vector table.**

Because the tiers are locked at two, both layouts are fully known at build time,
so "relocation" never needs runtime address arithmetic:

```text
16 KiB layout   the canonical shape (below). Demand-loads phases from floppy.
                Zero relocation tax — the hot path keeps fixed addressing.

32 KiB layout   the SAME shape, plus a few optional modules placed at
                build-time-fixed high addresses: the chat loop's working set
                preloaded resident, and (on a 286) the real-crypto modules.
                Everything else above is arena.

>32 KiB         the 32 KiB layout with the arena ceiling (ram_top) raised. The
                module addresses do not move; only the arena grows.
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

**The seam for the >64 KiB future.** The vector table *is* the escape hatch.
Today the vectors hold near pointers inside segment 0; a future EMS / unreal /
protected-mode tier makes them far (`segment:offset`) pointers without touching
a single call site. That is the segment-model-aware seam — designed for, not
built now (YAGNI). "Gigabytes" remains its own future redesign; this contract
only promises not to block it.

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
conversation window + USER/AGENT ARENA  ─────────►  session-persistent → ram_top
stack guard / stack
```

Two ideas carry the weight:

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

32 KiB   preloads ONLY the chat loop's working set (its phases + the streamed
         IDENTITY/COMPACT prompts) so the loop is floppy-free. It does NOT
         greedily preload everything it could — the rest stays on floppy and
         that RAM becomes arena. Boot-time reads are encouraged when they buy
         loop-time RAM.
```

## Runtime Step Order

The resident nucleus is a small scheduler plus shared hardware, UI, filesystem,
network, and state primitives. It reloads cold phases from the same `CORE.SYS`
file as needed.

```text
entry normalize
  -> set stack from BIOS path or BASIC-provided RAM top
  -> clear low and high runtime scratch
  -> record boot drive + RAM top in the handoff (capability vector seed)

hardware phase "."
  -> H: display, handoff, adapter discovery (sets NIC family in the vector)
  -> I: packet I/O initialization

internet phase (still ".")
  -> D: DHCP setup
  -> C: TCP connect to a generic probe path

agent phase "o"
  -> A: AGENTS.CFG load/parse or built-in fallback
  -> U: USER.CFG load/parse
  -> Q: prompt for any missing agent/server/key/model/reasoning values
  -> E: selected-agent endpoint and DNS name preparation
  -> R: request construction
  -> K: load the provider-critical crypto window
  -> L: build TLS ClientHello and low crypto constants
  -> C: TCP connect to the selected provider on port 443
  -> K: TLS server proof, key schedule, encrypted request, application receive
  -> T: parse the received application-data chunk for the returned answer
  -> S: best-effort USER.CFG save if values changed
  -> B: splash/result screen

prompt loop "Default Prompt Interface"
  -> render the model greeting, then take prompts on the live (reused) TLS session
  -> each turn builds the request, streams the reply, then a cold tool phase runs any
     $r/$w/$x and loops the result back to the model (see "Demo" below)
  -> reconnect (reload-before-race, then retry) only on a real drop

failure
  -> F: mark the current phase red, type the error, offer retry/restart
  -> retry returns to the hardware "." phase without rereading resident sectors
```

The same TCP connect phase serves the internet probe and the selected provider;
it is loaded into the network setup window each time it is needed.

## Phase Windows

`CORE.SYS` starts with a resident nucleus and a phase table. The phase loader
addresses phases by sector offset inside `CORE.SYS`, so keeping `CORE.SYS` first
in the FAT data area is part of the boot contract. The phase table is build
metadata (tools and the header read it); runtime dispatch is by sector offset,
and *which* copy a phase runs from — demand-loaded low, or preloaded high on
32 KiB — is the capability-vector decision routed through the dispatch table.

Current 19-phase layout (regenerate with `make inspect` / `tools/core-sys-info.py`):

```text
id  sectors  load addr  responsibility
K   14       0x1800     provider-critical crypto: SHA-256, ChaCha20-Poly1305, TLS, API
F   1        0x0700     failure action UI
H   4        0x0700     hardware/display/NIC discovery
I   1        0x0700     packet I/O initialization
D   3        0x0900     DHCP setup
C   3        0x0900     TCP connect
L   2        0x0700     TLS ClientHello and low crypto constants
E   1        0x0700     selected-agent endpoint setup
A   2        0x0700     AGENTS.CFG provider config
U   2        0x0700     USER.CFG persisted user values
Q   3        0x0700     agent selection and missing-value prompts
R   3        0x0900     API request construction
V   1        0x0700     agent/endpoint cache
X   3        0x0900     application-data stream (encrypted send/receive)
T   1        0x0d00     agent response parse
B   1        0x0700     splash/result display
Y   1        0x0700     Default Prompt Interface chat loop
M   2        0x0900     minimal tool calling ($r/$w/$x): scan window, execute in seg 0
S   1        0x0700     best-effort USER.CFG save
```

Phases that do network I/O — `D`, `C`, `R`, `X` — load at `0x0900` so they
coexist with the TCP/NIC scratch; the `M` tool phase shares that window since it
runs between turns when the network scratch is idle; the response parser `T`
loads at `0x0d00`; every other cold phase loads at `0x0700`. This
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
R  build request: instructions (RAM-tool grammar $r/$w/$x) + ledger (RAM size, IP, NIC,
     and a@ = the free seg-0 arena base) + the JSON-escaped window + the prompt
X  application-data stream: encrypt with the resident crypto window (ChaCha20-Poly1305)
     and send over the live (reused) TLS session, then receive the streamed reply - the
     renderer draws prose but HIDES any $-command (kept in the window for the tool phase,
     shown once as a dim echo)
M  tool phase (cold, loaded between turns): scan the window for
     $r ADDR LEN / $w ADDR BYTES / $x ADDR; execute each in segment 0 -
     read bytes / poke bytes / CALL the address; append a readable result line back
     INTO the window (model-facing) + a dim "read from / write to / jump to <addr>" line
   loop: a fired tool arms auto-continue - the next turn carries the tool result and the
     model acts on it, up to 8 hops, then control returns to the user
```

Worked example (validated): asked to write `b8 34 12 c3` (x86 `mov ax,0x1234;
ret`) into the arena and run it, the model `$w`s the four bytes, `$x`es the
address, and `AX=0x1234` comes back through the window. It is deliberately
minimal — four hand-aimed bytes, not general code generation — but the loop is
real end to end: a cloud model authored machine code and a 1981 PC ran it. There
is no sandbox; a `$x` into bad code hangs the machine, and recovery is a reboot
from trusted media (see Authority Model and Recovery Boundary).

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

The resource profile, measured by packet-capture timing across two boots (the
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

The TLS handshake is ~14.5 s of the CPU pinned flat-out — SHA-256 hashing the
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
on a full 16 KiB machine the extra sector comes from the only elastic region, the
arena — `high_crypto_scratch` base-raises by 512 B and the **arena goes 833 B →
321 B** (still functional; the conversation window and boot/chat buffers are
separate). **32 KiB is unaffected** — its arena is large and 512 B is noise, which
is the real shape of the trade: faster crypto everywhere, paid for in 16K arena,
free on the scale tier. It is also *load-bearing for the 286 secure tier* (below).

And the part that is *not* tractable on the 8088 — the honest gap:

- **The P-256 key exchange is skipped — a speed wall, not a size one.** The real
  constant-time primitives are written, cross-checked against OpenSSL, and fit
  in ~3.4 KiB, but one scalar multiply is 110.8 s here, so they are compiled
  out. The boot path substitutes a scalar-1 stub: the server's public X
  coordinate *is* the premaster, so **no key agreement happens** — anyone
  capturing the handshake derives every session key (`tools/tls-decrypt.py` does
  exactly that). Server-certificate authentication is also skipped (RSA-2048
  verify ~43 s, ECDSA-P256 ~220 s on the 8088 — both out of reach), so the
  channel is unauthenticated.
- **Real entropy would not help on its own.** The client random is only a nonce;
  with a public premaster, making it unpredictable buys no confidentiality.
  Entropy matters only once a real per-session *secret* exists. It is a cheap
  *prerequisite* (~0.16 s), never a standalone fix.
- So on a stock 8088 the public-key story is CPU-gated to minutes, and the
  product stays honestly **encrypted but not secure**.

**Security begins at the 286** (measured, same harness). An FPU does *not*
rescue the 8088 (SHA is FPU-immune; the P-256 reduction/carry work dominates) —
the real lever is CPU class. An optimised real ECDHE (Solinas + Karatsuba +
wNAF P-256, OpenSSL-verified) is 6.6 s on the lowest 6 MHz 286, and a full
cert-authenticated handshake (ECDHE + RSA-2048 verify 6.37 s + the fast PRF)
fits the provider's ~15 s window: **~13.8 s at 6 MHz** (a knife-edge, and only
with the 4.64× SHA win) and a comfortable **~10.4 s at 8 MHz**. So a real secure
channel is a **286@8+ tier** today.

> **Full 286 coverage is a Build-12 prerequisite, not a free byproduct.** The
> 6 MHz fit is a ~1.2 s knife-edge and leans entirely on the fast SHA; the
> heaviest piece, RSA-2048 verify (6.37 s), is still plain CIOS. Claiming the
> full 286 range secure down to 6 MHz with real slack needs a further
> crypto-optimisation pass — a dedicated squaring path (RSA → ~4.3 s) plus
> further ECDHE/PRF wins. That work is in scope for the secure-tier claim.
> Detail + reproducible benchmarks: `tools/crypto-bench/results/FINDINGS.md`.

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
without reshaping. The only sizing decision deferred is how large the resident
active-driver slot must be for the worst-case future driver — a seam to size,
not code to write now.

## Hardware And Handoff Contract

Seed publishes machine state through the handoff block at `0000:0600`. The
target-specific binary layout is in `targets/ibm_pc_5150/HANDOFF.md`. The
handoff is also where the **capability vector lives and grows** — it already
carries `ram_top` and `nic_family`; CPU class, FPU, and link-type extend it.

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
(growing) CPU class, FPU present, link type
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
Each turn assembles minimal context — a model-compacted rolling conversation
summary plus the current prompt — and the tool-result path lets the model emit
`$r/$w/$x` directives that a cold tool phase executes in segment 0 between turns,
with results flowing back through the same context window (the agentic loop; see
the Demo above).

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

## Recovery Boundary

The boot floppy is the trusted recovery boundary. A user must be able to restart
the machine from known Seed media after an agent-built tool hangs the machine,
corrupts RAM, or leaves hardware in a bad state.

Write-protected Seed media is a valid and desirable deployment mode — the floppy
is read-only by policy (see Floppy Policy). Local configuration writes are
convenience only; failed writes must not prevent boot or agent/API use. Faster
boot from `USER.CFG` is useful when the medium is writable, but read-only media
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
`tools/core-sys-info.py` reads the `CORE.SYS` header. Build 12 closes the two
real leaks: the Makefile constants duplicated by hand (the budget view can drift
silently), and the per-phase `%error` caps scattered across `core.asm`. Both
fold into one region/lifetime checker driven by `layout.inc`, so the owned
regions of the Memory Shape are checked at build time and nothing drifts.

## Larger Machines

Seed keeps one floppy, one visible `CORE.SYS`, and one product contract across
small and larger machines. Larger machines reuse the 32 KiB shape and grow the
arena; they do not become alternate products.

```text
larger conversation window and arena (the default home for headroom)
preloaded loop working set (the floppy-free 32 KiB chat loop)
real, authenticated TLS on a 286-class CPU
later: more NIC families and link types, additively
```

The >64 KiB future — EMS bank-switching on the 8088, unreal/protected mode on
286/386+ — stays additive through the relocation seam (near→far dispatch vectors,
above), not a rewrite. Do not build it speculatively; only keep from blocking it.
"Gigabytes" remains its own future redesign: keep fixed Seed-owned ranges, keep
dynamic scratch/request/response ranges explicit and lifetime-tagged, and make
the rest of the machine the user/agent environment's.
