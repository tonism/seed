# Seed Architecture Contract

Seed is a bootstrapping control plane, not a protected operating system.

The product goal is to give a memory-constrained machine a working agent API
path, publish the live hardware and memory contract, then leave the machine
open for user and agent-built local tooling. Seed should stay small enough that
the user and agent keep as much of the machine as possible.

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
minimal handoff into the user/agent environment, when that build phase exists
```

Seed should not grow into a general hardware abstraction layer or restrictive
runtime. Local tool formats, loaders, ABIs, workspaces, and result handling
belong to the user/agent environment. Seed's job is to get that environment to
the point where it can exist, not to become the environment itself.

Protected mode is not part of the current product direction. Even on later
machines, Seed should not become a protected supervisor unless the product
direction explicitly changes.

## Current Target Snapshot

The active implementation target is an IBM PC 5150-class machine:

```text
CPU              8088-compatible, 4.77 MHz
RAM floor        16 KiB through ROM BASIC sidecar entry
BIOS boot floor  32 KiB through direct floppy boot
media            160 KiB 5.25-inch FAT12 floppy image
video            BIOS text mode, CGA or MDA
network          3c501, 3c503, NE1000/NE2000, Novell NE1000, WD8003 families
runtime file     one visible CORE.SYS
```

Current measured image:

```text
CORE.SYS total bytes:       27648
CORE.SYS total sectors:     54
resident nucleus sectors:   4
resident nucleus bytes:     2048
phase count:                19
provider-critical K window: 14 sectors / 7168 bytes
16 KiB slack after critical: 1393 bytes
16 KiB guard:               ~256 B stack reserve, run thin (Build 9; see Guard Philosophy)
```

## Boot Artifact

The current floppy is a small FAT12 image with a reserved boot loader and a
normal visible runtime file:

```text
160 KiB FAT12 floppy
|
| sector 1       boot sector with BPB
| sectors 2-5    reserved loader
| sectors 6-7    FAT copies
| sectors 8-11   root directory
| sector 12+     file data
|                CORE.SYS is the first FAT data file
|                AGENTS.CFG, NET.CFG, optional USER.CFG follow
```

`CORE.SYS` is one file-backed runtime. The build splits its source into NASM
include files and cold phases, but the release artifact remains one visible
`CORE.SYS`. Do not introduce a second runtime image for 16 KiB entry.

## Entry Paths

Seed has two entry paths into the same resident nucleus.

```text
32 KiB and larger
-----------------
BIOS loads boot sector at 0000:7c00
  -> stage 1 reads reserved loader to 0000:0600
  -> reserved loader reads CORE.SYS root entry and FAT chain
  -> loader reads only the resident CORE.SYS sectors to 0000:1000
  -> loader clears BASIC-entry registers
  -> jump 0000:1000

16 KiB path
-----------
machine enters ROM BASIC
  -> user types or pastes generated SEED24A.BAS / SEED24B.BAS sidecar text
  -> BASIC pokes a tiny 8086 loader at 0000:3a00
  -> helper reads the resident CORE.SYS sectors from the Seed floppy
  -> helper passes AX = RAM top, BX/CX = "SEED" magic, DL = boot drive
  -> jump 0000:1000
```

The BASIC loader at `0x3a00` is entry-time only. It is deliberately placed in
memory that later becomes Seed critical scratch. Once it jumps to `CORE.SYS`,
the BASIC runtime and sidecar loader are abandoned.

## Runtime Step Order

The resident nucleus is a small scheduler plus shared hardware, UI, filesystem,
network, and state primitives. It reloads cold phases from the same `CORE.SYS`
file as needed.

High-level flow:

```text
entry normalize
  -> set stack from BIOS path or BASIC-provided RAM top
  -> clear low and high runtime scratch
  -> remember boot drive and RAM top in handoff block

hardware phase "."
  -> H: display, handoff, adapter discovery
  -> I: packet I/O initialization

internet phase (still ".")
  -> D: DHCP setup
  -> P: NET.CFG probe-host load/parse
  -> C: TCP connect to generic probe path

agent phase "o"
  -> A: AGENTS.CFG load/parse or built-in fallback
  -> U: USER.CFG load/parse
  -> Q: ask for missing agent/server/key/model/reasoning values if needed
  -> E: selected-agent endpoint and DNS name preparation
  -> R: request construction
  -> K: load provider-critical LINK window at 0x1800
  -> L: build TLS ClientHello and low crypto constants
  -> C: TCP connect to selected provider on port 443
  -> K: TLS server proof, key schedule, encrypted request, application receive
  -> T: parse a received application-data chunk for the returned answer
  -> S: best-effort USER.CFG save if values changed
  -> B: splash/result screen

prompt loop "Default Prompt Interface"
  -> render the model greeting, then take prompts on the live (reused) TLS session
  -> each turn builds the request, streams the reply, then a cold tool phase runs any
     $r/$w/$x and loops the result back to the model - traced in full under
     "Demo: A Tool-Called Request" below
  -> reconnect and resend only on a real drop

failure
  -> F: mark current phase red, type error, offer retry/restart
  -> retry returns to the hardware "." phase without rereading resident sectors
```

The same TCP connect phase is used for the internet probe and for the selected
agent provider. It is loaded into the network setup window each time it is
needed.

## Demo: A Tool-Called Request

What every part of the machine touches when the cloud model runs code on the 1981 PC
(Build 10):

```text
user types a prompt -> DPI captures it into the conversation window
R  build request: instructions (RAM-tool grammar $r/$w/$x) + ledger (RAM size, IP, NIC,
     and a@ = the free seg-0 arena base) + the JSON-escaped window + the prompt
X  application-data stream: encrypt with the resident K crypto window (ChaCha20-Poly1305)
     and send over the live (reused) TLS session, then receive the streamed reply - the
     renderer draws prose but HIDES any $-command (kept in the window for the tool phase,
     shown once as a dim echo)
M  tool phase (cold, loaded between turns at 0x0900): scan the window for
     $r ADDR LEN / $w ADDR BYTES / $x ADDR; execute each in segment 0 -
     read bytes / poke bytes / CALL the address; append a readable result line back
     INTO the window (model-facing) + a dim "read from / write to / jump to <addr>" line (screen)
   loop: a fired tool arms auto-continue - the next turn carries the tool result and the
     model acts on it, up to 8 hops, then control returns to the user
```

Worked example (the Build 10 capstone, validated): asked to write `b8 34 12 c3` (x86
`mov ax,0x1234; ret`) into the arena and run it, the model `$w`s the four bytes, `$x`es the
address, and `AX=0x1234` comes back through the window. It is deliberately minimal — four
hand-aimed bytes, not a general code-generation result — but the loop is real end to end: a
cloud model authored machine code and a 1981 PC ran it. There is no sandbox; a `$x` into bad
code hangs the machine, and recovery is a reboot from trusted media (see Authority Model and
Recovery Boundary below).

## Phase Windows

`CORE.SYS` starts with a resident nucleus and a phase table. The phase loader
uses sector offsets inside `CORE.SYS`, so keeping `CORE.SYS` first in the FAT
data area is part of the boot contract.

Current phase table:

```text
id  sectors  load addr  responsibility
K   14       0x1800     provider-critical LINK window: SHA-256, TLS, AEAD, API exchange
F   1        0x0700     failure action UI
H   4        0x0700     hardware/display/NIC discovery
I   1        0x0700     packet I/O initialization
D   3        0x0900     DHCP setup
C   3        0x0900     TCP connect
L   2        0x0700     TLS ClientHello and low crypto constants
E   1        0x0700     selected agent endpoint setup
P   2        0x0700     NET.CFG probe config
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

This is the live 20-phase layout; regenerate it with `make inspect` /
`tools/core-sys-info.py`. Phases that do network I/O — `D`, `C`, `R`, `X` — load at
`0x0900` so they coexist with the TCP/NIC scratch; the `M` tool phase shares that
`0x0900` window, since it runs between turns when the network scratch is idle; the
response parser `T` loads at `0x0d00`; every other cold phase loads at `0x0700`.

Most cold phases share the low scratch/window region. The K window is different:
it is loaded once into a larger high window before the provider-critical path.

This windowed, phase-streaming design is what lets the TLS 1.2 record path —
ChaCha20-Poly1305, SHA-256, HTTP/1.1, and SSE streaming — run in 16 KiB on a 4.77 MHz
8088: only the 2 KiB nucleus and the 7 KiB `K` crypto window stay permanently resident,
while the other 19 phases stream from the floppy on demand and take turns in one small
window. (The P-256 ECDH key agreement that real TLS also needs is the one piece that
doesn't fit — it is stubbed; see CPU And Crypto Budget.) See [`memory.md`](memory.md)
for the stage-by-stage memory maps.

## Provider Timing Model

The provider path is Seed's gift to the agent. The agent should inherit a
working API channel instead of rediscovering TCP, TLS, request construction, and
response parsing from raw hardware on every boot.

Floppy access is acceptable while Seed is still preparing the path:

```text
read config
ask user questions
resolve endpoint
build request
load K, L, and C windows
```

The fast path begins once Seed has enough code and scratch resident to open the
provider TCP connection and drive TLS/application data:

```text
TCP connect to provider
send ClientHello
receive ServerHello / Certificate / ServerKeyExchange / ServerHelloDone
derive the premaster (ECDH stubbed - see CPU And Crypto Budget) and TLS keys
send ClientKeyExchange / ChangeCipherSpec / encrypted client Finished
verify encrypted server Finished
send encrypted application request
receive encrypted application data
```

The current 16 KiB design keeps the handshake, key schedule, AEAD, request send,
and application receive inside the resident K window plus high/critical scratch.
After an encrypted application-data chunk has arrived, Seed may load the cold
T response parser from floppy and inspect that chunk. That is intentionally
later than the handshake/request race and has been validated on the 16 KiB
profiles.

After splash and into the prompt loop, floppy access should be avoided unless
the user or agent explicitly chooses to use the floppy, or Seed must recover
from a dropped or rebuilt provider link. The hot prompt/response path should be
RAM, network, and video flow rather than per-message overlay reads.

The per-NIC transport timing contracts this path depends on — render-before-ACK
pacing, the receive latch, and large-record completion handling — are documented in
[`networking.md`](networking.md).

## Memory Layout

The 16 KiB target ceiling is `0x4000`. Three regions stay permanently resident: the
2 KiB nucleus at `0x1000`, the 7 KiB `K` crypto window at `0x1800`, and ~2.3 KiB of
TLS/API scratch above it; cold phases stream through the shared low scratch at `0x0700`.
Above the critical scratch sits a reconnect-safe context pool — the conversation
window plus the user/agent arena — split 50/50, run with a thin stack guard, and scaling
with RAM (~961 B on a 16 KiB machine: ~480 B window + ~480 B arena; ~8.6 KiB each at 32 KiB).

The byte-level entry-time and runtime layouts, and the per-stage maps, live in
[`memory.md`](memory.md); regenerate them with `make memory-map` after any
memory-layout change and before release checks.

32 KiB and larger machines use the same `CORE.SYS` and the same 16 KiB contract.
Extra memory may be exposed later as optional arenas, caches, or tool space, but the
base product must not require it.

## CPU And Crypto Budget

The other half of the constraint is the processor. A 4.77 MHz 8088 is a 16-bit,
sub-MIPS part with a slow multiply and no crypto acceleration, and the provider path
asks it to run modern TLS 1.2. That splits into two very different costs. The
*symmetric* crypto — ChaCha20-Poly1305 record encryption and SHA-256 (the handshake
transcript and the PRF key schedule) — runs for real on the 8088. The *asymmetric*
step — a P-256 scalar multiply for the ECDH key exchange — is the killer: one real
scalar multiply is **110.8 s** measured on this CPU (the dormant constant-time
primitives, verified against OpenSSL), so the shipped build skips it (the security gap
below). Notably it is **not a size problem** — the real P-256 fits in ~3.4 KiB —
purely a speed one: the 8088's slow `mul` opcode is the wall. Skipping it keeps boot in
the tens of seconds instead of minutes — but, as the measured timeline below shows,
even the symmetric crypto that remains pins this CPU flat-out for ~14 seconds.

The resource profile, measured by packet-capture timing across two boots (the gaps
between the VM's packets *are* the 8088's compute), holds a surprise about which
resource dominates:

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

The TLS handshake is 14.5 s of the CPU pinned flat-out - SHA-256 hashing the 2.8 KB
certificate into the transcript, the PRF key schedule, and ChaCha - in two ~7 s halves
that come out identical run to run (fixed arithmetic on fixed input). Everything else is
small: the model thinks + replies in ~2.5 s, a network round trip is 7 ms, the
ClientHello takes 0.27 s to build. Setup (hardware detect, DHCP/DNS, and the floppy
phase loads including the 14-sector K window) is a few seconds before the handshake -
drawn approximately, since it cannot be cleanly separated from the emulator's own boot.

The contrast is the point: the expensive crypto is paid **once**, at boot. Every turn
after reuses the open session, so a chat or tool-call turn is mostly the 8088 idle while
the model thinks, then a quick ChaCha-decrypt, a render, and - for a tool call - a CALL
into the arena. On a 4.77 MHz part, modern TLS is not a network or key-exchange cost (the
key exchange is stubbed) - it is a symmetric-arithmetic cost, and that is the single
biggest line item in the whole boot.

What keeps the symmetric side tractable:

- **An ARX record cipher.** The negotiated suite is ChaCha20-Poly1305, an
  add-rotate-xor design with no S-boxes or large tables, so it needs no AES hardware
  and stays cheap on the 8088.
- **Reused HMAC state.** Prepared HMAC-SHA256 ipad/opad pads are kept across the TLS
  PRF, so the key schedule does not recompute SHA-256 blocks it already has.
- **Pace the stream to the renderer.** On the most constrained NICs, response text uses
  render-before-ACK pacing so the network does not outrun the 8088's text renderer (see
  `networking.md`).
- **No tight remote loops.** Network and model latency on top of a slow CPU make
  step-by-step remote hardware control unreliable, which is why the post-Seed model is
  asynchronous (see User/Agent Environment, below).

Measured headroom on the symmetric side (per-op micro-benchmarks, `tools/crypto-bench/`):
the TLS-PRF key schedule is 4.92 s and one SHA-256 block 156 ms here, both dominated by
the original bit-at-a-time 32-bit rotates (rotr-by-22 = 22 loop iterations) and
memory-to-memory math on the 8-bit bus. An evolutionary search found a byte-granular
rotate + register-resident rewrite that is **4.64× faster on SHA-256/PRF, verified on
86Box hardware** (PRF 4.92 s → 1.06 s), output bit-exact. Because the handshake is
SHA-bound — the PRF *plus* hashing the 2.8 KB certificate into the transcript — that
per-op win projects to cutting most of the ~14 s handshake CPU, the highest-leverage
margin against the reconnect race. The catch is size: it adds ~595 B and the K crypto
window has 9 B free, so landing it is a sized follow-up (free room in the other K-window
crypto, or raise the crypto-scratch base at a RAM cost on the 16 KiB target).

And the part that is *not* tractable — the honest gap:

- **The P-256 key exchange is skipped — a speed wall, not a size one.** The real
  constant-time primitives (Comba accumulation, Jacobian coordinates) are written,
  cross-checked against OpenSSL, and **fit in ~3.4 KiB**, but one scalar multiply is
  **110.8 s** measured here, so they are **compiled out**. The boot path substitutes a
  scalar-1 stub: the server's public X coordinate *is* the premaster, so **no key
  agreement happens** — anyone capturing the handshake derives every session key
  (`tools/tls-decrypt.py` does exactly that), and the session is not confidential.
  Server-certificate authentication is also skipped (RSA-2048 verify ~43 s, ECDSA-P256
  ~220 s per signature — both out of reach), so the channel is unauthenticated.
- **Real entropy would not help on its own.** The client random is only a nonce; with a
  public premaster, making it unpredictable buys no confidentiality. Entropy matters
  only once a real per-session *secret* exists — the secret ECDHE scalar, or an
  RSA-encrypted random premaster (RSA key transport, ~43 s, is the *cheapest* real
  confidentiality, still ~3× over the window). So entropy is a cheap *prerequisite*
  (~0.16 s) that must ship bundled with key agreement, never as a standalone "fix".
- The honest gap is therefore the whole public-key story, and on a stock 8088 it is
  CPU-gated to minutes (a full real-security handshake ≈ 2.7 min). The threshold on faster
  CPUs has since been **measured** (same harness): an FPU does *not* rescue it (SHA is
  FPU-immune, the P-256 reduction/carry work dominates), but **security begins at the
  286** — an optimised real ECDHE (Solinas + Karatsuba + wNAF P-256, OpenSSL-verified) is
  6.6 s on the lowest 6 MHz part, and a full cert-authenticated handshake (ECDHE +
  RSA-2048 verify 6.37 s + the fast PRF) fits the ~15 s window: ~13.8 s at 6 MHz (a
  knife-edge, only with the 4.64× SHA win) and a comfortable ~10.4 s at 8 MHz. So a real
  secure channel is a **286@8+ tier**; full 6 MHz coverage needs a further crypto pass and
  is scoped to the Build 12 redesign (`work/scaling`). The stock-8088 product stays
  honestly **encrypted but not secure**. Detail + reproducible benchmarks:
  `tools/crypto-bench/results/FINDINGS.md`.

The handshake race is also why the chat loop reuses one session instead of reconnecting
per turn — a fresh mid-chat handshake can lose the race:

```text
  fresh TLS handshake on the 8088   ├──────────────── ~15 s ────────────────┤ done
  provider reconnect window         ├─────────────── ~15 s ───────────────┤ ✗ closed

  So the chat loop:
    · holds ONE TLS session open and reuses it for every prompt; a keep-alive ping holds
      it open through long renders, so an engaged session reuses snappily, no reconnect
    · if the completion marker is missed but the text already rendered, accepts the answer
      rather than forcing a new (racing) handshake
    · when reuse DOES fail — idle long enough that the provider closed the socket — it
      reconnects behind a single dim "> reconnect" line and silently retries the rebuild-
      and-connect up to 3x; if all three lose the race it appends " failed" and drops to
      the prompt for a fresh attempt (never a blank turn)
  The ~15 s handshake is normally paid once, at boot — never per reused turn.
```

The two constraints are answered the same way: do the irreducible work once, keep it
resident only as long as it is needed, and lean on algorithm and layout choices that
suit a small, slow machine instead of fighting them.

## Hardware And Handoff Contract

Seed publishes machine state through the handoff block at `0000:0600`. The
target-specific binary layout is documented in
`targets/ibm_pc_5150/HANDOFF.md`.

The handoff state includes:

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
The first DPI release (Build 8) sent each prompt as a fresh provider request; Build 9
adds minimal context assembly - a model-compacted rolling conversation summary plus the
current prompt shape each request, so prompts are no longer semantically fresh. Build 10 ships this tool-result path: the model emits `$r/$w/$x`
directives, a cold tool phase executes them in segment 0 between turns, and the
results flow back through this same context window so the model acts on them - the
agentic loop. See "Demo: A Tool-Called Request" above.

Seed-owned context management should be compact and volatile on the 16 KiB
target: recent prompt/response state, a small rolling summary or equivalent
context record, and later tool-result slots. It should not depend on writeable
boot media and should not turn the hot prompt loop into a floppy-bound path.

Long-term semantic agent memory is a later environment concern. Persistent
notes, preferences, project state, and durable workspaces should use formats and
storage chosen by the user/agent environment, with Seed publishing enough memory
and storage facts for that environment to make its own decisions.

The remote agent should not be in tight hardware timing loops. Network latency
and model latency make live step-by-step hardware control unreliable on small
machines.

The intended post-Seed model is asynchronous:

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
surface for things that are hard to reconstruct or timing-sensitive, such as the
existing provider API channel or published hardware state. It should not own a
general local-tool execution runtime.

This keeps Seed minimal while still letting the environment build direct
hardware tooling. A later source-level workflow may make tool authoring nicer,
but the machine does not need an underlying OS, shell, compiler, or command
library for Seed itself to fulfill its contract.

## Recovery Boundary

The boot floppy is the trusted recovery boundary. A user must be able to
restart the machine from known Seed media after an agent-built tool hangs the
machine, corrupts RAM, or leaves hardware in a bad state.

Write-protected Seed media is a valid and desirable deployment mode. Local
configuration writes are convenience only; failed writes must not prevent boot
or agent/API use. Faster boot from `USER.CFG` is useful when the medium is
writable, but read-only media remains the cleanest physical kill switch.

## Authority Model

Seed is not a security boundary between the user, agent, and machine. If the
user allows an agent-built tool to run, that tool has bare-metal authority.

This is intentional. Seed optimizes for recovery, transparency, and freedom on
small machines rather than for multi-user isolation.

The product promise is:

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

A guard is still useful for stack depth, BIOS side effects, packet timing,
worst-case accepted config values, emulator versus real hardware variance, and
Seed's own mistakes. The guard should therefore be explicit, measured, and
small enough that it does not waste the point of a 16 KiB target.

For the 16 KiB target, the guard is a measured, thin execution reserve, not a fixed
block. Build 7 aimed for 1 KiB of headroom; Build 9 found that 16 KiB cannot fund both
that and a useful context pool, so the stack reserve was trimmed to a measured ~256 B
margin run thin. That is accepted only because the collision risk is covered actively —
explicit bound checks, visible loader failure, and a runtime stack high-water tripwire
in validation — rather than by leaving a large idle cushion.

Unused low memory is not reserved for future features by default. Future
features should either fit the published contract or belong to the user/agent
environment.

## Larger Machines

Seed should keep one floppy, one visible `CORE.SYS`, and one product contract
across small and larger machines. Larger machines may get additional optional
arenas, caches, or tool space after Seed detects the available RAM, but the base
16 KiB contract must not depend on those expansions.

Future work should test how larger-memory machines expose extra room to the
user/agent environment:

```text
larger packet/cache buffers
larger environment arena
larger environment-owned result/work buffers
optional persisted or prefetched windows
faster provider setup when extra RAM is available
```

Those are expansions of the same contract, not alternate products.

The long-term memory-ocean direction remains plausible: keep fixed Seed-owned
runtime ranges, keep dynamic scratch/request/response ranges explicit, and make
the remaining machine available to the user/agent environment. Do not reenter a
full memory defragmentation or ocean redesign until the chat loop is
stable.
