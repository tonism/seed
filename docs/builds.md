# Build Scope

Seed's loading marker has four semantic states plus the final splash:

```text
none         boot sector, loader, CORE.SYS load
"." dark     hardware then internet: CORE.SYS entry, display baseline, hardware detection, adapter init, handoff, then IP configuration, DNS, and reachability proof
"o" dark     secure connection: selected endpoint setup and TLS protocol proof
"o" normal   local crypto: P-256 ECDHE and TLS key-material derivation
"o" bright   agent/environment: API validation, model/session, and environment handoff
splash       ready handoff animation; no loading work happens here
```

`retry` returns to the dark `"."` hardware phase. It does not reread floppy
sectors or rerun the boot-sector/loader path.

Builds can be larger than individual internal checkpoints. A build should map
to a user-visible readiness goal; commits inside that build can still be small.

## Current Map

```text
build 1   boot floppy proof
build 2   minimal boot presentation: centered marker and fast-type banner
build 3   no-marker bootstrap: loader boundary, display baseline, handoff block, retry boundary
build 4   "." dark phase: hardware setup, adapter autodetect/fallback questions, hardware handoff
build 5   internet readiness under the "." phase: IP config, DNS, reachability proof
build 6   "o" dark + normal + bright phases: secure connection, credentials, minimal provider API proof
build 7   ROM BASIC 16 KiB entry and windowed-nucleus release target
build 8   Default Prompt Interface chat loop
build 9   minimal context management for agentic continuity
build 10  minimal tool calling through controlled RAM access
```

Build 5 is intentionally broad. It should end when Seed can bring up a network
path from the IBM PC 5150 target and prove outbound internet readiness. The
internal sequence is:

```text
NE-family packet hardware init
Ethernet transmit and receive
DHCP network configuration
ARP resolution for the next-hop or service endpoint
DNS resolution
TCP or chosen transport reachability proof
```

Current build 5 checkpoints completed for the current 5150 NIC families:
3c501, 3c503, NE1000/NE2000, and WD8003. The shared internet path performs
packet hardware init, bounded receive polling, DHCPDISCOVER/OFFER,
DHCPREQUEST/ACK, DHCP subnet/router/DNS capture, DNS-server ARP, DNS A
resolution for the `NET.CFG` probe host, subnet-aware next-hop ARP, and a TCP
connect handshake to port 80 through the boot-core TCP connect path. NE-family
cards also perform the receive-ring read diagnostic. This gives the dark `"."`
phase a real outbound reachability proof without starting TLS, model API calls,
or an agent session.

## Build 6

Build 6 owns the dark `"o"` secure-connection phase, the normal `"o"` local
crypto phase, and the bright `"o"` agent/API-prep phase. It starts after
internet readiness is proven and ends when Seed can connect to a selected
provider, complete the current TLS/API path, and display the minimal returned
answer. On MDA, dark and normal `"o"` both render with the same non-bright
attribute.

Build 6 checkpoint:

```text
FAT12 160 KiB boot floppy with small reserved loader and root CORE.SYS runtime
optional tracked AGENTS.CFG root file with five agent interfaces
optional tracked NET.CFG root file with the generic internet probe host
fallback built-in agent interfaces for openai, anthropic, and google
ignored USER.CFG for validated local user choices and secrets
dark "o" parsing of up to five AGENTS.CFG agent declarations when present
agent? drill-down menu when USER.CFG is missing, unreadable, unparseable, or invalid
same-panel server?/key? form for selected agents that need both values
preserve saved model/reasoning values, but do not ask the user to type them
selected-agent DNS resolution and TCP 443 connect proof
shared TCP connect boundary for internet and selected-agent reachability
minimal TCP payload send/receive primitives used by the TLS proof
TCP receive sequence validation so retransmits do not corrupt the TLS stream
minimal TLS 1.2 ClientHello with SNI and P-256 ECDHE-ECDSA-CHACHA20-POLY1305
without extended master secret for the current cloud timeout budget
ServerHello state parse for version, random, cipher-suite, session-id, extension flags, and selected cipher path
Certificate handshake header parse with declared certificate-list length
Certificate handshake drain to the next handshake boundary
ECDHE ServerKeyExchange header parse with uncompressed P-256 public-point capture
P-256 coordinate conversion to 16-bit little-endian field words and coordinate range checks
8086 P-256 field add/sub modulo-p primitives
8086 P-256 field multiplication/reduction primitives
P-256-specific coefficient reduction for faster field multiplication
Comba-style P-256 product accumulation and inlined reduction coefficient folding
P-256 public-point curve-equation validation in the dependency-free checker
8086 P-256 Jacobian point double and mixed-add helper primitives
8086 P-256 scalar multiplication helper for mixed affine points with leading-zero skip
dependency-free P-256 vector, field-math, and point-math checker with optional OpenSSL cross-check
ServerHelloDone proof
live SHA-256 TLS handshake transcript context through ServerHelloDone
sparse fixed-scalar ECDHE shared-point generation from the server public point
Jacobian shared point conversion into the affine X-coordinate pre-master secret
SHA-256 finalization and transcript-safe HMAC-SHA256 helper
TLS 1.2 SHA-256 PRF for master-secret and key-expansion derivation
prepared HMAC-SHA256 ipad/opad states for repeated TLS PRF calls on 8088-class hardware
ChaCha20-Poly1305 key-block split into client/server write keys and IVs
fixed-scalar ECDHE ClientKeyExchange record construction and transcript update
ClientKeyExchange transmit after local key preparation, with short pacing before the client Finished path
ChaCha20 block helper for the current TLS 1.2 record path
Poly1305 helper for the current one-record Finished MAC shape
client Finished verify_data derivation from the live SHA-256 transcript
ChangeCipherSpec and encrypted client Finished record construction and transmit
encrypted server Finished receive, ChaCha20-Poly1305 authentication/decryption, and verify_data check
TLS application-data record construction and ChaCha20-Poly1305 authentication/decryption
minimal hardcoded OpenAI Responses API request that asks the model to reply exactly "ok"
OpenAI response scan for the first answer text/error message field
dependency-free TLS PRF and key-schedule vector checker
dependency-free ChaCha20/Poly1305 vector and Finished record shape checker
direct OpenAI TLS 1.2 server-Finished proof on `vm-net-ne2k8`
direct OpenAI Responses request/response proof on all seven original 4.77 MHz NIC profiles, displaying returned `ok`
best-effort USER.CFG write of validated agent, model, reasoning, key, and endpoint values
```

Still outside the Build 7 16 KiB release scope:

```text
replace pseudo-random client random and fixed scalar with real entropy/scalar handling before claiming secure TLS
reduce the eventual full-random-scalar path below the current full double-and-add cost
generalize ChaCha20-Poly1305 beyond the current Finished-record shapes
fetch model and reasoning capabilities from the provider when available
```

Build 6 optimization used the original 4.77 MHz, 32 KiB `vm-net-ne2k8` profile
as the compatibility gate. Build 7 now uses original 4.77 MHz, 16 KiB profiles
through the ROM BASIC sidecar helper with an explicit 16 KiB packed-memory
budget; literal 24 KiB 86Box 5150 profiles stop in POST before ROM BASIC. The
earlier faster ad hoc profiles are no longer part of the normal workflow. On 1 May 2026, all seven original-speed
4.77 MHz NIC profiles completed the first minimal direct OpenAI Responses
request/response proof and displayed the returned `ok`. On 4 May 2026, the
64 KiB baseline was retested before memory-slimming work: `vm-net-3c503`,
`vm-net-ne1k`, `vm-net-ne2k8`, `vm-net-novell-ne1k`, `vm-net-wd8003e`, and
`vm-net-wd8003eb` reached `seed build 6` and displayed `ok`; `vm-net-3c501`
failed at agent setup. On 7 May 2026, the 32 KiB slimming checkpoint repaired
that 3c501 failure in representative NIC-family tests: `vm-net-ne2k8`,
`vm-net-3c501`, `vm-net-3c503`, and `vm-net-wd8003e` each displayed `ok` and
reached `seed build 6`. The later 24 KiB BASIC sidecar path reached returned
`ok` on those same representative families before the compact helper release;
the released hex helper was smoke-tested through returned `ok` on
`vm-net-ne2k8`.

## Build 7

Build 7 owns the 16 KiB entry contract. The user-visible packaging change
is that the same Seed floppy supports two entry modes:

```text
32 KiB and larger    BIOS boots the floppy directly into CORE.SYS
below 32 KiB         user enters ROM BASIC and types the generated BASIC sidecar helper
```

The BASIC helper is a sidecar entry path for the same `CORE.SYS`, not a second
runtime. The floppy must remain one product: one image, one visible `CORE.SYS`,
one code path after entry. The helper may be generated for emulator testing and
documentation, but the shippable 16 KiB promise is that a user can type the
minimal helper in ROM BASIC when BIOS boot is unavailable.

The first attempted release target was 24 KiB, but literal 24 KiB
IBM PC 5150 profiles in 86Box stop during POST before ROM BASIC. That makes
24 KiB useful as an internal budgeting shape, not a releasable entry target for
this emulator/target combination. Build 7 therefore uses the 16 KiB ROM BASIC
sidecar harness for emulator execution while enforcing the 16 KiB packed-memory
layout in `make inspect`.

Build 7 completion target:

```text
16 KiB RAM ceiling
ROM BASIC sidecar entry
same visible CORE.SYS as the BIOS-boot path
minimal OpenAI Responses request returns ok
representative NIC-family success, including 3c501 and NE2K
preferred 1 KiB measured execution guard after Seed-owned resident state,
scratch, window space, and stack needs are accounted for
0.5 KiB measured execution guard is the fallback release floor if the final
1 KiB cut would make the critical path brittle
```

The Build 7 implementation strategy was the windowed nucleus described in
`notes/old/16kb-windowed-nucleus-design.md`: keep a tiny resident control plane,
move cold setup and post-answer work into reloadable windows, and preserve one
no-floppy provider-critical window from TLS/API start until the answer has been
found. Historical progress and failed cuts are tracked in
`notes/old/16kb-windowed-nucleus-attempts.md`.

Build 7 checkpoint:

```text
runtime splash number moved to seed build 7
CORE.SYS 23040 bytes, 45 sectors
resident nucleus 4 sectors, 2040 nonzero bytes
LINK/K provider-critical window 13 sectors
high-crypto scratch 194 bytes
critical scratch 2097 bytes
16 KiB packed critical raw slack 1293 bytes
16 KiB packed critical guarded slack +269 bytes against the preferred 1 KiB guard
all seven BASIC-sidecar 16 KiB NIC profiles reached returned ok: vm-net-3c501,
vm-net-3c503, vm-net-ne1k, vm-net-ne2k8, vm-net-novell-ne1k,
vm-net-wd8003e, and vm-net-wd8003eb
no-card CGA and MDA profiles fail cleanly with no NIC
```

## Build 8

Build 8 owns the Default Prompt Interface, the first usable chat loop after the
provider API path is alive. It starts from the Build 7 16 KiB entry contract
rather than assuming a larger machine.

DPI is a disposable starter interface, not the final user/agent environment. It
exists so a user can boot the machine, see an initial model greeting, type
prompts, and receive streamed model responses across multiple turns in one boot
session.

Build 8 scope:

```text
initial model greeting
prompt input with a visible ">" marker
user text in bright text and model text in normal text
readable streamed response rendering
multiple prompt/response turns in one boot session
each prompt may still be a fresh provider request without semantic context
no tool calling yet
```

Build 8 release blockers:

```text
chat loop must not freeze after repeated prompt/response turns
response rendering must be readable enough for real use
prompt input must not corrupt runtime state
hot chat loop should avoid floppy reads after splash, or document any temporary exception before release
```

Build 8 checkpoint (2026-06-02): chat-loop reliability COMPLETE across all 7 NIC profiles.
Blockers 1-3 met (no-freeze, readable rendering, prompt input no longer corrupts runtime
state) — validated by the 7-card matrix: multi-turn short + long + idle-reconnect. Blocker #4
(floppy reads): the windowed-nucleus loads phases on demand, so the hot loop still reads the
floppy per prompt — accepted as a TEMPORARY EXCEPTION per this blocker's escape clause
(matrix-validated reliable); the floppy-read optimization is DEFERRED to Build 9. Key fixes:
keep-alive reuse + durable resend (commit 2b09f60); long-render completion fallback for all
NICs (commit 535de35) — the long-render 0D flake (was 3/28) is eliminated (0/21). The
intermittent "no response" seen in testing was a harness screencapture observation artifact,
not the product. Release marker pending (not yet cut).

Build 8 should stay minimal. It should not introduce protected-mode machinery,
a general shell, a local tool ABI, or memory-ocean/defrag work while the chat
loop itself is still being stabilized.

## Build 9

Build 9 owns minimal context management for agentic continuity. It builds on the
stable Build 8 chat loop. The layered request, chunked streaming, conversation
accumulation, and model-driven compaction are implemented and validated end-to-end -
the model recalls a fact across a compaction collapse; the full working record is
`notes/build9-context-attempts.md`.

Each request is assembled from four layers:

```text
identity      static, on the floppy, hand-tuned     tone / self / tools
ledger        serialized from the handoff block      machine facts: RAM top, NIC, IP, ...
conversation  RAM, model-compacted rolling summary   recent interaction
prompt        current user input (256 B in RX)       this turn
```

identity + ledger are the protected frame: never lossy-compacted. Only the
conversation is compacted, and by the model (an occasional round-trip near the
budget), never by local heuristics. The ledger is regenerated from the handoff
block, so it costs ~0 durable RAM; Seed publishes machine facts (including the
already-present `ram_top`) and lets the user/agent derive their own free arena
rather than dictating one.

Implementation (Phases 2-3b, validated): the request is streamed as separate TLS
records (headers+model / instructions+ledger / conversation+prompt), so the layered
prefix never has to fit one send buffer. The conversation accumulates recent turns raw
(JSON-escaped only at send) and, when it passes a tunable threshold (default 3/4,
measured before each request so the reply has room to land), the model is asked to end
its reply with a `SUMMARY:` line that the next request scans back into the window -
model-driven compaction, shown as a dim `compacting context...` status block. The
adjustment knobs (window / arena / threshold addresses) are documented in `HANDOFF.md`
(Context-management knobs); their agent-facing advertisement in the ledger is deferred
to Build 10, since advertising actionable addresses before a memory-write tool exists
makes the model hallucinate tool calls. Known debt: a long escaped prompt+conversation
can still exceed one chunk-3 record; generalizing the chunked send to split chunk 3 too
is pending.

Build 9 scope:

```text
recent user prompt and model response influence the next request
model-compacted rolling conversation summary (no local summarization heuristics)
context is reconnect-safe: it survives an idle/walk-away reconnect
context lives in RAM reclaimed from the stack reserve, above the TLS scratch
context state does not require writeable boot media
clear, visible compaction when the conversation region fills
a reserved user/agent arena floor shares the reclaimed pool with conversation
no tool calling yet
```

On the 16 KiB target Build 9 accepts bounded, documented per-turn floppy reads
(identity loads with the existing per-turn phases): the Build 8 blocker #4 goal of
eliminating hot-loop floppy reads is descoped here to "accept + document," trading
hot-loop disk for the RAM that context and the arena need. Floppy-read elimination
becomes a larger-machine quality-of-life item after Build 10.

The reclaimed pool is split conversation/arena 50/50 by default and is
user/agent-adjustable; the arena grows with RAM on larger machines, while the
transmitted conversation is naturally bounded (on the 8088, RAM is the binding
limit long before the model's context window). The release guard is run thin per
the closed-contract guard philosophy (`architecture.md`): the 16 KiB stack reserve
is trimmed to a measured margin, confirmed by a stack high-water check in validation.

Build 9 is not full long-term agent memory. Persistent notes, preferences, project
state, and durable workspaces belong to the later user/agent environment. Build 9
only needs enough continuity that the next prompt is not semantically fresh.

Build 9 carried-TODO disposition (from Build 8):

```text
floppy reads:  RESOLVED by decision - accept bounded documented per-turn reads on
  16 KiB (see scope); elimination deferred to larger machines.
memory reclaim: FOLDED into the core - the stack-reserve reclaim funds the context
  pool; the old "toward a 1 KiB guard" target is replaced by a measured ~256 B reserve
  run thin per the guard philosophy, confirmed by a validation tripwire.
NIC timing unification: the one open investigation, sequenced into Build 9 validation
  and evidence-gated. ~10-11 behavioral carve-outs (3c501-dominated: render-before-ACK,
  the el1 single-buffer receive latch, handshake-flight ordering; one 3c503 app-send-
  before-server-finished) are the candidates. Per docs/networking.md, remove a per-card
  rule only with a documented replacement rule + cross-NIC evidence.
```

## Build 10

Build 10 owns the first minimal tool-calling surface and is in scope for the
first public release. It should build on a stable Build 9 context path rather
than making stateless tool calls from isolated prompts.

Build 10 scope:

```text
agent can read RAM through a narrow controlled mechanism
agent can write RAM through a narrow controlled mechanism
agent can jump to or execute controlled RAM entrypoints
agent gets enough success/failure feedback for Seed-observable failures
published memory and hardware contract is sufficient for tool decisions
tool results can flow back through the Build 9 context path
```

This is still not a general OS milestone. Seed remains the bootstrapping control
plane: it provides the trusted recovery boundary, working provider API path,
published machine contract, and first controlled tool hook, then leaves local
tool formats, loaders, ABIs, workspaces, and result handling to the user/agent
environment.

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
