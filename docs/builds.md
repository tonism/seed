# Build Scope

Seed's loading marker has five semantic states plus the final splash:

```text
none         boot sector, loader, CORE.SYS load
"." dark     hardware: CORE.SYS entry, display baseline, hardware detection, adapter init, hardware handoff
"," dark     internet: IP configuration, DNS, and plain reachability proof
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
build 5   "," dark phase: internet prep, IP config, reachability proof
build 6   "o" dark + normal + bright phases: secure connection, credentials, minimal provider API proof
build 7   ROM BASIC low-memory entry and 16 KiB windowed-nucleus release target
build 8   user/agent environment, local tool ABI, and handoff loop
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
cards also perform the receive-ring read diagnostic. This gives the dark `","`
phase a real outbound reachability proof without starting TLS, model API calls,
or an agent session.

## Build 6

Build 6 owns the dark `"o"` secure-connection phase, the normal `"o"` local
crypto phase, and the bright `"o"` agent/API-prep phase. It starts after
internet readiness is proven and ends when Seed can connect to a selected
provider, complete the current TLS/API path, and display the minimal returned
answer. On MDA, dark and normal `"o"` both render with the same non-bright
attribute.

Current build 6 checkpoint:

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

Still in build 6 scope:

```text
replace pseudo-random client random and fixed scalar with real entropy/scalar handling before claiming secure TLS
reduce the eventual full-random-scalar path below the current full double-and-add cost
generalize ChaCha20-Poly1305 beyond the current Finished-record shapes
fetch model and reasoning capabilities from the provider when available
```

Build 6 optimization uses the original 4.77 MHz, 32 KiB `vm-net-ne2k8` profile
as the BIOS-boot compatibility gate. The 24 KiB gate uses the ROM BASIC
sidecar helper with a runtime ceiling of `0x6000`; literal 24 KiB 86Box 5150
profiles stop in POST before ROM BASIC. The earlier faster ad hoc profiles are
no longer part of the normal workflow. On 1 May 2026, all seven original-speed
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

Build 7 owns the low-memory entry contract. The user-visible packaging change
is that the same Seed floppy supports two entry modes:

```text
32 KiB and larger    BIOS boots the floppy directly into CORE.SYS
below 32 KiB         user enters ROM BASIC and types the generated BASIC sidecar helper
```

The BASIC helper is a sidecar entry path for the same `CORE.SYS`, not a second
runtime. The floppy must remain one product: one image, one visible `CORE.SYS`,
one code path after entry. The helper may be generated for emulator testing and
documentation, but the shippable low-memory promise is that a user can type the
minimal helper in ROM BASIC when BIOS boot is unavailable.

The first attempted low-memory release target was 24 KiB, but literal 24 KiB
IBM PC 5150 profiles in 86Box stop during POST before ROM BASIC. That makes
24 KiB useful as an internal budgeting shape, not a releasable entry target for
this emulator/target combination. Build 7 should therefore not be called
complete until the 16 KiB ROM BASIC sidecar path reaches the Build 6 OpenAI
`ok` proof.

Build 7 completion target:

```text
16 KiB RAM ceiling
ROM BASIC sidecar entry
same visible CORE.SYS as the BIOS-boot path
minimal OpenAI Responses request returns ok
representative NIC-family success, including 3c501 and NE2K
1 KiB measured execution guard after Seed-owned resident state, scratch,
window space, and stack needs are accounted for
```

The active implementation strategy is the windowed nucleus described in
`notes/16kb-windowed-nucleus-design.md`: keep a tiny resident control plane,
move cold setup and post-answer work into reloadable windows, and preserve one
no-floppy provider-critical window from TLS/API start until the answer has
been found. Current progress and failed cuts are tracked in
`notes/16kb-windowed-nucleus-attempts.md`.

## Build 8

Build 8 owns the other end of Seed: the first usable user/agent environment
after the provider API path is alive. It should start from the Build 7
low-memory entry contract rather than assuming a larger machine.

Build 8 should turn Seed from an API proof into an agent-operable runtime:

```text
publish the live memory and hardware contract to the agent
define the first tiny local tool ABI
reserve or discover a tool arena and result buffer
load an agent-provided or built-in local tool payload
call that tool locally at machine speed
return status/result data through the provider API path
provide a recovery path if the tool fails or corrupts volatile state
```

This is not a general OS milestone. Seed remains the bootstrapping control
plane: it provides the trusted recovery boundary, working provider API path,
and small handoff ABI, then leaves the rest of the machine open for user and
agent-built tooling.
