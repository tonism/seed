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
build 6   "o" dark + normal + bright phases: secure connection, credentials, API, session, handover
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
crypto phase, and the bright `"o"` agent/environment phase. It starts after
internet readiness is proven and ends when Seed can connect to an agent and
hand over to the first agent/user environment. On MDA, dark and normal `"o"`
both render with the same non-bright attribute.

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
create the agent session and hand over to the environment path
```

Build 6 optimization uses `vm-net-ne2k8-8mhz` as the benchmark lane and the
original 4.77 MHz `vm-net-ne2k8` profile as the compatibility gate. The earlier
16 MHz ad hoc profile is no longer part of the normal workflow. On 1 May 2026,
all seven original-speed 4.77 MHz NIC profiles completed the first minimal
direct OpenAI Responses request/response proof and displayed the returned `ok`.
