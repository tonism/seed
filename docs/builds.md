# Build Scope

Seed's loading marker has four semantic phases plus the final splash:

```text
" "          project init: boot sector, loader, CORE.SYS entry, display setup
"." dark     HAL setup: hardware detection, adapter init, hardware handoff
"o" dark     internet prep: network configuration and reachability
"o" bright   agent prep: gateway, model, reasoning, key, session, and environment setup
splash       ready handoff animation; no loading work happens here
```

`retry` returns to the dark `"."` HAL setup phase. It does not rerun the
project-init phase or reread floppy sectors.

Builds can be larger than individual internal checkpoints. A build should map
to a user-visible readiness goal; commits inside that build can still be small.

## Current Map

```text
build 1   boot floppy proof
build 2   minimal boot presentation: centered marker and fast-type banner
build 3   " " phase: project init, display baseline, handoff block, retry boundary
build 4   "." dark phase: HAL setup, adapter autodetect/fallback questions, hardware handoff
build 5   "o" dark phase: internet prep, IP config, reachability proof
build 6   "o" bright phase: agent prep, credentials, TLS, API, session, handover
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
cards also perform the receive-ring read diagnostic. This gives the dark `"o"`
phase a real outbound reachability proof without starting TLS, model API calls,
or an agent session.

## Build 6

Build 6 owns the bright `"o"` phase. It starts after internet readiness is
proven and ends when Seed can connect to an agent and hand over to the first
agent/user environment.

Current build 6 checkpoint:

```text
FAT12 160 KiB boot floppy with small reserved loader and root CORE.SYS runtime
optional tracked AGENTS.CFG root file with five agent interfaces
optional tracked NET.CFG root file with the generic internet probe host
fallback built-in agent interfaces for openai, anthropic, and google
ignored USER.CFG for validated local user choices and secrets
bright "o" parsing of up to five AGENTS.CFG agent declarations when present
agent? drill-down menu when USER.CFG is missing, unreadable, unparseable, or invalid
same-panel server?/key? form for selected agents that need both values
preserve saved model/reasoning values, but do not ask the user to type them
selected-agent DNS resolution and TCP 443 connect proof
shared TCP connect boundary for internet and selected-agent reachability
minimal TCP payload send/receive primitives used by the TLS proof
TCP receive sequence validation so retransmits do not corrupt the TLS stream
minimal TLS 1.2 ClientHello with SNI and P-256 ECDHE-RSA-CHACHA20-POLY1305
ServerHello state parse for version, random, cipher-suite, session-id, extension flags, and selected cipher path
Certificate handshake header parse with declared certificate-list length
Certificate handshake drain to the next handshake boundary
ECDHE ServerKeyExchange header parse with uncompressed P-256 public-point capture
P-256 coordinate conversion to 16-bit little-endian field words and coordinate range checks
8086 P-256 field add/sub modulo-p primitives
8086 P-256 field multiplication/reduction primitives
P-256-specific coefficient reduction for faster field multiplication
runtime P-256 public-point curve-equation validation for ServerKeyExchange
8086 P-256 Jacobian point double and mixed-add helper primitives
8086 P-256 scalar multiplication helper for mixed affine points
dependency-free P-256 vector, field-math, and point-math checker with optional OpenSSL cross-check
ServerHelloDone proof
live SHA-256 TLS handshake transcript context through ServerHelloDone
best-effort USER.CFG write of validated agent, model, reasoning, key, and endpoint values
```

Still in build 6 scope:

```text
add transcript digest finalization/copy support for Finished verification
optimize and wire P-256 scalar multiplication into ECDHE shared-secret generation
convert the Jacobian ECDHE shared point into the affine x-coordinate pre-master secret
implement TLS 1.2 SHA-256 PRF and ChaCha20-Poly1305 records
complete TLS directly from the 8088 runtime
validate the selected provider key with a model API request
fetch model and reasoning capabilities from the provider when available
create the agent session and hand over to the environment path
```
