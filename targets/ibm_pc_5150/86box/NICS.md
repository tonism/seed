# 86Box NIC Inventory

Build 5 treated network support as internet readiness. Stage 2 still probes
common ISA Ethernet I/O bases, records the responding I/O base, starts
resolving the adapter family when the base is ambiguous, and reads 3c501,
3c503, NE1000/NE2000, and WD8003 station-address PROMs into the handoff block
when they validate. It also records IRQ 3 for the current 5150 86Box profiles
after adapter family resolution. The packet path now covers all current 5150
candidate families: 3c501, 3c503, NE1000/NE2000, and WD8003. It initializes
packet hardware, sends DHCPDISCOVER, waits for DHCPOFFER, parses IPv4 address,
subnet mask, router, and DNS server, sends DHCPREQUEST, waits for DHCPACK,
sends ARP for the DHCP-provided DNS server, resolves the `NET.CFG` probe host,
selects and ARPs the TCP next hop, opens a TCP connection to port 80, and sends
the final ACK.

Build 6 adds the dark `"o"` secure-connection checkpoint, the normal `"o"`
local crypto checkpoint, and the bright `"o"` agent/environment checkpoint.
MDA collapses dark and normal `"o"` to the same non-bright attribute. The
current ready screen also proves that agent interfaces came from either a valid
FAT12 root `AGENTS.CFG` file or the built-in `openai`, `anthropic`, and
`google` fallback, and that selected agent and connection values came from
either valid `USER.CFG` state or the question flow. With valid saved `USER.CFG`, the
Build 6 path also resolves the selected agent host and proves TCP 443
connection, then sends a minimal TLS 1.2 ClientHello with SNI offering only
P-256 ECDHE-ECDSA-CHACHA20-POLY1305 without extended master secret for the
current crypto path, parses
ServerHello version, random, cipher-suite, session-id, known extension flags,
selected cipher path, and the following Certificate handshake header, drains
the Certificate handshake to the next handshake boundary, parses
ServerKeyExchange, captures the uncompressed P-256 public point, converts X/Y
into 16-bit little-endian field words, range-checks them below the P-256 prime,
parses ServerHelloDone, maintains a live SHA-256 TLS handshake transcript
context through ServerHelloDone, computes the sparse fixed-scalar ECDHE shared
point, converts the Jacobian result into the affine X-coordinate pre-master
secret, derives the TLS master secret and ChaCha20-Poly1305 client/server
write keys and IVs with the TLS 1.2 SHA-256 PRF, sends ClientKeyExchange,
sends ChangeCipherSpec and encrypted client Finished, receives and verifies
encrypted server Finished, then begins the minimal hardcoded OpenAI Responses
API request path. On 1 May 2026, all seven original-speed NIC profiles
completed that request/response proof and displayed the returned `ok`:
`vm-net-3c501`, `vm-net-3c503`, `vm-net-ne1k`, `vm-net-ne2k8`,
`vm-net-novell-ne1k`, `vm-net-wd8003e`, and `vm-net-wd8003eb`. On 4 May 2026,
the 64 KiB baseline was retested before memory-slimming work:
`vm-net-3c503`, `vm-net-ne1k`, `vm-net-ne2k8`, `vm-net-novell-ne1k`,
`vm-net-wd8003e`, and `vm-net-wd8003eb` reached `seed build 6` and displayed
`ok`; `vm-net-3c501` failed at agent setup and became the open valid-profile
failure. On 7 May 2026, the 32 KiB slimming checkpoint repaired that failure
in representative family tests: `vm-net-ne2k8`, `vm-net-3c501`,
`vm-net-3c503`, and `vm-net-wd8003e` each displayed `ok` and reached
`seed build 6`. The current Build 7 low-memory path uses the same profiles
through the ROM BASIC sidecar bootstrap while `make inspect` enforces the
16 KiB packed-memory layout.

## IBM PC 5150 Candidates

These are the 86Box card identifiers that matter first for the 8-bit IBM PC
target:

```text
3c501        3Com EtherLink (3c500/3c501)
3c503        3Com EtherLink II
novell_ne1k  Novell NE1000
ne1k         NE1000 Compatible
ne2k8        NE2000 Compatible 8-bit
wd8003e      Western Digital WD8003E
wd8003eb     Western Digital WD8003EB
```

## MCA Candidates

These are available in 86Box, but they are not valid IBM PC 5150 cards. The
`/A` Western Digital profiles were checked on the 5150 and did not respond
there; they should move to an MCA-capable target.

```text
ethernextmc  NetWorth EtherNext/MC
wd8003eta    Western Digital WD8003ET/A
wd8003ea     Western Digital WD8003E/A
wd8013epa    Western Digital WD8013EP/A
```

## Later ISA Candidates

These are useful once we move beyond the strict original-PC shape:

```text
novell_ne2k  Novell NE2000
ne2k         NE2000 Compatible
ne2kpnp      Realtek RTL8019AS
de220p       D-Link DE-220P
pcnetisa     AMD PCnet-ISA
pcnetracal   Racal Interlan EtherBlaster
pcnetisaplus AMD PCnet-ISA+
wd8013ebt    Western Digital WD8013EBT
```

## PCI And Newer Targets

These should be tested on later x86 targets with PCI/modern buses:

```text
ne2kpci              Realtek RTL8029AS
pcnetpci             AMD PCnet-PCI II
pcnetfast            AMD PCnet-FAST III
pcnetfast_onboard    AMD PCnet-FAST III on-board
dec_21040_tulip      DEC DE-435 EtherWorks Turbo
dec_21140_tulip      DEC 21140 Fast Ethernet
dec_21143_tulip      DEC DE-500A Fast Ethernet
dec_21140_tulip_vpc  Microsoft Virtual PC Network
rtl8139c+            Realtek RTL8139C+
```

## Current 5150 Test Profiles

All current 5150 candidate profiles were boot-tested for the Build 6
internet-proof checkpoint on 27 April 2026 with `USER.CFG` excluded from the
test floppy. Each NIC-present profile reached the dark `"o"` secure-connection
`agent?` prompt after packet-level internet readiness and FAT12 `AGENTS.CFG`
parsing. With a valid `USER.CFG`, the same checkpoint can skip the prompt and
advance to the `seed build 6` splash.

On 28 April 2026, ambiguous-family autodetect and the saved-config agent-prep
path were smoke-tested with saved `USER.CFG`. NE1000/NE2000, WD8003, and 3c501
profiles reached `seed build 6` without `adapter?`. The stricter ServerHello
handshake proof was smoke-tested on `vm-net-3c501` and `vm-net-ne2k8`. The
ServerHello state parser was smoke-tested on `vm-net-3c501` and `vm-net-ne2k8`;
extension parsing and Certificate handshake header parsing were smoke-tested on
`vm-net-3c501` and `vm-net-ne2k8`. Certificate handshake draining was
smoke-tested across all listed NIC-present profiles. TCP receive sequence
validation, ChaCha20-Poly1305-only cipher negotiation, ServerKeyExchange and
P-256 public-point capture/range-check, ServerHelloDone parsing, and the live
SHA-256 transcript context through ServerHelloDone were smoke-tested on
`vm-net-3c501` and `vm-net-ne2k8`. ECDHE pre-master generation and TLS
key-schedule derivation after the pre-master secret were first smoke-tested on
`vm-net-ne2k8` on 29 April 2026.

On 30 April 2026, `vm-net-ne2k8` completed the current direct OpenAI TLS path
through encrypted server Finished verification and reached `seed build 6`.
On 1 May 2026, all original-speed 4.77 MHz NIC profiles completed the minimal
direct OpenAI Responses request/response proof and displayed the returned `ok`:
`vm-net-3c501`, `vm-net-3c503`, `vm-net-ne1k`, `vm-net-ne2k8`,
`vm-net-novell-ne1k`, `vm-net-wd8003e`, and `vm-net-wd8003eb`.
On 4 May 2026, the 64 KiB baseline was retested before memory-slimming work:
all valid profiles except `vm-net-3c501` reached `seed build 6` and displayed
`ok`; `vm-net-3c501` failed at agent setup and remained open until the 32 KiB
slimming pass. On 7 May 2026, representative 32 KiB family tests repaired that
failure: `vm-net-ne2k8`, `vm-net-3c501`, `vm-net-3c503`, and
`vm-net-wd8003e` each displayed `ok` and reached `seed build 6`. The 24 KiB
ROM BASIC sidecar path later reached returned `ok` on those same
representative families before the compact helper release; the released hex
helper was smoke-tested through returned `ok` on `vm-net-ne2k8`.

Also on 30 April 2026, the fixed shipped agent hosts were checked against
Seed's single current TLS path: TLS 1.2, P-256,
ECDHE-ECDSA-CHACHA20-POLY1305 without extended master secret. `api.openai.com`,
`api.anthropic.com`, `generativelanguage.googleapis.com`, and `openrouter.ai`
all negotiated that path. `litellm` remains a dynamic endpoint entry and must
point at a server with the same compatibility profile.

```text
vm                   no network card; expected: red "." no network card, retry/restart menu
vm-mda               no network card, MDA; expected: bright "." no network card, retry/restart menu
vm-net-3c501         3Com EtherLink; expected: auto family, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, OpenAI Responses request/response, returned ok, then splash
vm-net-3c503         3Com EtherLink II; expected: MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, OpenAI Responses request/response, returned ok, then splash
vm-net-ne1k          NE1000-compatible; expected: auto family, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, OpenAI Responses request/response, returned ok, then splash
vm-net-ne2k8         8-bit NE2000-compatible; expected: auto family, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, OpenAI Responses request/response, returned ok, then splash
vm-net-novell-ne1k   Novell NE1000; expected: auto family, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, OpenAI Responses request/response, returned ok, then splash
vm-net-wd8003e       Western Digital WD8003E; expected: auto family, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, OpenAI Responses request/response, returned ok, then splash
vm-net-wd8003eb      Western Digital WD8003EB; expected: auto family, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, OpenAI Responses request/response, returned ok, then splash
```

The WD8003 86Box profiles must use a five-digit shared-memory address and byte
size:

```ini
ram_addr = D0000
ram_size = 8192
```

Run a profile with:

```sh
tools/run-86box.sh vm-net-ne2k8
```

The later ISA and PCI cards stay in the inventory, but they should be tested
under later machine profiles instead of the original IBM PC 5150 profile.
