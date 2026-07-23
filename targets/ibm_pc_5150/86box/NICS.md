# 86Box NIC Inventory

Build 5 treated network support as internet readiness. Stage 2 still probes
common ISA Ethernet I/O bases, records the responding I/O base, starts
resolving the adapter family when the base is ambiguous, and reads 3c501,
3c503, NE1000/NE2000, and WD80x3 station-address PROMs into the handoff block
when they validate. It also records IRQ 3 for the current 5150 86Box profiles
after adapter family resolution. The packet path now covers all current 5150
candidate families: 3c501, 3c503, NE1000/NE2000, and WD80x3. It initializes
packet hardware, sends DHCPDISCOVER, waits for DHCPOFFER, parses IPv4 address,
subnet mask, router, and DNS server, sends DHCPREQUEST, waits for DHCPACK,
sends ARP for the DHCP-provided DNS server, resolves the selected agent host,
selects and ARPs the TCP next hop, opens a TCP connection to port 443, and sends
the final ACK.

Build 6 adds the dark `"o"` secure-connection checkpoint, the normal `"o"`
local crypto checkpoint, and the bright `"o"` agent/environment checkpoint.
MDA collapses dark and normal `"o"` to the same non-bright attribute. The
current ready screen also proves that agent interfaces came from either a valid
FAT12 `SEED/AGENTS.CFG` file or the built-in `openai`, `anthropic`, and
`google` fallback, and that selected agent and connection values came from
either valid `SEED/USER.CFG` state or the question flow. With valid saved `SEED/USER.CFG`, the
Build 6 path also resolves the selected agent host and proves TCP 443
connection, then runs the full TLS 1.2 / application-data path (ClientHello
through encrypted application data) documented once in
[../../../docs/architecture.md](../../../docs/architecture.md), "Provider
Timing Model", then begins the minimal hardcoded OpenAI Responses
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
`seed build 6`. The current entry path uses the same profiles
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

These are useful once we move beyond the strict original-PC shape. The generic,
Novell, and ISA PnP NE2000-class adapters use the existing `NE.DRV` DP8390
path. The PnP cards need a bounded ISA PnP activation pass first; Seed assigns
the supported Realtek RTL8019AS, D-Link DE-220P, and AMD PCnet-ISA+ IDs to I/O
base 0x300 and IRQ 3, plus DMA 5 for PCnet-ISA+, then lets the normal MAC/PROM
probe and driver metadata selection run. The PCnet/LANCE adapters use
`PCNET.DRV`. The 16-bit Western Digital adapter uses the existing
`WD80X3.DRV` shared-memory path with WD8013-specific ring bounds. These are
covered by checked-in 386SX profiles.

```text
ne2k             NE2000 Compatible             covered by vm-net-ne2k
novell_ne2k      Novell NE2000                 covered by vm-net-novell-ne2k
ne2kpnp          Realtek RTL8019AS             covered by vm-net-ne2kpnp
de220p           D-Link DE-220P                covered by vm-net-de220p
wd8013ebt        Western Digital WD8013EBT     covered by vm-net-wd8013ebt
pcnetisa         AMD PCnet-ISA                 covered by vm-net-pcnetisa
pcnetracal       Racal Interlan EtherBlaster   covered by vm-net-pcnetracal
pcnetisaplus     AMD PCnet-ISA+                covered by vm-net-pcnetisaplus
```

## PCI And Newer Targets

These should be tested on later x86 targets with PCI/modern buses:

```text
ne2kpci              Realtek RTL8029AS             covered by vm-net-ne2kpci
pcnetpci             AMD PCnet-PCI II              covered by vm-net-pcnetpci
pcnetfast            AMD PCnet-FAST III            covered by vm-net-pcnetfast
pcnetfast_onboard    AMD PCnet-FAST III on-board   needs a machine-integrated profile
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
`agent?` prompt after packet-level internet readiness and FAT12 `SEED/AGENTS.CFG`
parsing. With a valid `SEED/USER.CFG`, the same checkpoint can skip the prompt and
advance to the `seed build 6` splash.

On 28 April 2026, ambiguous-family autodetect and the saved-config agent-prep
path were smoke-tested with saved `SEED/USER.CFG`. NE1000/NE2000, WD8003, and 3c501
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

On 21 July 2026, the Build 13 PCnet/LANCE expansion reached the Default Prompt
Interface and returned `kiwi` on `vm-net-pcnetisa`, `vm-net-pcnetracal`, and
`vm-net-pcnetisaplus`. The same checkpoint revalidated `vm-net-ne2kpnp` and
the original-speed 16 KiB `vm-net-ne2k8` path after moving the NE PROM read
buffer out of the hardware-setup phase image. The Build 13 PCI discovery
checkpoint also reached the Default Prompt Interface and returned `kiwi` on
`vm-net-ne2kpci`, with `vm-net-ne2kpnp` revalidated afterward to prove fallback
from PCI discovery to ISA PnP stayed green.

On 23 July 2026, the PCI PCnet/LANCE add-in expansion reached the Default
Prompt Interface and returned `kiwi` on `vm-net-pcnetpci` and
`vm-net-pcnetfast`. The same checkpoint revalidated `vm-net-ne2kpci` to prove
the Realtek PCI path still wins when present, and `vm-net-pcnetisa` to prove
PCI discovery still falls through cleanly to ISA PCnet discovery. The
`pcnetfast_onboard` device remains unrepresented by these add-in profiles; 86Box
exposes it as a machine-integrated NIC and it needs a separate machine-profile
checkpoint.

Also on 30 April 2026, the fixed shipped agent hosts were checked against
Seed's single current TLS path: TLS 1.2, P-256,
ECDHE-ECDSA-CHACHA20-POLY1305 without extended master secret. `api.openai.com`,
`api.anthropic.com`, `generativelanguage.googleapis.com`, and `openrouter.ai`
all negotiated that path. `litellm` remains a dynamic endpoint entry and must
point at a server with the same compatibility profile.

```text
vm                   no network card; expected: red "." no network card, retry/restart menu
vm-mda               no network card, MDA; expected: bright "." no network card, retry/restart menu
vm-net-3c501         3Com EtherLink; expected: auto family, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, OpenAI Responses request/response, returned ok below the existing splash
vm-net-3c503         3Com EtherLink II; expected: MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, OpenAI Responses request/response, returned ok below the existing splash
vm-net-ne1k          NE1000-compatible; expected: auto family, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, OpenAI Responses request/response, returned ok below the existing splash
vm-net-ne2k8         8-bit NE2000-compatible; expected: auto family, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, OpenAI Responses request/response, returned ok below the existing splash
vm-net-ne2k          16-bit NE2000-compatible on 386SX; expected: auto family through NE.DRV, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, TLS/API path, returned ok
vm-net-ne2kpci       Realtek RTL8029AS PCI on 486; expected: PCI BIOS discovery, auto family through NE.DRV, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, TLS/API path, returned ok
vm-net-ne2kpnp       Realtek RTL8019AS ISA PnP on 386SX; expected: ISA PnP activation, auto family through NE.DRV, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, TLS/API path, returned ok
vm-net-pcnetpci      AMD PCnet-PCI II on 486; expected: PCI BIOS discovery, auto family through PCNET.DRV, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, TLS/API path, returned ok
vm-net-pcnetfast     AMD PCnet-FAST III on 486; expected: PCI BIOS discovery, auto family through PCNET.DRV, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, TLS/API path, returned ok
vm-net-novell-ne1k   Novell NE1000; expected: auto family, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, OpenAI Responses request/response, returned ok below the existing splash
vm-net-novell-ne2k   Novell NE2000 on 386SX; expected: auto family through NE.DRV, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, TLS/API path, returned ok
vm-net-de220p        D-Link DE-220P ISA PnP on 386SX; expected: ISA PnP activation, auto family through NE.DRV, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, TLS/API path, returned ok
vm-net-pcnetisa      AMD PCnet-ISA on 386SX; expected: auto family through PCNET.DRV, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, TLS/API path, returned ok
vm-net-pcnetracal    Racal EtherBlaster on 386SX; expected: auto family through PCNET.DRV, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, TLS/API path, returned ok
vm-net-pcnetisaplus  AMD PCnet-ISA+ ISA PnP on 386SX; expected: ISA PnP activation, auto family through PCNET.DRV, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, TLS/API path, returned ok
vm-net-wd8003e       Western Digital WD8003E; expected: auto family, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, OpenAI Responses request/response, returned ok below the existing splash
vm-net-wd8003eb      Western Digital WD8003EB; expected: auto family, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, Certificate drained, ServerKeyExchange, ServerHelloDone, SHA-256 transcript context, ECDHE pre-master, TLS key schedule, ClientKeyExchange, ChangeCipherSpec, encrypted client Finished, server Finished verification, OpenAI Responses request/response, returned ok below the existing splash
vm-net-wd8013ebt     Western Digital WD8013EBT on 386SX; expected: auto family through WD80X3.DRV, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, TLS/API path, returned ok
```

The WD80x3 86Box profiles must use a five-digit shared-memory address and byte
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
