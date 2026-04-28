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

Build 6 adds the bright `"o"` agent-prep checkpoint. The current ready screen
also proves that agent interfaces came from either a valid FAT12 root
`AGENTS.CFG` file or the built-in `openai`, `anthropic`, and `google`
fallback, and that selected agent and connection values came from either valid
`USER.CFG` state or the bright question flow. With valid saved `USER.CFG`, the
Build 6 path also resolves the selected agent host and proves TCP 443
connection, then sends a minimal TLS 1.2 ClientHello with SNI and parses a
ServerHello handshake before the ready splash.

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
test floppy. Each NIC-present profile reached the bright `"o"` agent-prep
`agent?` prompt after packet-level internet readiness and FAT12 `AGENTS.CFG`
parsing. With a valid `USER.CFG`, the same checkpoint can skip the prompt and
advance to the `seed build 6` splash.

On 28 April 2026, ambiguous-family autodetect and the saved-config agent-prep
path were smoke-tested with saved `USER.CFG`. NE1000/NE2000, WD8003, and 3c501
profiles reached `seed build 6` without `adapter?`. The stricter ServerHello
handshake proof was smoke-tested on `vm-net-3c501` and `vm-net-ne2k8`.

```text
vm                   no network card; expected: red "." no network card, retry/restart menu
vm-mda               no network card, MDA; expected: bright "." no network card, retry/restart menu
vm-net-3c501         3Com EtherLink; expected: auto family, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, then agent?
vm-net-3c503         3Com EtherLink II; expected: MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, then agent?
vm-net-ne1k          NE1000-compatible; expected: auto family, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, then agent?
vm-net-ne2k8         8-bit NE2000-compatible; expected: auto family, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, then agent?
vm-net-novell-ne1k   Novell NE1000; expected: auto family, MAC read, RX read check, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, then agent?
vm-net-wd8003e       Western Digital WD8003E; expected: auto family, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, then agent?
vm-net-wd8003eb      Western Digital WD8003EB; expected: auto family, MAC read, DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, TCP connected, ServerHello, then agent?
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
