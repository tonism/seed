# IBM PC 5150 Handoff Block

The boot core publishes its current boot/runtime state at:

```text
0000:0600
```

This block is runtime state, not persisted config. It exists so later boot-core,
network, and environment code can consume one stable contract instead of
depending on boot core internal variables.

The address is above the interrupt vector table and BIOS data area. During
project init the reserved loader temporarily occupies this address range; after
the loader jumps to `CORE.SYS` at `0000:1000`, the runtime clears and publishes
the handoff block at `0000:0600`.

## Layout

All multi-byte values are little-endian.

```text
offset  size  value
0x00    4     magic: "SEED"
0x04    1     structure version: 3
0x05    1     structure size: 44
0x06    2     build number
0x08    2     flags
0x0a    1     BIOS boot drive
0x0b    1     BIOS video mode
0x0c    1     active text columns
0x0d    1     centered seed column
0x0e    2     responding NIC I/O base, or 0
0x10    1     NIC family
0x11    1     config source
0x12    1     NIC IRQ, or 0 when unknown
0x13    6     MAC address, zero until valid
0x19    1     status
0x1a    1     network readiness status
0x1b    1     network error code
0x1c    4     IPv4 address, zero until configured
0x20    4     IPv4 router, zero until configured
0x24    4     IPv4 DNS server, zero until configured
0x28    4     IPv4 subnet mask, zero until configured
```

## Flags

```text
0x0001  MDA display
0x0002  NIC responded
0x0004  adapter family resolved
0x0008  MAC address valid
```

## NIC Families

```text
0  none or unresolved
1  3c503
2  ne2000
3  ne1000
4  3c501
5  wd8003
```

## Config Source

```text
0  none
1  auto
2  user answer
```

## Status

```text
1  booting
2  no network card
3  ready
4  network setup failed
5  agent setup failed
```

## Network Readiness Status

```text
0  none
1  adapter identity ready
2  packet hardware ready
3  NE-family transmit path ready
4  NE-family receive ring poll ready
5  NE-family receive frame read
6  DHCPDISCOVER sent
7  DHCPOFFER received and parsed
8  DHCPREQUEST sent
9  DHCPACK received; lease accepted
10 ARP request sent for DHCP-provided DNS server
11 ARP reply received; destination MAC resolved
12 DNS query sent
13 DNS response received; A address parsed
14 ARP request sent for selected TCP next hop
15 ARP reply received; TCP next-hop MAC resolved
16 TCP SYN sent
17 TCP SYN-ACK received
18 TCP connected; final ACK sent
19 TCP payload sent
20 TCP payload received
21 TLS ClientHello sent
22 TLS record header received
23 TLS ServerHello received
```

## Network Error

```text
0  none
1  NE-family packet hardware init failed
2  NE-family transmit failed
3  NE-family receive read failed
4  no matching DHCPOFFER observed before the bounded poll ended
5  NE-family receive DMA timed out
6  NE-family receive header was outside the configured ring
7  NE-family receive byte count was invalid
8  no matching DHCPACK observed before the bounded wait ended
9  DNS-server ARP target was missing or did not resolve before the bounded wait ended
10 no matching DNS response observed before the bounded wait ended
11 selected TCP next hop was missing or did not resolve before the bounded wait ended
12 no matching TCP SYN-ACK observed before the bounded wait ended
13 no TLS ServerHello observed after ClientHello
```

Build 4 fills the block through adapter-family resolution plus 3c501, 3c503,
NE1000/NE2000, and WD8003 station-address PROM reads. It records IRQ 3 for the
current 86Box IBM PC 5150 profiles after adapter family resolution; IRQ
discovery, packet I/O, IP config, TLS, and model API connection are later
milestones.

Build 5 extends the block for internet readiness. The current checkpoint marks
adapter identity readiness for all resolved NICs, then advances
NE1000/NE2000-family cards through packet hardware readiness, receive-ring poll
readiness, one receive-frame read when a packet is already pending,
DHCPDISCOVER transmit, and a two-pass bounded filtered DHCPOFFER wait. When an
offer is available, Seed sends DHCPREQUEST and performs a bounded DHCPACK wait.
After DHCPACK, it sends a bounded ARP request for the DHCP-provided DNS server
and records the resolved MAC internally for the DNS packet step. It then reads
the optional `NET.CFG` probe host, falls back to `example.com` if that file is
missing or invalid, sends a minimal DNS A query, and records the returned IPv4
address internally. Seed selects the TCP next hop using the DHCP subnet mask and
router, ARPs that next hop, opens a TCP connection to port 80, and sends the
final ACK after receiving a matching SYN-ACK.
The NE receive path records separate DMA, ring-header, and byte-count failures
so DHCP receive behavior can be diagnosed without changing user-facing text.
When status is 7, the IP, subnet mask, router, and DNS fields contain
byte-order IPv4 values copied from the offer. When status is 9, the offered
lease was acknowledged. When status is 11, the DNS server's Ethernet MAC has
been resolved. When status is 13, a DNS response matching Seed's query ID and
UDP port was received and an A record was parsed. When status is 18, the TCP
reachability proof has completed the handshake. If no offer, ACK, ARP reply,
DNS response, or SYN-ACK is observed during the bounded waits, the dark `"o"`
internet phase fails into the network setup error path with the corresponding
status and network error.

Build 6 starts the bright `"o"` agent-prep phase. The current checkpoint
extends the network readiness states for TCP payload send/receive and the first
TLS handshake proof. It parses up to five `AGENTS.CFG` `agent ` declarations and falls
back to built-in `openai`, `anthropic`, and `google` when that file is missing
or bad. It validates a saved `USER.CFG` selected-agent choice when present, asks
`agent?` when that choice is missing or invalid, asks `server?` and `key?` on
one form when both selected-agent connection values are required, preserves
saved model and reasoning values when present, resolves the selected agent
host, proves TCP 443 connection, sends a minimal TLS 1.2 ClientHello with SNI,
requires a handshake record, parses the first handshake message as ServerHello,
stores the ServerHello version, random, cipher-suite, session-id, known
extension flags, and selected cipher path internally, and writes the validated
values back best-effort.
If agent endpoint reachability fails, status is set to 5 and Seed enters the
agent setup error path before the ready splash.
