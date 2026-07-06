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
0x04    1     structure version: 4
0x05    1     structure size: 46
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
0x2c    2     runtime RAM top used for the initial stack
```

## Capability vector (Build 12)

This block is also Seed's **capability vector** — the boot-detected facts that
drive what loads and where (see [../../docs/architecture.md](../../docs/architecture.md),
"Capability Tiers" and "The One-Artifact Relocation Model"). Three dimensions are
live today (struct version 4):

```text
RAM tier     derived from RAM top (0x2c): < 32 KiB = 16K tier, >= 32 KiB = 32K tier.
             (Only 16K and 32K boot configurations exist; >32K reuses the 32K tier.)
NIC family   0x10, used to select the active adapter path.
CPU class    flags bit handoff_flag_cpu_286plus (0x0010): set when the CPU is a 286 or
             better (hardware_setup's FLAGS bits-12-15 test) — gates the secure tier.
Writable     flags bit handoff_flag_writable_media (0x0040): set when a non-destructive
media        boot-sector write-back probe succeeds — gates the persistence tier (env
             save/load). Clear on write-protected media (the recovery-boundary mode).
```

The remaining capability dimensions are **reserved for later feature tiers**:

```text
finer CPU class  V20 / 386 / 486 distinctions — only "is 286+" is needed today.
FPU present      reserved flags bit 0x0020; held but inert (the FPU does not unlock
                 secure crypto; measured), so detection is deferred until a consumer.
link type        wired / Wi-Fi — selects driver + setup-UI family (no Wi-Fi yet).
```

The CPU-class **gate** rides a free `flags` bit on purpose: the struct is
**full-packed** (it ends at `0x2e`, and `low_runtime_state` begins immediately there
and runs packed to the `0x0700` phase window), so a dedicated *byte* would have to
grow the struct and reclaim low-runtime-state slack first. A single bit is all the
secure tier's gate needs, so it avoids that. Promoting CPU class to a richer field,
or allocating FPU / link-type as bytes, is the job of the session that adds a
consumer needing the finer value: bump the struct version, append the field(s), and
re-verify the low scratch fits via `tools/check-layout.py`.

## Flags

```text
0x0001  MDA display
0x0002  NIC responded
0x0004  adapter family resolved
0x0008  MAC address valid
0x0010  CPU is 286 or better (handoff_flag_cpu_286plus) — gates the secure tier
0x0020  FPU present (reserved; held but inert — the FPU does not unlock secure crypto)
0x0040  writable boot media present (handoff_flag_writable_media) — gates the persistence tier
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
24 TLS Certificate handshake header received
25 TLS Certificate handshake drained to the next handshake boundary
26 TLS ServerKeyExchange received and P-256 public point range-checked
27 TLS ServerHelloDone received
28 live SHA-256 TLS handshake transcript context updated through ServerHelloDone
29 ECDHE pre-master secret generated from the server public point
30 TLS master secret and client/server traffic keys derived
31 TLS ClientKeyExchange sent and added to the live handshake transcript
32 TLS ChangeCipherSpec sent
33 encrypted TLS client Finished sent and added to the live handshake transcript
34 TLS server ChangeCipherSpec received
35 encrypted TLS server Finished authenticated, decrypted, and verified
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
13 TLS handshake proof failed
```

The block is filled through adapter-family resolution plus 3c501, 3c503,
NE1000/NE2000, and WD8003 station-address PROM reads. It records IRQ 3 for the
current 86Box IBM PC 5150 profiles after adapter family resolution.

For internet readiness, the block marks
adapter identity readiness for all resolved NICs, then advances
NE1000/NE2000-family cards through packet hardware readiness, receive-ring poll
readiness, one receive-frame read when a packet is already pending,
DHCPDISCOVER transmit, and a two-pass bounded filtered DHCPOFFER wait. When an
offer is available, Seed sends DHCPREQUEST and performs a bounded DHCPACK wait.
After DHCPACK, it sends a bounded ARP request for the DHCP-provided DNS server
and records the resolved MAC internally for the DNS packet step. It then resolves
the selected agent host with a minimal DNS A query and records the returned IPv4
address internally. (Build 11 removed the old standalone `example.com` port-80
connectivity probe and its `NET.CFG` parse; the DNS and TCP path now targets the
agent endpoint directly.) Seed selects the TCP next hop using the DHCP subnet mask
and router, ARPs that next hop, opens a TCP connection to the agent endpoint, and
sends the final ACK after receiving a matching SYN-ACK.
The NE receive path records separate DMA, ring-header, and byte-count failures
so DHCP receive behavior can be diagnosed without changing user-facing text.
When status is 7, the IP, subnet mask, router, and DNS fields contain
byte-order IPv4 values copied from the offer. When status is 9, the offered
lease was acknowledged. When status is 11, the DNS server's Ethernet MAC has
been resolved. When status is 13, a DNS response matching Seed's query ID and
UDP port was received and an A record was parsed. When status is 18, the TCP
reachability proof has completed the handshake. If no offer, ACK, ARP reply,
DNS response, or SYN-ACK is observed during the bounded waits, the dark `","`
internet phase fails into the network setup error path with the corresponding
status and network error.

The secure-connection phase follows the dark `","` internet phase. It uses a dark `"o"` for
secure connection prep, switches to a normal `"o"` for local ECDHE/key
material derivation, and switches to a bright `"o"` after the TLS
proof succeeds. On MDA, dark and normal `"o"` both render non-bright. This phase
covers the network readiness states for TCP payload send/receive and the
TLS handshake proof. It parses up to five `AGENTS.CFG` `agent ` declarations and falls
back to built-in `openai`, `anthropic`, and `google` when that file is missing
or bad. It validates a saved `USER.CFG` selected-agent choice when present, asks
`agent?` when that choice is missing or invalid, asks `server?` and `key?` on
one form when both selected-agent connection values are required, preserves
saved model and reasoning values when present, resolves the selected agent
host, proves TCP 443 connection, then runs the full TLS 1.2 / application-data
path (ClientHello through encrypted application data) documented once in
[../../docs/architecture.md](../../docs/architecture.md), "Provider Timing
Model", advancing the network-readiness states above, and only then finishes
writing the validated values back best-effort.
If agent endpoint reachability fails, status is set to 5 and Seed enters the
agent setup error path before the ready splash.

## Context-management knobs

Seed runs a conversation context window with model-driven compaction (see
[../../docs/architecture.md](../../docs/architecture.md), "User/Agent Environment").
Three knobs govern it:

```text
window      conversation window address. Recent turns accumulate here (raw, JSON-escaped
            only at send) and ride in the request ahead of the prompt.
arena       user/agent arena address - the free RAM Seed leaves for the agent to build in.
threshold   the compaction-threshold byte: address + value, default 3/4 of the window.
```

Compaction is measured before each request: when the window is past the threshold, Seed
compacts the older turns into a rolling model-written summary (the `COMPACT` static prompt's
contract) and keeps the recent turns verbatim, so context is preserved while the window stays
bounded; the user sees a dim, fast-typed `compacting context` status line. Measuring before
send guarantees the reply has room to land. The window and arena scale with RAM on a larger
machine, so it holds more verbatim context and compacts less often with no mechanism change.

The model-facing ledger keeps only the cheap, actionable memory facts: `r=`/`a@` for the
seg-0 arena, `F@`/`e@` for larger arenas, `s=` for save availability, and `c@` for the
context-cap variable address. Network diagnostics remain in this handoff block, not in the
per-turn model ledger.
