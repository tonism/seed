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
the loader jumps to `SEED.SYS` at `0000:1000`, the runtime clears and publishes
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

## Capability vector

This block is also Seed's **capability vector** — the boot-detected facts that
drive what loads and where (see [../../docs/architecture.md](../../docs/architecture.md),
"Capability Tiers" and "The One-Artifact Relocation Model"). These dimensions are
live today (struct version 4):

```text
RAM tier     derived from RAM top (0x2c): < 32 KiB = 16K tier, >= 32 KiB = 32K tier.
             (Only 16K and 32K boot shapes exist; >32K reuses the 32K shape and grows
             arena/context through the memory-reach tiers.)
NIC family   0x10, used to select the active adapter path.
CPU class    flags bit handoff_flag_cpu_286plus (0x0010): set when the CPU is a 286 or
             better (hardware_setup's FLAGS bits-12-15 test). The conforming
             TLS tier additionally requires BDA conventional memory >=512 KiB.
             flags bit handoff_flag_cpu_386plus (0x0080): set when the CPU supports the
             386+ unreal-mode memory tier.
HMA          flags bit handoff_flag_hma (0x0100): A20 was enabled and the HMA direct
             range is available.
Unreal       flags bit handoff_flag_unreal (0x0200): 386 unreal mode is available for
             high-memory direct access.
```

The remaining capability dimensions are **reserved for later feature tiers**:

```text
finer CPU class  V20 / 486 distinctions beyond the live 286+ and 386+ flags.
FPU present      flags bit 0x0020; held but inert (the FPU does not unlock
                 secure crypto; measured), so detection is deferred until a consumer.
link type        wired / Wi-Fi — selects driver + setup-UI family (no Wi-Fi yet).
```

The CPU-class **fact** rides a free `flags` bit on purpose: the struct is
**full-packed** (it ends at `0x2e`, and `low_runtime_state` begins immediately there
and runs packed to the `0x0700` phase window), so a dedicated *byte* would have to
grow the struct and reclaim low-runtime-state slack first. A single bit is all the
CPU test needs, so it avoids that. `handoff_ram_top` is only the low entry
ceiling and must not be used for the 512 KiB TLS gate; read the BDA
conventional-memory word. Promoting CPU class to a richer field,
or allocating FPU / link-type as bytes, is the job of the session that adds a
consumer needing the finer value: bump the struct version, append the field(s), and
re-verify the low scratch fits via `tools/check-layout.py`.

## Flags

```text
0x0001  MDA display
0x0002  NIC responded
0x0004  adapter family resolved
0x0008  MAC address valid
0x0010  CPU is 286 or better; conforming TLS also requires BDA RAM >=512 KiB
0x0020  FPU present (reserved; held but inert — the FPU does not unlock secure crypto)
0x0040  reserved writable-media hint (handoff_flag_writable_media); startup does not probe or write
0x0080  CPU is 386 or better (handoff_flag_cpu_386plus) — gates unreal setup
0x0100  HMA available (handoff_flag_hma)
0x0200  unreal mode available (handoff_flag_unreal)
0x0400  WD80x3 shared RAM window is DC000 instead of D0000
```

## NIC Families

```text
0  none or unresolved
1  3c503
2  ne2000
3  ne1000
4  3c501
5  wd8003
6  wd8013
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

Values 21–35 are retained legacy TLS 1.2 diagnostic values in structure
version 4. The TLS 1.3 product routes do not expose their internal
provisional/quarantine/committed security state through this byte: that would
let a compatibility diagnostic become an authority boundary. Their capability
publication is private, redundant, status-last state, and the handoff reaches
ordinary ready only after product dispatch returns success.

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
14 no suitable NIC driver was present or loaded
```

The block is filled through adapter-family resolution plus 3c501, 3c503,
NE1000/NE2000, and WD80x3 station-address PROM reads. It records IRQ 3 for the
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
address internally. (The old standalone `example.com` port-80 connectivity
probe is gone; the DNS and TCP path now targets the
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

The TLS phase follows the dark `","` internet phase. It uses a dark `"o"` for
connection prep, a normal `"o"` for local key/proof work, and a bright `"o"`
only after the selected TLS 1.3 route commits. The 8088 profile keeps all TLS
state in conventional RAM; CGA and MDA memory remain ordinary display state.

OpenAI is the only current provider route. The runtime validates the shipped
declaration and optional saved OpenAI values, resolves `api.openai.com`, and
dispatches by CPU/RAM capability. Pre-286 uses the 8088 cold K14 route;
CPU286+ with BDA conventional memory >=512 KiB uses the fully conforming
`X25519MLKEM768` acquisition/offline-auth/no-0RTT-resumption route. Its
tentative same-boot ticket is promoted only after full FO and
YE2/hostname/UTC/CV proof; the final connection uses independent hybrid keys
and publishes credentials only after resumed Finished verification. There is
no TLS 1.2 fallback and no downgrade between profiles after admission.

The handoff does not contain tickets, certificate pins, entropy bundles,
traffic secrets, or credential-unlock state. Those are private TLS state and
are erased on failure or restart.
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
seg-0 arena, `F@` for far conventional arena, `H@` for HMA, `e@` for EMS or native
extended arena, `s=` for save availability, and `c@` for the context-cap variable
address. Network diagnostics remain in this handoff block, not in the per-turn model ledger.
