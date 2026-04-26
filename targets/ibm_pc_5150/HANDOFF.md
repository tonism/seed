# IBM PC 5150 Handoff Block

Stage 2 publishes its current boot/runtime state at:

```text
0000:0600
```

This block is runtime state, not persisted config. It exists so later boot-core,
network, and environment code can consume one stable contract instead of
depending on stage 2 internal variables.

The address is below the boot sector stack and stage 2 load address, and above
the interrupt vector table and BIOS data area.

## Layout

All multi-byte values are little-endian.

```text
offset  size  value
0x00    4     magic: "SEED"
0x04    1     structure version: 2
0x05    1     structure size: 40
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
```

## Network Readiness Status

```text
0  none
1  adapter identity ready
2  packet hardware ready
3  NE-family transmit proof sent
4  NE-family receive ring poll ready
5  NE-family receive frame read
```

## Network Error

```text
0  none
1  NE-family packet hardware init failed
2  NE-family transmit proof failed
3  NE-family receive read failed
```

Build 4 fills the block through adapter-family resolution plus 3c501, 3c503,
NE1000/NE2000, and WD8003 station-address PROM reads. It records IRQ 3 for the
current 86Box IBM PC 5150 profiles after adapter family resolution; IRQ
discovery, packet I/O, IP config, TLS, and model API connection are later
milestones.

Build 5 extends the block for internet readiness. The current checkpoint marks
adapter identity readiness for all resolved NICs, then advances
NE1000/NE2000-family cards through packet hardware readiness, transmit proof,
receive-ring poll readiness, and one receive-frame read when a packet is
already pending. IP, router, and DNS fields remain zero until DHCP or an
equivalent network configuration path exists.
