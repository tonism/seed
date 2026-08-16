# 86Box NIC Inventory

Adapter support is an end-to-end transport contract: detection, station
address, external driver load, packet I/O, DHCP, DNS, ARP, TCP, TLS 1.3
application records, and Default Prompt Interface reuse. PROM reads remain
non-fatal, and inactive `.DRV` files consume no resident RAM.

OpenAI at `api.openai.com` is the only current provider route. TLS 1.3 is
integrated and under validation; earlier TLS 1.2 request/response runs are
driver regression history in `docs/builds.md`, not current security evidence.

The current TLS acceptance matrix has two exact floors:

```text
8088 profile     4.77 MHz, exactly 16 KiB, ROM BASIC, read-only image;
                 seven original-speed ISA NICs plus CGA/MDA vault cases
286 conforming   6 MHz, 512 KiB conventional RAM; acquisition, offline
                 authentication, no-0RTT PSK-DHE X25519MLKEM768 resumption
```

Every live route must return authenticated OpenAI text, reuse its committed
session, and pass the one-attempt same-request reconnect policy. A no-card or
no-driver profile must retain the established clean retry/restart failure.

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
current target covers them through checked-in PS/2 Model 55SX profiles with
configured NVR.
The NetWorth card reuses `NE.DRV`; the Western Digital cards reuse
`WD80X3.DRV`. The WD MCA profiles use the PS/2 reference utility's `DC000`
shared-RAM window instead of the original ISA WD `D0000` default.

```text
ethernextmc  NetWorth EtherNext/MC         covered by vm-net-ethernextmc
wd8003eta    Western Digital WD8003ET/A    covered by vm-net-wd8003eta
wd8003ea     Western Digital WD8003E/A     covered by vm-net-wd8003ea
wd8013epa    Western Digital WD8013EP/A    covered by vm-net-wd8013epa
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

## VLB Candidates

The AMD PCnet-32 VLB card exposes the same LANCE-style I/O register window as
the ISA and PCI PCnet cards. Seed finds it through the fixed-base I/O probe and
loads the shared `PCNET.DRV`. The checked-in representative uses the CS4031
VLB machine with saved AMI setup NVR.

```text
pcnetvlb         AMD PCnet-32                  covered by vm-net-pcnetvlb
```

## PCI And Newer Targets

These should be tested on later x86 targets with PCI/modern buses:

```text
ne2kpci              Realtek RTL8029AS             covered by vm-net-ne2kpci
pcnetpci             AMD PCnet-PCI II              covered by vm-net-pcnetpci
pcnetfast            AMD PCnet-FAST III            covered by vm-net-pcnetfast
pcnetfast_onboard    AMD PCnet-FAST III on-board   covered by vm-net-pcnetfast-onboard
dec_21040_tulip      DEC DE-435 EtherWorks Turbo   covered by vm-net-dec21040
dec_21140_tulip      DEC 21140 Fast Ethernet       covered by vm-net-dec21140
dec_21143_tulip      DEC DE-500A Fast Ethernet     covered by vm-net-dec21143
dec_21140_tulip_vpc  Microsoft Virtual PC Network  covered by vm-net-dec21140vpc
rtl8139c+            Realtek RTL8139C+             covered by vm-net-rtl8139
smc_epic100          SMC EtherPower II 9432        covered by vm-net-epic100
```

## Current test profiles

The original-speed 8088-profile matrix is:

```text
vm-net-3c501        3Com EtherLink, single-buffer path
vm-net-3c503        3Com EtherLink II
vm-net-ne1k         NE1000-compatible
vm-net-ne2k8        8-bit NE2000-compatible
vm-net-novell-ne1k  Novell NE1000
vm-net-wd8003e      Western Digital WD8003E
vm-net-wd8003eb     Western Digital WD8003EB
```

The current read-only exact-floor 8088 profile passes all seven profiles
through fresh use, session reuse, a 500-second idle, and one bounded reconnect.
The exact four-flow timings are recorded in
[`../../../docs/testing.md`](../../../docs/testing.md).

`vm` and `vm-mda` are no-card failure gates. The MDA TLS vault also needs a
NIC-present exact-floor profile because it disables the only text page during
the public-object lifetime and must restore it after scrub.

For every original-speed NIC, the current expected route is:

```text
family/MAC -> .DRV load -> DHCP -> DNS/ARP -> TCP
-> TLS 1.3 8088 deadline phase -> Finished + bounded ticket receipt
-> full FO + exact dated-leaf/CV -> resumed 0-RTT credential-free liveness
-> status-last credential unlock
-> authenticated OpenAI response -> session reuse -> one bounded reconnect
```

The later-machine inventory is a driver and transport regression matrix:

```text
NE.DRV       vm-net-ne2k, vm-net-novell-ne2k, vm-net-ne2kpnp,
             vm-net-de220p, vm-net-ne2kpci, vm-net-ethernextmc
WD80X3.DRV   vm-net-wd8013ebt, vm-net-wd8003eta, vm-net-wd8003ea,
             vm-net-wd8013epa
PCNET.DRV    vm-net-pcnetisa, vm-net-pcnetracal, vm-net-pcnetisaplus,
             vm-net-pcnetvlb, vm-net-pcnetpci, vm-net-pcnetfast,
             vm-net-pcnetfast-onboard
TULIP.DRV    vm-net-dec21040, vm-net-dec21140, vm-net-dec21140vpc,
             vm-net-dec21143
RTL8139.DRV  vm-net-rtl8139
EPIC100.DRV  vm-net-epic100
```

The conforming TLS floor is specifically a 6 MHz 286 with 512 KiB
conventional RAM. A faster 386/486 NIC profile or the larger checked-in
`vm-net-286` profile does not prove it. The exact run must show the
acquisition connection, target-side offline WE1/hostname/UTC-validity/CV
proof, full FO comparison, table generation, and status-last tentative-ticket
promotion. The final connection must be no-0RTT PSK-DHE resumption with an
independent genuine ML-KEM-768 + X25519 attempt, a real binder,
`selected_identity=0`, full decapsulation, strict
EncryptedExtensions-to-Finished, client Finished before credential
publication, authenticated application data, reuse, and bounded reconnect.

Driver-family evidence remains valid only for the hardware work it exercised.
TLS 1.3 acceptance remains open until the current exact-floor matrix passes.
See [`../../../docs/testing.md`](../../../docs/testing.md) for commands and
[`../../../docs/builds.md`](../../../docs/builds.md) for dated history.
