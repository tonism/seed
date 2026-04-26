# 86Box NIC Inventory

Build 4 treats network support as hardware discovery plus an in-memory config
handoff. Stage 2 probes common ISA Ethernet I/O bases, records the responding
I/O base, starts resolving the adapter family when the base is ambiguous, and
reads 3c503 plus NE1000/NE2000 station-address PROMs into the handoff block
when they validate. Packet I/O is later scope.

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

```text
vm                   no network card; expected: + no network card
vm-mda               no network card, MDA; expected: + no network card
vm-net-3c501         3Com EtherLink; expected: adapter prompt, then seed build 4
vm-net-3c503         3Com EtherLink II; expected: MAC read, then seed build 4
vm-net-ne1k          NE1000-compatible; expected: adapter prompt, MAC read, then seed build 4
vm-net-ne2k8         8-bit NE2000-compatible; expected: adapter prompt, MAC read, then seed build 4
vm-net-novell-ne1k   Novell NE1000; expected: adapter prompt, MAC read, then seed build 4
vm-net-wd8003e       Western Digital WD8003E; expected: adapter prompt, then seed build 4
vm-net-wd8003eb      Western Digital WD8003EB; expected: adapter prompt, then seed build 4
```

Run a profile with:

```sh
tools/run-86box.sh vm-net-ne2k8
```

The later ISA and PCI cards stay in the inventory, but they should be tested
under later machine profiles instead of the original IBM PC 5150 profile.
