# IBM PC 5150 Target

This target is the first Seed discipline target: an original IBM PC-class boot
path, starting from a 160 KiB 5.25-inch single-sided floppy image.

Current milestone:

```text
BIOS loads boot sector
  -> boot sector loads the fixed reserved-sector FAT12 loader
  -> loader reads CORE.SYS from the FAT12 root directory
  -> CORE.SYS reads the current BIOS text-mode column count
  -> CORE.SYS clears text mode
  -> shows the project-init load marker at the centered project start column
  -> switches to a dim . marker for HAL setup
  -> probes common ISA network card I/O bases
  -> records the responding NIC I/O base if one is found
  -> publishes boot, video, and NIC state to the handoff block at 0000:0600
  -> turns the . marker red and plays a low failure tone if no card responds
  -> offers retry/restart after a critical failure; retry returns to HAL setup
  -> probes station-address PROMs when the responding I/O base is ambiguous
  -> asks for adapter family only if the probes remain ambiguous
  -> records the current 86Box profile IRQ after adapter family resolution
  -> reads station-address PROMs into handoff when valid
  -> initializes NE1000/NE2000-family packet hardware
  -> reads one NE1000/NE2000-family pending receive-ring frame when available
  -> switches to a dim o marker for internet prep
  -> sends one NE1000/NE2000-family DHCPDISCOVER
  -> performs a two-pass filtered DHCPOFFER wait and parses it when available
  -> sends DHCPREQUEST and waits for DHCPACK when an offer is available
  -> sends ARP for the DHCP-provided DNS server after DHCPACK
  -> reads NET.CFG and resolves its probe host with a minimal DNS A query
  -> selects and ARPs the TCP next hop
  -> opens the probe TCP target on port 80 and sends the final ACK
  -> switches to a bright o marker for agent prep
  -> reads AGENTS.CFG and parses up to five agent declarations
  -> falls back to built-in openai/anthropic/google if AGENTS.CFG is missing or bad
  -> reads USER.CFG when present and validates the saved agent choice
  -> asks agent? when the saved choice is missing or invalid
  -> asks server? and key? on one form when the selected agent needs both
  -> resolves the selected agent host and proves TCP 443 connection
  -> sends a minimal TLS 1.2 ClientHello with SNI and parses ServerHello
  -> writes validated agent config back best-effort
  -> otherwise types seed build 6 rightward from that column
  -> waits about 500 ms
  -> halts
```

The floppy image is a minimal FAT12 filesystem with a stable reserved loader
and a visible file-backed runtime:

```text
sector 1       boot sector with FAT12 BPB
sectors 2-5    reserved FAT12 loader
sectors 6-7    FAT copies
sectors 8-11   root directory
sector 12+     file data, starting with CORE.SYS
```

`CORE.SYS` is shipped in the FAT12 root directory and contains the current Seed
runtime. Normal runtime updates can replace that file without rewriting the
boot sector or reserved loader.

Future artifacts may also ship host-specific loaders that jump into `CORE.SYS`
from an already-running OS. DOS `.COM`, Windows, macOS/OSX, Linux, and other
common hosts are possible candidates, but this is a one-way takeover path, not
a normal program that returns cleanly to the host OS.

`AGENTS.CFG` is shipped in the FAT12 root directory from `config/AGENTS.CFG`.
When present and valid, it overrides the built-in `openai`, `anthropic`, and
`google` direct-vendor fallback. `NET.CFG` is shipped from `config/NET.CFG` and
supplies the generic internet probe host. If `NET.CFG` is missing or bad, Seed
falls back to `example.com`. `USER.CFG` is optional ignored user-local state and
is included only when `config/USER.CFG` exists. The project-level policy is
documented in:

```text
docs/config.md
```

The Seed boot core is organized as source includes under:

```text
targets/ibm_pc_5150/boot/core/
```

This is not a runtime module system. `core.asm` includes those files in fixed
order and NASM emits one flat `CORE.SYS` runtime file.

Text UI behavior, including fast-typed errors, questions, menus, and modals, is
documented in:

```text
docs/ui.md
```

The boot core runtime handoff block is documented in:

```text
targets/ibm_pc_5150/HANDOFF.md
```

Build 5 was the internet-readiness milestone. The boot core still probes common
ISA Ethernet I/O bases, publishes boot/video/NIC state to a low-memory handoff
block, and resolves the adapter family. Known single-card bases continue
automatically. Shared bases are resolved by station-address PROM probes when
one family can be identified safely; `adapter?` remains a fallback question
when the probes are invalid or ambiguous. For 3c501, 3c503,
NE1000/NE2000-family, and WD8003-family cards, the boot core reads the
station-address PROM and marks the MAC valid only after rejecting multicast,
all-zero, and all-`ff` addresses. The boot core also records IRQ 3 for the
current 86Box IBM PC 5150 profiles once the adapter family is known; real IRQ
discovery is later scope.

The current build 5 checkpoint initializes NE1000/NE2000-family packet hardware
after a valid MAC read, polls the receive-ring pointers, reads one pending
receive frame when available, sends a minimal DHCPDISCOVER, and performs a
two-pass bounded filtered DHCPOFFER wait. When a DHCPOFFER is observed, the boot core
records the offered IPv4 address, subnet mask, router, and DNS server in the
handoff block. It then sends DHCPREQUEST and performs a bounded DHCPACK wait to
mark the lease accepted. After DHCPACK, it sends an ARP request for the
DHCP-provided DNS server, resolves the `NET.CFG` probe host, selects a TCP next
hop using the DHCP subnet/router data, ARPs that next hop, opens the probe TCP
target on port 80 through the shared TCP connect path, and sends the final ACK
after a matching SYN-ACK.

Build 6 is the agent-prep milestone. The current checkpoint keeps the build 5
internet path intact and adds the first filesystem-backed agent setup check:
the boot core reads `AGENTS.CFG`, parses up to five `agent ` declarations, reads
`USER.CFG` when present, validates a saved `agent <id>`, asks `agent?` when the
saved choice is missing or invalid, asks `server?` and `key?` on one form when
the selected agent needs both values, preserves saved model and reasoning
values when present, resolves the selected agent host, proves TCP 443
connection through the same TCP connect path, sends a minimal TLS 1.2
ClientHello with SNI, parses and stores ServerHello version, random,
cipher-suite, session-id, and extension bounds, and writes the validated values
back best-effort. Missing or invalid `AGENTS.CFG` content falls back to
built-in `openai`, `anthropic`, and `google`; other agent setup failures still
fail in the bright `"o"` phase as `agent setup failed`.

The boot path does not switch video modes. It keeps the BIOS-provided text
mode, reads the active column count, and uses that value for clearing and for
the centered project-name anchor.

The first screen text is hardcoded in `CORE.SYS` for now:

```text
project init    " "
HAL setup       dim "."
internet prep   dim "o"
agent prep      bright "o"
failure         current marker turns red, low descending PC speaker tone, fast-typed error, then retry/restart
question        phase-colored blinking marker, low PC speaker attention tone, bright fast-typed prompt ending with ?
agent question  agent? with AGENTS.CFG entries or built-in big-three fallback when USER.CFG has no valid agent choice
field question  server? and/or key? with cursor shown only while typing; Up/Down moves field focus
success         " " -> dim "." -> dim "o" -> bright "o" -> seed build 6
```

The splash is only the ready handoff animation. No hardware setup, network
negotiation, agent setup, or environment setup happens during the splash.

Adapter prompts:

```text
0x250       auto 3c503
0x280       auto wd8003 by checksum, else 3c501 by 3Com OUI; ask if unresolved
0x300       auto ne2000 or ne1000 by NE PROM layout; ask if unresolved
other base  keep base only
```

Default display attributes:

```text
seed       CGA white / MDA bright
build 6    CGA dark gray / MDA normal
loading    CGA dark gray / MDA normal
ready      CGA white / MDA bright
question   CGA white / MDA bright
error      CGA red / MDA bright
menu       selected white/bright, inactive dark gray/normal
```

Build:

```sh
make
```

Output:

```text
build/ibm_pc_5150/floppy-160k.img
```

Inspect the generated FAT12 image:

```sh
make inspect
```
