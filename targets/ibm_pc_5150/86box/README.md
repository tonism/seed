# 86Box Harness Notes

86Box is installed on this machine through Homebrew Cask, with the official
86Box ROM repository cloned to:

```text
~/Library/Application Support/net.86box.86Box/roms
```

The default no-network VM lives at:

```text
targets/ibm_pc_5150/86box/vm/86box.cfg
```

The MDA no-network VM lives at:

```text
targets/ibm_pc_5150/86box/vm-mda/86box.cfg
```

Networked success-profile VMs live beside those profiles:

```text
targets/ibm_pc_5150/86box/vm-net-3c501/86box.cfg
targets/ibm_pc_5150/86box/vm-net-3c503/86box.cfg
targets/ibm_pc_5150/86box/vm-net-ne1k/86box.cfg
targets/ibm_pc_5150/86box/vm-net-ne2k8/86box.cfg
targets/ibm_pc_5150/86box/vm-net-novell-ne1k/86box.cfg
targets/ibm_pc_5150/86box/vm-net-wd8003e/86box.cfg
targets/ibm_pc_5150/86box/vm-net-wd8003eb/86box.cfg
```

Current CGA machine shape:

```text
Machine: IBM PC 5150
CPU:     8088, 4.77 MHz
RAM:     16 KiB
Video:   CGA
FDC:     XT floppy controller
Floppy:  5.25" single-sided drive as A:
Disk A:  build/ibm_pc_5150/floppy-160k.img
```

The original-speed 4.77 MHz, 16 KiB profiles are the
compatibility gate through the ROM BASIC sidecar bootstrap. The normal BIOS
boot path remains part of the same floppy for 32 KiB and larger machines, while
the tracked emulator profiles exercise the sub-32 KiB entry path. Literal
24 KiB IBM PC profiles in 86Box stop in POST with a memory-size error before
ROM BASIC. Faster ad hoc profiles are not part of the normal workflow.

The 86Box NIC inventory for this target is tracked in:

```text
targets/ibm_pc_5150/86box/NICS.md
```

Expected first screen:

```text
boot loader     no marker
hardware setup  dim "." for CORE.SYS display baseline, hardware detection, and adapter initialization
internet prep   dim "," for network configuration and plain reachability
secure prep     dim "o" for selected endpoint setup and TLS protocol proof
crypto prep     normal "o" on CGA/VGA, dim "o" on MDA, for ECDHE/key setup
agent/env prep  bright "o" for API validation, model, reasoning, session, and environment setup
no card         current marker turns red, low descending PC speaker tone, fast-typed no network card, then retry/restart
question        phase-colored blinking marker, low PC speaker attention tone, bright fast-typed prompt ending with ?
agent question  agent? with AGENTS.CFG entries or built-in big-three fallback when USER.CFG has no valid agent choice
field question  server? and/or key? with cursor shown only while typing; Up/Down moves field focus
success         dim "." -> dim "," -> dim "o" -> normal "o" -> bright "o" -> the seed build splash
```

The splash is only the ready handoff animation. No setup work happens during
the splash.

Seed auto-detects the current 86Box shared-base adapters with
station-address PROM probes before asking. If those probes are invalid or
ambiguous, the fallback `adapter?` prompt appears in bright text. Menu
selection still uses color: the selected adapter is bright and the inactive
adapter is dim; Up and Down toggle the selected row, and Enter accepts it.

Seed does not switch video modes in this target. It reads the active BIOS text
column count and uses that for screen clearing and centering, so 40-column and
80-column text modes share the same path.

The broader text UI rule is documented in:

```text
docs/ui.md
```

The boot core runtime handoff block is documented in:

```text
targets/ibm_pc_5150/HANDOFF.md
```

Default CGA colors:

```text
seed       white
build      dark gray
loading    dark gray
crypto     light gray
ready      white
question   white
error      red
menu       selected white, inactive dark gray
```

The floppy is a minimal FAT12 filesystem. Sector 1 is the boot sector with a
FAT12 BPB. Sectors 2-5 are the fixed reserved-sector loader, sectors 6-7 are
FAT copies, sectors 8-11 are the root directory, and sector 12 onward contains
file data starting with `CORE.SYS`.

This launcher builds the floppy and starts a VM profile:

```sh
tools/run-86box.sh
tools/run-86box.sh vm-net-ne2k8
```

Without an argument it starts `vm`. 86Box 5.x starts specific machines with
`--vmpath`; the launcher also passes the generated floppy image as drive `A:`.

The original IBM PC target has no built-in floppy controller in 86Box, so the
VM config must explicitly use:

```ini
[Storage controllers]
fdc = fdc_xt
```

The Seed floppy now has a FAT12 BIOS Parameter Block. Some 86Box profiles still
keep BPB checking disabled so older boot-layout experiments remain easy to
compare:

```ini
[Floppy and CD-ROM drives]
fdd_01_type = 525_1dd
fdd_01_check_bpb = 0
```

Build 5 was boot-tested on 86Box 5.3 build 8200 on 26 April 2026 with the CGA
no-card, `vm-net-3c501`, `vm-net-3c503`, `vm-net-ne1k`, `vm-net-ne2k8`,
`vm-net-novell-ne1k`, `vm-net-wd8003e`, and `vm-net-wd8003eb` configs. The
no-card screen showed:

```text
. no network card
retry
restart
```

The `.` marker is rendered in the error color. On MDA, the error is expected to render bright because monochrome adapters do
not have red. The no-card path also plays the low failure tone through the PC
speaker using the PIT rather than the BIOS bell. Retry returns to the hardware
setup phase without rereading floppy sectors; restart performs a warm machine restart.
`vm-net-ne1k`, `vm-net-ne2k8`, and `vm-net-novell-ne1k` showed the adapter
prompt when needed, accepted their NE family, initialized packet hardware,
checked the receive-ring read path, sent DHCPDISCOVER, and performed a bounded
filtered DHCPOFFER wait. When an offer was available, Seed sent DHCPREQUEST and
performed a bounded DHCPACK wait before sending ARP for the DHCP-provided DNS
server, resolving the `NET.CFG` probe host, selecting and ARPing the TCP next
hop, and receiving a TCP SYN-ACK from port 80. All three outbound-gated NE paths
advanced to `seed build 5`. `vm-net-3c501`, `vm-net-3c503`, `vm-net-wd8003e`,
and `vm-net-wd8003eb` preserved the non-NE handoff path, read their MACs, and
advanced to `seed build 5`.

Build 6 started on 26 April 2026. `vm-net-3c503` reached `agent?`, accepted
`openai`, wrote `USER.CFG`, and then reached `seed build 6`. Relaunching 86Box
directly against the already-written image skipped `agent?` and reached
`seed build 6`. `vm-net-ne2k8` preserved the full outbound path before reaching
`seed build 6` in the earlier Build 6 filesystem checkpoint.

On 27 April 2026, the current Build 6 internet-proof checkpoint was retested
with `USER.CFG` excluded from the test floppy. `vm-net-3c501`,
`vm-net-3c503`, `vm-net-ne1k`, `vm-net-ne2k8`, `vm-net-novell-ne1k`,
`vm-net-wd8003e`, and `vm-net-wd8003eb` all reached `agent?` after
DHCPDISCOVER/OFFER, DHCPREQUEST/ACK, DNS ARP/query, next-hop ARP, and TCP
SYN-ACK.

On 30 April 2026, `vm-net-ne2k8` reached `seed build 6` after completing the
current direct OpenAI TLS 1.2 path through encrypted server Finished
verification. The current TLS compatibility path is P-256
ECDHE-ECDSA-CHACHA20-POLY1305 without extended master secret.
On 1 May 2026, original-speed 4.77 MHz `vm-net-ne2k8` completed the direct
OpenAI Responses request/response proof and displayed the returned `ok`.
On 4 May 2026, the 64 KiB baseline was retested before memory-slimming work:
`vm-net-3c503`, `vm-net-ne1k`, `vm-net-ne2k8`, `vm-net-novell-ne1k`,
`vm-net-wd8003e`, and `vm-net-wd8003eb` reached `seed build 6` and displayed
`ok`; `vm-net-3c501` failed at agent setup and was carried as the open
valid-profile failure for the next slimming pass. On 7 May 2026, after the
32 KiB stack and resident-image reductions, that failure was repaired and
representative family profiles
`vm-net-ne2k8`, `vm-net-3c501`, `vm-net-3c503`, and `vm-net-wd8003e` all
completed the direct OpenAI Responses request/response proof, displayed the
returned `ok`, and reached `seed build 6`. Retest individual profiles when
changing TLS timing or shared packet code.

The 16 KiB path uses `tools/run-basic-bootstrap-86box.py`
to force ROM BASIC entry and inject the generated sidecar helper while
`make inspect` enforces the 16 KiB packed-memory layout. Before the compact
helper release, that path
reached returned `ok` on `vm-net-ne2k8`, `vm-net-3c501`, `vm-net-3c503`, and
`vm-net-wd8003e`. The released short hex `DATA` helper was then smoke-tested
through returned `ok` on `vm-net-ne2k8`.

The WD8003 profiles use `ram_addr = D0000` and `ram_size = 8192`; 86Box expects
the shared-memory address as a five-digit physical address and the EB RAM size
in bytes.

The current Build 6 checkpoint also asks missing selected-agent fields as
`server?` and `key?`. When both are required, they share one panel and Up/Down
moves focus between them. Text fields render plain typed characters and keep
long values on one row by showing the visible tail inside the field area. With
valid saved `USER.CFG`, `vm-net-ne2k8` was also tested on 27 April 2026 through
selected-agent DNS resolution and TCP 443 SYN-ACK reachability before reaching
`seed build 6`. If `AGENTS.CFG` is missing or invalid, the agent menu falls
back to built-in `openai`, `anthropic`, and `google`.

On 29 April 2026, `vm-net-ne2k8` reached `seed build 6` after deriving the
TLS master secret and ChaCha20-Poly1305 client/server write keys and IVs from
the ECDHE pre-master secret.

On 28 April 2026, the boot layout was split into a reserved FAT12 loader plus
root `CORE.SYS`. The no-card `vm` profile reached the red `"."` failure state,
and `vm-net-3c501` reached `seed build 6` from the file-backed runtime.
