# IBM PC 5150 Target

This target is the first Seed discipline target: an original IBM PC-class boot
path, starting from a 160 KiB 5.25-inch single-sided floppy image.

Current boot flow:

```text
BIOS loads boot sector
  -> boot sector loads the fixed reserved-sector FAT12 loader
  -> loader reads SEED.SYS from the FAT12 root directory
  -> SEED.SYS reads the current BIOS text-mode column count
  -> SEED.SYS clears text mode
  -> shows a dim . marker for hardware setup
  -> probes common ISA network card I/O bases
  -> records the responding NIC I/O base if one is found
  -> publishes boot, video, and NIC state to the handoff block at 0000:0600
  -> draws the seed build splash and CPU-class warning
  -> turns the . marker red and plays a low failure tone if no card responds
  -> offers retry/restart after a critical failure; retry returns to hardware setup
  -> probes station-address PROMs when the responding I/O base is ambiguous
  -> asks for adapter family only if the probes remain ambiguous
  -> records the current 86Box profile IRQ after adapter family resolution
  -> reads station-address PROMs into handoff when valid
  -> scans SEED/DRIVERS/*.DRV for a suitable driver
  -> loads one suitable driver, or asks which driver if multiple drivers suit
  -> fails as driver setup failed with retry/restart if no suitable driver is present
  -> initializes packet hardware through the active driver
  -> reads one pending receive-ring frame when available
  -> switches to a dim , marker for internet prep
  -> sends one NE1000/NE2000-family DHCPDISCOVER
  -> performs a two-pass filtered DHCPOFFER wait and parses it when available
  -> sends DHCPREQUEST and waits for DHCPACK when an offer is available
  -> sends ARP for the DHCP-provided DNS server after DHCPACK
  -> selects the TCP next hop for the selected agent host
  -> switches to a dim o marker for secure connection prep
  -> reads SEED/AGENTS.CFG and parses up to five agent declarations
  -> falls back to built-in openai/anthropic/google if SEED/AGENTS.CFG is missing or bad
  -> reads SEED/USER.CFG when present and validates the saved agent choice
  -> asks agent? when the saved choice is missing or invalid
  -> asks server? and key? on one form when the selected agent needs both
  -> resolves the selected agent host and proves TCP 443 connection
  -> sends a TLS 1.2 ClientHello with SNI and P-256 ECDHE-ECDSA-CHACHA20-POLY1305 without extended master secret
  -> parses ServerHello plus Certificate header
  -> drains the Certificate handshake to the next handshake boundary
  -> parses ServerKeyExchange and range-checks the P-256 public point
  -> parses ServerHelloDone
  -> maintains a live SHA-256 TLS handshake transcript context through ServerHelloDone
  -> computes the baseline 8088 fixed-scalar premaster, or real ECDHE + pinned RSA cert auth on a 286+
  -> converts the Jacobian shared point into the affine X-coordinate pre-master secret
  -> derives TLS master secret and ChaCha20-Poly1305 traffic keys
  -> sends ClientKeyExchange, then ChangeCipherSpec + encrypted client Finished
  -> receives and verifies encrypted server Finished
  -> uses a normal o marker during local crypto/key setup
  -> switches to a bright o marker for agent and environment prep
  -> writes validated agent config back best-effort
  -> enters the Default Prompt Interface below the existing splash
  -> streams chat turns over the live TLS session
  -> captures native Responses function_call items
  -> runs read_mem/write_mem/exec/save_env/load_env locally and replays function_call_output
```

The floppy image is a minimal FAT12 filesystem with a stable reserved loader
and a visible file-backed runtime. On machines with at least 32 KiB of RAM,
the normal BIOS boot path starts at `0000:7c00` and reaches Seed
automatically. The FAT12 sector map (boot sector, reserved loader, FAT copies,
root directory, and the `SEED.SYS`-first data area) is documented once in
[../../docs/architecture.md](../../docs/architecture.md), "Boot Artifact".

`SEED.SYS` is shipped in the FAT12 root directory and contains the current Seed
runtime. Runtime-owned config and prompt files live under `SEED/`, the current
RSA leaf ships as `SEED/LEAF.DER` and may be refreshed after a verified
auto-recertification, and included NIC driver files live under `SEED/DRIVERS/`.
Normal runtime updates can replace `SEED.SYS` without rewriting the boot sector or
reserved loader; driver-only updates can replace the relevant `.DRV` file when the
driver ABI is unchanged.
The build includes all current NIC drivers by default, but `INCLUDE_NIC_DRIVERS=0`
or per-driver `INCLUDE_NIC_DRIVER_NE`, `INCLUDE_NIC_DRIVER_WD8003`,
`INCLUDE_NIC_DRIVER_3C503`, and `INCLUDE_NIC_DRIVER_3C501` switches can
intentionally produce a floppy without some or all drivers.

The reserved loader keeps its FAT buffer below the `SEED.SYS` load address and
uses a `0x8000` stack top for 32 KiB machines so core builds can be read
through the FAT12 cluster chain without overwriting loader state. `SEED.SYS`
also switches to a `0x8000` runtime stack after entry.

Machines below 32 KiB cannot enter through the BIOS boot sector because the PC
BIOS loads that sector at `0000:7c00`, above the installed RAM ceiling of a
24 KiB or 16 KiB machine. Those machines enter through ROM BASIC instead.
Cassette BASIC cannot read FAT files directly, so the BASIC helper is a typed
or pasted sidecar generated by the build, not a file packaged on the release
floppy:

```text
build/ibm_pc_5150/SEED24A.BAS   typed helper for a Seed floppy in drive A:
build/ibm_pc_5150/SEED24B.BAS   typed helper for a Seed floppy in drive B:
```

Those BASIC programs poke a tiny 8086 loader at `0x3a00`, use BIOS INT 13h to
read `SEED.SYS` from the same Seed floppy, and jump to `0000:1000`. `SEED.SYS`
stays first in the FAT data area so this helper can use the stable first-data
LBA while the normal boot loader continues to read `SEED.SYS` through FAT12. The
generated sidecar text stores the loader as short hexadecimal `DATA` rows and
decodes them with ROM BASIC's `VAL("&H...")` support. The current 16 KiB helper
uses `0x4000` as its RAM ceiling and fails with a single red `X` at the normal
loading-glyph position if `SEED.SYS` would collide with the BASIC loader or if
BIOS sector reads fail.

Future artifacts may also ship host-specific loaders that jump into `SEED.SYS`
from an already-running OS. DOS `.COM`, Windows, macOS/OSX, Linux, and other
common hosts are possible candidates, but this is a one-way takeover path, not
a normal program that returns cleanly to the host OS.

`SEED/AGENTS.CFG` is shipped from `config/AGENTS.CFG`.
When present and valid, it overrides the built-in `openai`, `anthropic`, and
`google` direct-vendor fallback. `SEED/USER.CFG` is optional ignored user-local
state and is included only when `config/USER.CFG` exists. The project-level policy is
documented in:

```text
docs/config.md
```

The Seed boot core is organized as source includes under:

```text
targets/ibm_pc_5150/boot/core/
```

`core.asm` includes those files in fixed order and NASM emits one flat `SEED.SYS`
runtime file. NIC drivers are the target's scoped runtime modules: the build
emits one-sector `.DRV` files into `SEED/DRIVERS/` when included, and the runtime
scans those files for ABI-compatible metadata matching the detected adapter
family. One suitable driver loads automatically, multiple suitable drivers are
shown as a boot-time choice, and no suitable driver fails through retry/restart.

Text UI behavior, including fast-typed errors, questions, menus, and modals, is
documented in:

```text
docs/ui.md
```

The boot core runtime handoff block is documented in:

```text
targets/ibm_pc_5150/HANDOFF.md
```

The boot core probes common
ISA Ethernet I/O bases, publishes boot/video/NIC state to the handoff
block, and resolves the adapter family. Known single-card bases continue
automatically. Shared bases are resolved by station-address PROM probes when
one family can be identified safely; `adapter?` remains a fallback question
when the probes are invalid or ambiguous. For 3c501, 3c503,
NE1000/NE2000-family, and WD8003-family cards, the boot core reads the
station-address PROM and marks the MAC valid only after rejecting multicast,
all-zero, and all-`ff` addresses. The boot core also records IRQ 3 for the
current 86Box IBM PC 5150 profiles once the adapter family is known; real IRQ
discovery is later scope.

The boot core initializes NE1000/NE2000-family packet hardware
after a valid MAC read, polls the receive-ring pointers, reads one pending
receive frame when available, sends a minimal DHCPDISCOVER, and performs a
two-pass bounded filtered DHCPOFFER wait. When a DHCPOFFER is observed, the boot core
records the offered IPv4 address, subnet mask, router, and DNS server in the
handoff block. It then sends DHCPREQUEST and performs a bounded DHCPACK wait to
mark the lease accepted. After DHCPACK, it sends an ARP request for the
DHCP-provided DNS server, selects a TCP next hop using the DHCP subnet/router
data, ARPs that next hop for the selected agent host, opens the selected
agent's TCP 443 target through the shared TCP connect path, and sends the final
ACK after a matching SYN-ACK.

The target runs the full internet path and agent prep from `SEED.SYS`
in a 16 KiB packed-memory layout, the smallest IBM PC 5150 configuration. The
boot core reads
`SEED/AGENTS.CFG`, parses up to five `agent ` declarations, reads `SEED/USER.CFG` when
present, validates a saved `agent <id>`, asks `agent?` when the saved choice is
missing or invalid, asks `server?` and `key?` on one form when the selected
agent needs both values, preserves saved model and reasoning values when
present, resolves the selected agent host, proves TCP 443 connection through
the same TCP connect path, and runs the full TLS 1.2 / application-data path
(ClientHello through encrypted application data), documented once in
[../../docs/architecture.md](../../docs/architecture.md), "Provider Timing
Model". It then runs the Default Prompt Interface chat loop over the established
session as TLS application data: an initial model greeting, prompt input, and
streamed model responses across multiple turns in one boot session. Native
Responses function calls provide memory read/write/execute plus environment
save/load; memory read/write calls are currently capped at 4 bytes while the
native tool loop is hardened. It writes the validated values back best-effort.
Missing or invalid `SEED/AGENTS.CFG` content falls back to
built-in `openai`, `anthropic`, and `google`; other agent setup failures still
fail in the bright `"o"` phase as `agent setup failed`.

The boot path does not switch video modes. It keeps the BIOS-provided text
mode, reads the active column count, and uses that value for clearing and for
the centered project-name anchor.

The first screen text is hardcoded in `SEED.SYS` for now:

```text
boot loader     no marker
hardware setup  dim "."
internet prep   dim ","
secure prep     dim "o"
crypto prep     normal "o" on CGA/VGA, dim "o" on MDA
agent/env prep  bright "o"
failure         current marker turns red, low descending PC speaker tone, fast-typed error, then retry/restart
question        phase-colored blinking marker, low PC speaker attention tone, bright fast-typed prompt ending with ?
agent question  agent? with AGENTS.CFG entries or built-in big-three fallback when USER.CFG has no valid agent choice
field question  server? and/or key? with cursor shown only while typing; Up/Down moves field focus
splash         seed build banner; red insecure warning on pre-286, hidden on 286+
success         dim "." -> dim "," -> dim "o" -> normal "o" -> bright "o" -> Default Prompt Interface
```

The splash is a boot banner drawn after display and CPU-class setup. Driver
loading, network negotiation, agent setup, and environment setup happen after
the splash.

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
build N    CGA dark gray / MDA normal
loading    CGA dark gray / MDA normal
crypto     CGA light gray / MDA normal
ready      CGA white / MDA bright
question   CGA white / MDA bright
error      CGA red / MDA bright
menu       selected white/bright, inactive dark gray/normal
```

Build:

```sh
make
make INCLUDE_NIC_DRIVERS=0   # package the floppy without NIC driver files
```

Output:

```text
build/ibm_pc_5150/floppy-160k.img
```

Inspect the generated FAT12 image:

```sh
make inspect
```
