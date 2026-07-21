# Memory Layout

This appendix records how Seed fits inside the 16 KiB IBM PC 5150 target at
important points during boot and the stage-by-stage fill-in below. The diagrams are generated from the
assembled `SEED.SYS` plus layout constants.

Refresh this file after memory-layout changes:

```sh
make memory-map
```

Each character represents 128 bytes. Each row is 4 KiB. Four rows cover the
16 KiB target.

Most of the story is in five bands — BIOS-owned memory, the resident nucleus, the
K crypto window, the conversation window, and the arena. The other symbols are
scratch/state detail you can skim on a first read.

```text
█  BIOS-owned low memory
▓  SEED.SYS resident nucleus
▒  K LINK window
h  handoff block
t  TLS / crypto state
w  wire / TCP / NIC state
r  TLS receive buffer
:  dormant reconnect-handshake scratch
a  agent config (and reconnect-safe caches)
c  crypto constants
m  conversation window (model-compacted context)
+  user/agent arena
,  currently loaded cold phase / phase-local scratch
   free RAM
|  stack guard region
```

## Stage 1 — Cold Boot

<!-- BEGIN MAP: stage-cold -->
```text
  ┌────────┬───────1───────2───────3───────4┐ KiB
  │ 0x0000 │██████████                      │
  │ 0x1000 │                                │
  │ 0x2000 │                                │
  │ 0x3000 │                                │
  └────────┴────────────────────────────────┘

Power-on. BIOS owns 0x0000..0x0500 (interrupt vectors plus the
BIOS data area). Everything else is RAM Seed will claim in
stages — currently all free.
```
<!-- END MAP: stage-cold -->

## Stage 2 — Nucleus Loaded

<!-- BEGIN MAP: stage-nucleus -->
```text
  ┌────────┬───────1───────2───────3───────4┐ KiB
  │ 0x0000 │██████████  h                   │
  │ 0x1000 │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                │
  │ 0x2000 │                                │
  │ 0x3000 │                              ||│
  └────────┴────────────────────────────────┘

SEED.SYS resident nucleus is at 0x1000..0x1800. The phase
loader, NIC TX/RX, TCP send/receive, and UI primitives live
here. main.inc has cleared the runtime scratch and stamped
boot_drive + ram_top into the handoff (the tiny 'h' cell).
```
<!-- END MAP: stage-nucleus -->

## Stage 3 — HAL Ready

<!-- BEGIN MAP: stage-hal -->
```text
  ┌────────┬───────1───────2───────3───────4┐ KiB
  │ 0x0000 │██████████  hw,,,,,,,,,,,,,,,,, │
  │ 0x1000 │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                │
  │ 0x2000 │                                │
  │ 0x3000 │                              ||│
  └────────┴────────────────────────────────┘

H (hardware_setup) + 2 (driver_load) + I (packet_io_init) have
run. Handoff now carries video mode, NIC family/base/IRQ, MAC;
the selected NIC driver is resident in the active-driver slot;
NIC TX/RX page tracking lives in low_runtime_state; UI cursor/
colour attrs sit in low_phase_state.
```
<!-- END MAP: stage-hal -->

## Stage 4 — Network Ready

<!-- BEGIN MAP: stage-net -->
```text
  ┌────────┬───────1───────2───────3───────4┐ KiB
  │ 0x0000 │██████████  hw,,,,,,,,,,,,,,,,, │
  │ 0x1000 │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                │
  │ 0x2000 │                                │
  │ 0x3000 │                              ||│
  └────────┴────────────────────────────────┘

D (dhcp_setup) + C (tcp_connect) have
run. Handoff also carries IP/router/DNS/subnet; the persistent
block has arp_target_mac and tcp_target_ip/seq/ack. Visual is
identical to the HAL stage — the new bytes populate the same
cells, just more densely inside them.
```
<!-- END MAP: stage-net -->

## Stage 5 — Agent Prep

<!-- BEGIN MAP: stage-agent-prep -->
```text
  ┌────────┬───────1───────2───────3───────4┐ KiB
  │ 0x0000 │██████████  hw,,,,,,,,,,,,,,,,, │
  │ 0x1000 │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                │
  │ 0x2000 │                                │
  │ 0x3000 │                  ttttaaaa    ||│
  └────────┴────────────────────────────────┘

A + U + Q + E + R have run. seed_* loaded from SEED/AGENTS.CFG /
SEED/USER.CFG, the HTTP POST built into api_request_plain. The K
LINK window is still on the floppy — its 7.5 KiB slot at
0x1800..0x3600 stands empty, the largest visible free band.
```
<!-- END MAP: stage-agent-prep -->

## Stage 6 — TLS / First Response

<!-- BEGIN MAP: stage-tls -->
```text
  ┌────────┬───────1───────2───────3───────4┐ KiB
  │ 0x0000 │██████████cchw,,,,,,,,,,,,,,,,cc│
  │ 0x1000 │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒│
  │ 0x2000 │▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒│
  │ 0x3000 │▒▒▒▒▒▒▒▒▒▒▒▒ttrrrrttttttaaaa++||│
  └────────┴────────────────────────────────┘

Densest moment. K LINK window loaded; persistent TLS state
derived; receive buffer holding the encrypted response; the rest
of pre-response scratch (hmac_prepared + tls_server_random /
master_secret / handshake_hash) filled by the handshake. The
context pool above critical scratch (caches a, arena +, window m)
is already reserved. Nothing is free here - 16 KiB at full pack.
```
<!-- END MAP: stage-tls -->

## Stage 7 — Chat Loop / Response Streaming

<!-- BEGIN MAP: stage-dpi -->
```text
  ┌────────┬───────1───────2───────3───────4┐ KiB
  │ 0x0000 │██████████cchw,,,,,,,,,,,,,,,,cc│
  │ 0x1000 │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒│
  │ 0x2000 │▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒│
  │ 0x3000 │▒▒▒▒▒▒▒▒▒▒▒▒ttrrrrr:::::aaaa++||│
  └────────┴────────────────────────────────┘

Chat loop after the first response. The K window, session keys, and
receive buffer (the streamed response) stay resident and serve every
turn. The ':' band is the TLS handshake scratch (HMAC pads, server
random, master secret, transcript hash): dormant once the session keys
exist, but reserved - a reconnect re-runs the handshake and reuses it,
and it sits below critical scratch (the reconnect-safe line), so it can
never be permanent pool. The context pool therefore lives ABOVE
that line - reconnect-safe caches, user/agent arena (+), and
conversation window (m) - so it survives an idle/walk-away reconnect. In
the current Build 12 native-tool layout the remaining 16 KiB pool is
192 B, split 50/50 by hardware_setup into a 96 B arena and a 96 B
window at the far end. The 32 KiB direct tier spends its extra low RAM on the
normal-turn loop cache and tools-schema cache, so its seg-0
arena/window are 224 B each; larger far-memory tiers keep the 50/50
policy until the context window reaches the 1 MiB cap.
```
<!-- END MAP: stage-dpi -->

## Profile Examples

The stage maps above are the byte-level 16 KiB floor. The examples below use the
flat addresses the model sees through the memory tools.
Ranges are half-open: `[start..end)`.

### Higher-Memory Range Visuals

Cluster maps of each memory tier, ScanDisk-style: each cell is a fixed span of
RAM, drawn to scale and filled by who owns it. Legend:

```text
█ low Seed RAM        C conversation context     A user/agent arena
H HMA                 F EMS page frame           X device / ROM (unusable)
░ real-mode gap / unpopulated
```

```text
256 KiB conventional   (cell 2 KiB · row 64 KiB)
  ┌──────────┬────────────────────────────────┐
  │ 0x000000 │████████████████████████████████│
  │ 0x010000 │AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA│
  │ 0x020000 │AAAAAAAAAAAAAAAACCCCCCCCCCCCCCCC│
  │ 0x030000 │CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC│
  └──────────┴────────────────────────────────┘

640 KiB conventional   (cell 8 KiB · row 256 KiB)
  ┌──────────┬────────────────────────────────┐
  │ 0x000000 │████████AAAAAAAAAAAAAAAAAAAAAAAA│
  │ 0x040000 │AAAAAAAAAAAACCCCCCCCCCCCCCCCCCCC│
  │ 0x080000 │CCCCCCCCCCCCCCCCXXXXXXXXXXXXXXXX│
  │ 0x0C0000 │XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX│
  └──────────┴────────────────────────────────┘

256 KiB conv + 4 MiB EMS (flat model view)   (cell 32 KiB · row 1 MiB)
  ┌──────────┬────────────────────────────────┐
  │ 0x000000 │██AAAAAA░░░░░░░░░░░░░░░░░░░░░░░░│
  │ 0x100000 │AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA│
  │ 0x200000 │AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA│
  │ 0x300000 │AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA│
  │ 0x400000 │CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC│
  └──────────┴────────────────────────────────┘

EMS physical view (where the page frame sits)   (cell 8 KiB · row 256 KiB)
  ┌──────────┬────────────────────────────────┐
  │ 0x000000 │████████AAAAAAAAAAAAAAAAAAAAAAAA│
  │ 0x040000 │AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA│
  │ 0x080000 │AAAAAAAAAAAAAAAAXXXXXXXXXXXXXXXX│
  │ 0x0C0000 │XXXXXXXXFFFFFFFFXXXXXXXXXXXXXXXX│
  └──────────┴────────────────────────────────┘

286, 640 KiB conv + 1 MiB native extended   (cell 16 KiB · row 512 KiB)
  ┌──────────┬────────────────────────────────┐
  │ 0x000000 │████AAAAAAAAAAAAAAAAAAAAAAAAAAAA│
  │ 0x080000 │AAAAAAAAXXXXXXXXXXXXXXXXXXXXXXXX│
  │ 0x100000 │HHHHAAAAAAAAAACCCCCCCCCCCCCCCCCC│
  │ 0x180000 │CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC│
  └──────────┴────────────────────────────────┘

386, 640 KiB conv + 3 MiB native extended   (cell 32 KiB · row 1 MiB)
  ┌──────────┬────────────────────────────────┐
  │ 0x000000 │██AAAAAAAAAAAAAAAAAAXXXXXXXXXXXX│
  │ 0x100000 │HHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA│
  │ 0x200000 │AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA│
  │ 0x300000 │CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC│
  └──────────┴────────────────────────────────┘
```

### 16 KiB ROM BASIC Sidecar

```text
0x00000000..0x00000500   BIOS IVT + BIOS data area
0x00000600..0x0000062E   Seed handoff block
0x00000700..0x00001000   cold phase / packet scratch window
0x00001000..0x00001800   resident nucleus
0x00001800..0x00003600   K crypto/TLS window when loaded
0x00003600..0x00003E40   TLS, reconnect, config, and tool state
0x00003E40..0x00003EA0   direct user/agent arena (96 B)
0x00003EA0..0x00003F00   conversation context window (96 B)
0x00003F00..0x00004000   stack guard
```

This is the headline floor. Native tools still work here, but memory read/write
calls are capped at 4 bytes and the tools schema streams from the floppy each
turn.

### 32 KiB Direct Boot

```text
0x00003E40..0x00003F20   direct user/agent arena (224 B)
0x00003F20..0x00004000   conversation context window (224 B)
0x00004000..0x00004200   resident tools-schema cache
0x00004200..0x00007A00   normal-turn loop cache / 286 secure overlay band
0x00007A00..0x00008000   stack guard
```

The low-memory arena/context pool is only modestly larger than the 16 KiB floor
because the extra RAM is buying a floppy-free normal chat turn: the K window,
normal-turn phases, identity prompt, and tools schema live in the high cache.

### 256 KiB Conventional 8088, No EMS

```text
0x00003E40..0x00004000   low direct arena/context mirror (arena before context)
0x00010000..0x00028000   direct far arena (96 KiB)
0x00028000..0x00040000   canonical far conversation context (96 KiB)
```

The far conventional region starts at `0x10000` and ends at the BIOS-reported
conventional top. With 256 KiB installed, the far region is `0x30000` bytes, so
Seed splits it 50/50: the direct arena gets the lower half (the executable base) and the far
context log gets the upper half. Tool status lines show real flat addresses, for
example `write to 0x00010000`.

### 640 KiB Conventional 8088, No EMS

```text
0x00010000..0x00058000   direct far arena (288 KiB)
0x00058000..0x000A0000   canonical far conversation context (288 KiB)
0x000A0000..0x00100000   video, adapter memory, option ROMs, BIOS ROM (not arena)
```

Seed does not advertise UMBs as arena. The upper-memory area belongs to devices
and ROMs, and write/read-back probing there can false-positive on device memory.

### 256 KiB Conventional + 4 MiB EMS

```text
0x00010000..0x00040000   direct conventional arena (192 KiB)
0x00100000..0x00400000   EMS windowed arena (3 MiB)
0x00400000..0x00500000   canonical conversation context (1 MiB cap)
0x000D0000..0x000E0000   physical EMS page frame used as the 64 KiB bank window
```

EMS uses a synthetic flat range above the real-mode 1 MiB ceiling. The model
addresses `0x00100000` and above; Seed maps those requests through the EMS page
frame. If a request address and physical target differ, status shows both, for
example `write to 0x00100020 -> 0x000D0020`.

### 286, 640 KiB Conventional + 1 MiB Native Extended

```text
0x00010000..0x000A0000   direct conventional arena (576 KiB)
0x00100000..0x0010FFF0   HMA direct range (almost 64 KiB)
0x00110000..0x00138000   native extended arena below context (160 KiB)
0x00138000..0x00200000   canonical conversation context (800 KiB)
```

A20 makes HMA a separate direct range above the upper-memory hole. Native
extended memory above HMA is reached through BIOS `int 15h AH=87h` block moves,
so it is slower than conventional/HMA memory and is treated as a copied/windowed
backend for tool access.

### 386, 640 KiB Conventional + 3 MiB Native Extended

```text
0x00010000..0x000A0000   direct conventional arena (576 KiB)
0x00100000..0x0010FFF0   HMA direct range
0x00110000..0x00300000   high arena below context
0x00300000..0x00400000   canonical conversation context (1 MiB cap)
```

Unreal mode keeps BIOS-compatible real mode but refreshes segment limits so
Seed can directly read and write flat high-memory addresses. The context window
stays capped at 1 MiB; surplus high memory belongs to the arena.

## ENV.DAT Snapshot Format

Persistence (see [`architecture.md`](architecture.md), "Persistence") saves the contiguous user region and the
screen to `ENV.DAT` on the boot drive. The file is a header plus two payload
sections: the arena+window region for the model, and the screen snapshot for the
user. The context cap tells restore where the context suffix begins:

```text
offset  size  field
0x00    4     magic "SEDV"
0x04    1     format_version         (the compatibility axis)
0x05    1     flags                  (reserved)
0x06    2     build_number           (provenance, informational)
0x08    2     ram_top at save time   (hint for the warning text)
0x0a    2     chat_context_len_var   (context cap at the end of the region)
0x0c    2     chat_context_used      (valid conversation bytes)
0x0e    2     note_len               (compacted-memory prefix length)
0x10    2     region_len             (arena+window bytes from chat_pool_start)
0x12    2     region_stored          (trimmed region bytes, <= region_len)
0x14    1     screen_cols            (snapshot width; 0 = no snapshot)
0x15    1     screen_rows            (snapshot height)
0x16    2     screen_stored          (row-trimmed encoded screen bytes)
0x18    2     payload checksum       (16-bit sum of stored payload bytes)
0x1a    2     header checksum        (16-bit sum of bytes 0x00..0x1a)
0x1c    ..    payload: [region_stored arena+window bytes]
              [screen_stored encoded-screen bytes]
```

The full region is conceptually `[arena][context]`, where
`arena_len = region_len - chat_context_len_var`. The stored prefix is trimmed
only at the end, so a non-empty context preserves its offset even when the arena
prefix is all zero. On restore Seed clears the current full region, copies the
saved arena prefix to `chat_pool_start`, and copies the saved context suffix to
the far end of the current pool. That keeps larger machines' extra room in the
arena while preserving the saved conversation.

The snapshot cells are row-major char+attr, exactly as in CGA/MDA text memory,
encoded with per-row trailing blanks removed, and painted back to the video
segment verbatim on restore. Compatibility hinges on `format_version`, not
`build_number`: Seed carries a `min_supported_format` and a `current_format` and
accepts a file when `min <= format_version <= current`. `layout.inc` mirrors
these offsets in assembly, and `tools/env-dat.py` is the byte-for-byte reference
for offline creation and inspection.
