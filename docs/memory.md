# Memory Layout

This appendix records how Seed fits inside the 16 KiB IBM PC 5150 target at
important points during boot and hydration. The diagrams are generated from the
assembled `CORE.SYS` plus layout constants, not by hand.

Refresh this file after memory-layout changes:

```sh
make memory-map
```

Each character represents 128 bytes. Each row is 4 KiB. Four rows cover the
16 KiB target.

```text
█  BIOS-owned low memory
▓  CORE.SYS resident nucleus
▒  K LINK window
h  handoff block
t  TLS / crypto state
w  wire / TCP / NIC state
r  TLS receive buffer
:  handshake scratch, reserved for the reconnect handshake (dormant in chat)
a  agent config (and reconnect-safe caches)
c  crypto constants
m  conversation window (model-compacted context, Build 9)
+  user/agent arena (Build 9)
,  currently loaded cold phase / phase-local scratch
   free RAM
|  stack guard region
```

The cleanup/defrag/ocean architecture is intentionally not part of the current
rebuild. If that work returns later, this appendix should show it as a
new stage generated from the live cleanup table.

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

CORE.SYS resident nucleus is at 0x1000..0x1800. The phase
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

H (hardware_setup) + I (packet_io_init) have run. Handoff
now carries video mode, NIC family/base/IRQ, MAC; NIC TX/RX
page tracking lives in low_runtime_state; UI cursor/colour
attrs sit in low_phase_state.
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

D (dhcp_setup) + P (net_probe_cfg) + C (tcp_connect) have
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
  │ 0x3000 │                    tttttaaa  ||│
  └────────┴────────────────────────────────┘

A + U + Q + E + R have run. seed_* loaded from AGENTS.CFG /
USER.CFG, the HTTP POST built into api_request_plain. The K
LINK window is still on the floppy — its 7.0 KiB slot at
0x1800..0x3400 stands empty, the largest visible free band.
```
<!-- END MAP: stage-agent-prep -->

## Stage 6 — TLS / First Response

<!-- BEGIN MAP: stage-tls -->
```text
  ┌────────┬───────1───────2───────3───────4┐ KiB
  │ 0x0000 │██████████cchw,,,,,,,,,,,,,,,,cc│
  │ 0x1000 │▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒│
  │ 0x2000 │▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒│
  │ 0x3000 │▒▒▒▒▒▒▒▒ttrrrrrrrrrrttttttaam+||│
  └────────┴────────────────────────────────┘

Densest moment. K LINK window loaded; persistent TLS state
derived; receive buffer holding the encrypted response; the rest
of pre-response scratch (hmac_prepared + tls_server_random /
master_secret / handshake_hash) filled by the handshake. The
context pool above critical scratch (caches a, window m, arena +)
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
  │ 0x3000 │▒▒▒▒▒▒▒▒ttrrrrrrrrrrr:::::aam+||│
  └────────┴────────────────────────────────┘

Chat loop after the first response. The K window, session keys, and
receive buffer (the streamed response) stay resident and serve every
turn. The ':' band is the TLS handshake scratch (HMAC pads, server
random, master secret, transcript hash): dormant once the session keys
exist, but reserved - a reconnect re-runs the handshake and reuses it,
and it sits below critical scratch (the reconnect-safe line), so it can
never be permanent pool. The Build 9 context pool therefore lives ABOVE
that line - reconnect-safe caches + keepalive (a), conversation window
(m), user/agent arena (+) - so it survives an idle/walk-away reconnect.
The pool is small here only because the reconnect-safe gap to the stack
is ~214 B on 16 KiB (split ~107/107 window/arena); it scales with RAM, so
larger machines get a far bigger window and arena. (Consolidating the dormant
scratch into the pool would need a memory defrag; Build 10 investigated it and
the TLS-buffer lever and found no safe win - the scratch is reconnect-reserved,
and the buffer must stay MSS-sized because Cloudflare ignores client record-size
caps on TLS 1.2. The pool stays at the RAM-scaling levels. See builds.md Build 10.)
```
<!-- END MAP: stage-dpi -->
