# Testing

How to exercise the IBM PC 5150 runtime in 86Box. This is the knowledge a fresh
session needs to validate Seed without rediscovering it.

## Harness

`tools/run-basic-bootstrap-86box.py` drives 86Box headless: it builds the floppy,
launches a profile, waits for the Default Prompt Interface, types prompts, and
captures the screen. `tools/run-86box.sh <profile>` launches a profile
interactively (no typing) for manual poking.

Always `pkill -f 86Box` before launching - two windows break the auto-typing.

## Two boot modes

Seed boots two ways, and they exercise different memory sizes:

- **16 KiB, ROM BASIC sidecar** (`--entry basic`, the default). The floppy sits
  in drive B:, the machine powers into ROM BASIC, and the harness types a BASIC
  bootstrap that POKEs `SEED.SYS` into RAM and runs it. `ram_top` ends up
  `0x4000`; in the current Build 12 layout the reconnect-safe pool leaves a
  96 B conversation window and a 96 B arena. This is the
  compatibility gate.
- **>=32 KiB, direct floppy boot** (`--entry direct`). The floppy
  sits in drive A:, the BIOS boots it directly - no sidecar, no BASIC. `ram_top`
  is `0x8000`; the 32 KiB tier uses the extra low RAM for the cached normal-turn chat
  loop cache and tools-schema cache, leaving a 224 B seg-0 window and 224 B
  arena. This is the direct-boot / cache-path gate. Direct runs preserve the
  profile's checked-in `mem_size` unless `--ram-kib N` is passed explicitly.

`--entry direct` rewrites the profile cfg to put the floppy in A:. Without it a
stale cfg leaves the floppy in B: and the machine lands in ROM BASIC.

## Key flags

- `--profile <name>` - the 86Box profile (a NIC; see the matrix below).
- `--ram-kib N` - machine RAM override (sets `mem_size`). Omit it for direct
  profile gates so the profile's representative RAM tier is preserved. The
  ROM BASIC sidecar defaults to 16 KiB.
- `--entry basic|direct` - boot mode (above).
- `--post-dpi-text "..."` - one chat turn; repeatable, one per turn. Each is
  typed after the DPI is ready and gated on the screen oracle. This drives a
  multi-turn conversation.
- `--screen-oracle` - required with `--post-dpi-text`; gates turns on screen state.
- `--screenshot PATH` - save a final screenshot (then read it; see below).
- `--post-dpi-idle N` - idle N seconds before a turn to force the keep-alive to
  close, exercising a real reconnect.
- `--pcap PATH` / `--pcap-iface IFACE` - capture the wire to a pcap; see Wire
  capture below (the capture is host-wide, so seed must be isolated from it).

## Reading results

**The OCR is unreliable** - the status bar bleeds in, dim (`0x08`) text is
invisible, and digits get mangled (`7` -> `?`). **Read the screenshot image**
with the Read tool; do not trust the printed OCR transcription. The screen
oracle's success/failure verdict is reliable; its transcribed text is not.

## Wire capture (pcap)

`--pcap PATH` (optionally `--pcap-iface IFACE`, default `en0`) captures the wire
during a run. **Caveat:** 86Box's SLiRP NATs the VM out through the *host's* IP,
so the capture is the Mac's entire network (browser, Slack, ...), not just seed.
You must isolate seed's traffic - and SLiRP terminates the VM's TCP and opens its
own host socket, so the SYN options and source ports on the wire are the *host's*,
not seed's. Identify seed only by destination IP + its TLS handshake fingerprint,
never by source port.

1. **OpenAI's edge IP** - `dig +short api.openai.com` (Cloudflare, e.g.
   `162.159.140.245` / `172.66.0.243`); the harness also prints "HTTPS remotes:".
2. **Walk only seed's streams** - `python3 tools/tls-flow.py <pcap> 162.159`. The
   IP-substring arg drops the host noise; per connection it prints the client
   AppData record count/sizes, whether the server sent CCS+Finished (handshake
   accepted), retransmit counts, and a timestamped record timeline.
3. **seed's fingerprint** - multi-second gaps between handshake steps (the 8088
   grinding key-derivation: ~7 s ClientHello->ClientKeyExchange, ~7 s ->Finished).
   No real client stalls like that, so you can spot seed even unfiltered.
4. **"Did seed even dial out?"** - `tcpdump -nr <pcap> 'host <openai-ip>'`. Zero
   packets to OpenAI after an event means seed never opened a socket - a
   client-side bug, not a handshake or network failure. (This is exactly how the
   post-panic reconnect bug was caught: the reconnects produced no OpenAI
   connection at all, only the original request did.)

## Validation recipes

- **Both-sides recall** (the model remembers its own answers): turn 1 "invent a
  unique nonsense word, reply with only that word"; turn 2 "what word did you
  invent?". Recall of an un-derivable word proves the response entered the window.
- **Invisible compaction**: keep chatting on 16 KiB until `compacting context`
  appears (dim). Recall a fact from before it to prove the recap carried forward.
- **Big-window context flush** (needs `--entry direct` on `vm-net-ne2k8`): two ~230 B
  prompts so turn 2's window+prompt exceeds one ~440 B TLS record. Establish a
  passcode in turn 1, recall it in turn 2 - confirms the chunked send and the
  JSON-escaping of the (quoted) stored response.
- **Reconnect survival**: `--post-dpi-idle 20` before a turn forces a keep-alive
  close + reconnect; the turn should still answer.
- **Driver packaging**: `make inspect` should list `SEED/DRIVERS/*.DRV` in the
  generated FAT image by default. `make INCLUDE_NIC_DRIVERS=0 inspect` should
  build a valid image with no `SEED/DRIVERS/` directory; a NIC-present boot from
  that image should fail as `driver setup failed` and offer retry/restart.
  Individual-image trims use `INCLUDE_NIC_DRIVER_NE`,
  `INCLUDE_NIC_DRIVER_WD80X3`, `INCLUDE_NIC_DRIVER_3C503`, and
  `INCLUDE_NIC_DRIVER_3C501`.

## Build 12 Memory Tiers

The checked-in 86Box profiles are the representative matrix: failure paths,
NIC families, memory tiers, and the CPU classes implied by those tiers. Profile
generation remains for automation and exact hardware mixes that should not be
tracked combinatorially.

- **16 KiB 8088 sidecar**: `vm-net-ne2k8` with the default `--entry basic`.
- **32 KiB 8088 direct**: `vm-net-ne2k8 --entry direct`.
- **256 KiB 8088 far conventional**: `vm-net-ne2k8-xt --entry direct`.
- **256 KiB 8088 + 4 MiB EMS**: `vm-net-ems --entry direct`.
- **286 HMA/native extended**: tracked `vm-net-286` (`ami286`, 2048 KiB RAM)
  with the 360K image, or `python3 tools/run-286-86box.py --mem-kib 2048` for
  generated speed/RAM sweeps. This exposes 1 MiB above 1 MiB through BIOS
  `int 15h AH=88h/87h`.
- **386 unreal**: tracked `vm-net-386` (`adi386sx`/`i386sx`, 4096 KiB RAM), or
  `python3 tools/run-386-86box.py` for generated automation.
- **16-bit ISA NE/DP8390 cards**: `vm-net-ne2k`, `vm-net-novell-ne2k`,
  `vm-net-ne2kpnp`, and `vm-net-de220p` use the 386SX direct-boot shape with
  the 360K image. The PnP profiles first exercise ISA PnP resource activation,
  then reuse `NE.DRV`.
- **16-bit ISA WD/DP8390 cards**: `vm-net-wd8013ebt` uses the 386SX direct-boot
  shape with the 360K image.

The harness handles 86Box's first-run "moved or copied" network-identity dialog
itself during tests; no manual button press should be needed.

For intermittent "model did not respond" captures, start the rootless watcher
before the VM run:

```sh
python3 tools/watch-86box-session.py --profile vm-net-ne2k8 --duration 7200
```

It waits for matching 86Box processes, logs TCP socket state changes, warns when
more than one 86Box TCP/443 socket remains established, and captures periodic
plus socket-change screen/OCR snapshots under `build/ibm_pc_5150/watch/`. Add
`--pcap` only on hosts where `sudo -n tcpdump --version` works; packet capture
uses a bounded rotating ring by default (`--pcap-rotate-mb`,
`--pcap-rotate-files`). Otherwise packet capture is reported as unavailable and
the watcher continues with sockets and screens.

## NIC matrix

The compatibility gate is original-speed 4.77 MHz, 16 KiB `vm-net-ne2k8` via the
sidecar. The seven original-PC NIC profiles:

`vm-net-3c501`, `vm-net-3c503`, `vm-net-ne1k`, `vm-net-ne2k8`,
`vm-net-novell-ne1k`, `vm-net-wd8003e`, `vm-net-wd8003eb`.

Additional AT/386 NIC coverage profiles:

`vm-net-ne2k`, `vm-net-novell-ne2k`, `vm-net-ne2kpnp`, `vm-net-de220p`,
`vm-net-wd8013ebt`.

`vm` and `vm-mda` have no card (expect a clean red `.` failure). Retest
individual profiles when changing TLS timing or shared packet/NIC code.

## Gotchas

- The profile's `86box.cfg` is a **test artifact** the harness rewrites - never
  commit it.
- `config/USER.CFG` holds the API key - never print or commit it.
- A transient "agent setup failed" red screen is usually a network/TLS flake -
  re-run before investigating.
- A NIC-present boot that shows `driver setup failed` means hardware detection
  resolved an adapter family, but no included `.DRV` file matched that family
  and ABI.
- The test network can be intermittently spotty, and a network drop looks
  identical to a product bug. To tell them apart, run a background connectivity
  monitor during the test and correlate it against the failure point: `ping -i 2
  1.1.1.1` (general reachability) **plus** a probe to the *actual* endpoint
  (`curl`/`openssl s_client` to `api.openai.com:443` - ICMP to 1.1.1.1/8.8.8.8
  does not exercise the OpenAI path). Drops at the failure point => network;
  a clean ping straight through the failure => the product.
- A very long single reply can render for >20 min on the PC (render-rate, not
  network); the keep-alive holds the session. Force a long render with an essay
  prompt, not "count to N" (the Concise directive makes the model answer short).
