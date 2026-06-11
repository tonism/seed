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
  bootstrap that POKEs `CORE.SYS` into RAM and runs it. `ram_top` ends up
  ~`0x4000`, so the conversation window is ~480 B (arena ~480 B too). This is the
  compatibility gate.
- **>=32 KiB, direct floppy boot** (`--entry direct --ram-kib 32`). The floppy
  sits in drive A:, the BIOS boots it directly - no sidecar, no BASIC. `ram_top`
  is `0x8000`, so the window is large (~8 KB). This is the only way to reach the
  big-window code paths (the `append_context` multi-record send).

`--entry direct` rewrites the profile cfg to put the floppy in A:. Without it a
stale cfg leaves the floppy in B: and the machine lands in ROM BASIC.

## Key flags

- `--profile <name>` - the 86Box profile (a NIC; see the matrix below).
- `--ram-kib N` - machine RAM (sets `mem_size`); 16 (default) or 32 for direct.
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
- **Big-window context flush** (needs `--entry direct --ram-kib 32`): two ~230 B
  prompts so turn 2's window+prompt exceeds one ~440 B TLS record. Establish a
  passcode in turn 1, recall it in turn 2 - confirms the chunked send and the
  JSON-escaping of the (quoted) stored response.
- **Reconnect survival**: `--post-dpi-idle 20` before a turn forces a keep-alive
  close + reconnect; the turn should still answer.

## NIC matrix

The compatibility gate is original-speed 4.77 MHz, 16 KiB `vm-net-ne2k8` via the
sidecar. The seven NIC profiles:

`vm-net-3c501`, `vm-net-3c503`, `vm-net-ne1k`, `vm-net-ne2k8`,
`vm-net-novell-ne1k`, `vm-net-wd8003e`, `vm-net-wd8003eb`.

`vm` and `vm-mda` have no card (expect a clean red `.` failure). Retest
individual profiles when changing TLS timing or shared packet/NIC code.

## Gotchas

- The profile's `86box.cfg` is a **test artifact** the harness rewrites - never
  commit it.
- `config/USER.CFG` holds the API key - never print or commit it.
- A transient "agent setup failed" red screen is usually a network/TLS flake -
  re-run before investigating.
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
