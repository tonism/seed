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
  `0x4000`; in the current layout the reconnect-safe pool leaves a
  96 B conversation window and a 96 B arena. This is the
  compatibility gate. The loader also replaces ROM BASIC's live INT 1Ch timer
  callback with the permanent resident `IRET` at `0000:15ff` before Seed
  reclaims BASIC workspace.
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
2. **Walk only Seed's streams** - use `tcpdump -tttt -nr <pcap>` with the
   resolved destination IP, then feed the candidate flow to the current TLS
   1.3 product/PoC pcap parser for the route under test. The older
   `tools/tls-flow.py` CCS/Finished summary was written for TLS 1.2 and is not
   an acceptance oracle for the replacement path.

   ```sh
   # 8088 bounded Seed route
   python3 tools/crypto-bench/tls13-poc/live_k15_pcap.py capture.pcap \
     --server-ip 162.159.140.245 --expect reconnect

   # 286 conforming route
   python3 tools/crypto-bench/tls13-product/live_286_pcap.py capture.pcap \
     --server-ip 162.159.140.245 --expect reconnect
   ```

   The analyzers enforce different ClientHello profiles. In particular, the
   conforming 286 route deliberately omits `compress_certificate`; do not use
   the 8088 analyzer for its capture.
3. **Seed's TLS 1.3 fingerprint** - a large hybrid ClientHello followed by
   multi-second 8088 compute gaps, client Finished near the observed provider
   deadline, and a fixed credential-free HEAD before any credentialed OpenAI
   request on the 8088 profile. Both fresh and resumed connections send the
   HEAD after client Finished; the resumed ClientHello must not offer
   `early_data`. Do not apply the old ClientKeyExchange/CCS timing
   interpretation.
4. **"Did seed even dial out?"** - `tcpdump -nr <pcap> 'host <openai-ip>'`. Zero
   packets to OpenAI after an event means seed never opened a socket - a
   client-side bug, not a handshake or network failure. (This is exactly how the
   post-panic reconnect bug was caught: the reconnects produced no OpenAI
   connection at all, only the original request did.)

## TLS 1.3 acceptance gates

The TLS 1.3 source is integrated. The RAM-only 8088 route passes its offline
structure, composition, hostile-input, exact-floor live, seven-NIC, and CGA/MDA
display gates. The conforming 286 route passes its current exact-floor live
reconnect gate. Offline gates never replace a live pcap, and emulator timing
receives no physical entropy credit.

Run the product-level offline gates:

```sh
make
python3 tools/check-tls13-existing-read-sampler.py
python3 tools/check-secure-warm-restart.py
python3 tools/crypto-bench/tls13-poc/existing_read_entropy_check.py
python3 tools/crypto-bench/tls13-poc/system_ram_hello_check.py
python3 tools/crypto-bench/tls13-poc/system_ram_resumed_hello_check.py
python3 tools/crypto-bench/tls13-poc/system_ram_candidate_check.py
python3 tools/crypto-bench/tls13-poc/system_ram_fo_check.py
python3 tools/crypto-bench/tls13-poc/system_ram_auth_check.py
python3 tools/crypto-bench/tls13-poc/check_tls13_sym_system_ram.py
python3 tools/crypto-bench/tls13-poc/check_tls13_sym_system_ram_resumption.py
```

`make` builds and executes the exact RAM-only product-pack composition gate,
core dispatch/config/application guards, reconnect/replay, 286 module and
controller KATs, product-tail hostile matrix, FAT budget, and final image
binding. The component commands above keep the individual 8088 ABI boundaries
easy to rerun while debugging. The integration gate explicitly proves that
video RAM, adapter RAM, config, and arena/context are unchanged.

The 286 product directory contains the module/controller KATs. Its aggregate
serialized exact-floor timing gate is:

```sh
python3 tools/crypto-bench/tls13-product/run_286_tls13_serialized_gate.py
```

That result is deliberately not a live-product pass. It sums individually
tick-aligned target operations. The matrix is 4,608 bytes / nine A^T
polynomials and removes 27 matrix SHAKE128 permutations from live
decapsulation. The v4 report measures post-connect HELLO TX/RX wrappers and
protected-flight controllers, but still excludes named resident
connect/load/NIC work and complete offline authentication timing. Do not carry
old report numbers into release documentation: rerun the serialized gate and
the live activity measurements from the release-bound image. Run the
cache/controller hostile gates alongside the timing model:

```sh
python3 tools/crypto-bench/tls13-product/check_mlkem_product_modules.py
python3 tools/crypto-bench/tls13-product/check_286_hello_controller.py
python3 tools/crypto-bench/tls13-product/check_286_flight.py
```

Those gates must prove the 12-sector symmetric image is read before TCP,
published status-last, consumed once, relocated, and CRC-checked; the
early-derived value has a complete bytewise complement and is consumed/wiped;
and the public matrix is generated before TCP and consumed once by full cached
FO after ServerHello. Missing/torn/reversed/stale cache status must abort before
client Finished or application publication. Matrix payload corruption must
take the full implicit-rejection path and then fail server Finished, never
becoming a candidate-only shortcut.

The final 286 gate is a 6 MHz, 512 KiB pcap
showing a provisional hybrid acquisition, verified protected flight, client
Finished plus the immutable credential-free HEAD, authenticated HTTP and
NewSessionTicket capture, offline full FO/X.509/hostname/UTC/WE1/CV
authentication, and a final no-0RTT PSK-DHE resumption. The final connection
must use independent ML-KEM/X25519 keys, a correct binder,
`selected_identity=0`, the three pre-TCP cache lifecycles, full FO after
ServerHello, and only EncryptedExtensions-to-Finished before client Finished
and credential publication. It must then show authenticated OpenAI application
data, reuse, and one bounded reconnect.

The exact-floor harness may bypass the unusually slow AMI286 POST count, but
only after a loader-safe 90-second count window. This avoids aborting at the
first roughly 96-KiB display step, which is below the current `SEED.SYS`
direct-load span. Use `--platform-rtc-utc` to configure the emulator's platform
clock; Seed asks no RTC question and the harness injects no clock answer. The
harness also recognizes and resumes an emulator window launched at `0 Hz` so
focus-loss auto-pause cannot masquerade as target latency.

The current read-only exact-floor reconnect capture has the required ordered
`acquisition -> resumption -> acquisition -> resumption` topology. Its four
ServerHello-to-client-Finished intervals are 8.8880, 8.6428, 8.9518, and
8.6425 seconds, and the target renders the authenticated `FORTYTWO` response
before returning to DPI. The corresponding CPU/RAM, time, entropy,
certificate/CV, Finished, FO/cache, pack, and abort rejection gates pass.
Physical RTC/PIT characterization remains separate.

The 8088 final gate is 4.77 MHz, exactly 16 KiB, ROM BASIC entry, read-only
media, with fresh Finished inside the deadline, authenticated fresh HEAD and
ticket completion, full FO and dated exact-leaf/CV proof, a no-0RTT resumed
flow with authenticated post-Finished HEAD liveness, status-last credential
unlock, returned OpenAI text, reuse, and bounded reconnect. A close before
fresh liveness/ticket completion, late Finished, resumed early data, or a
credentialed provisional record must fail. Repeat both CGA and MDA display
profiles and all seven
original-speed ISA NIC profiles. The display must remain an ordinary Seed
screen throughout; dense binary/random glyphs indicate unintended memory
corruption and fail the run. The executable RAM-only gate must also retain its
unchanged video/adapter/config/arena guards, including the exact 32 KiB
success/abort restoration trampoline.

The current RAM-only 8088 architecture passes the exact ordered
`fresh -> resumed -> fresh -> resumed` capture on all seven original-speed
profiles. Values are ServerHello-to-client-Finished seconds; every interval has
a 15-second budget.

| Profile | Fresh 1 | Resumed 1 | Fresh 2 | Resumed 2 |
| --- | ---: | ---: | ---: | ---: |
| `vm-net-3c501` | 12.977 | 6.487 | 12.774 | 6.433 |
| `vm-net-3c503` | 13.790 | 7.017 | 13.600 | 7.010 |
| `vm-net-ne1k` | 13.470 | 6.938 | 13.470 | 6.991 |
| `vm-net-ne2k8` | 13.471 | 6.961 | 13.296 | 6.938 |
| `vm-net-novell-ne1k` | 13.468 | 6.984 | 13.461 | 6.945 |
| `vm-net-wd8003e` | 13.614 | 6.950 | 13.616 | 6.993 |
| `vm-net-wd8003eb` | 13.616 | 6.847 | 13.612 | 7.005 |

Each capture observes the credential-free HEAD, bounded one-reconnect policy,
authenticated OpenAI text, and a clean DPI return. The NIC-present MDA display
case passes the same four-flow gate at 13.4648, 6.9930, 13.5233, and 6.9963
seconds; CGA is covered by the seven-profile matrix. Current no-card CGA/MDA and
isolated no-driver images reach the documented retry/restart menus.

`make basic-bootstrap` statically gates the ROM BASIC boundary. It requires the
resident `IRET` byte, the atomic INT 1Ch vector sequence in both A: and B:
loader binaries, interrupts remaining disabled through the `0000:1000`
handoff, and byte-exact reconstruction of each loader from its generated BASIC
DATA lines. This gate is necessary but does not replace the exact-floor VM run.

Emulator timing inputs receive zero entropy credit. The 8088 route still needs
representative physical traces of PIT phases attached to its already-required
floppy reads; the 286 route needs physical RTC-periodic/PIT traces.
Conservative min-entropy estimates and calibrated health tests remain separate
acceptance gates for both sources.

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
- **Reconnect survival**: use `--post-dpi-idle 500` for the current OpenAI gate;
  shorter waits can exercise ordinary keep-alive reuse instead of a stale
  channel. The turn may establish exactly one fresh route and must answer
  without duplicating the request. A forced second failure returns
  `reconnect failed`. Repeat with a tool continuation and after rendered text;
  neither may replay automatically.
- **Driver packaging**: `make inspect` should list `SEED/DRIVERS/*.DRV` in the
  generated FAT image by default. `make INCLUDE_NIC_DRIVERS=0 inspect` should
  build a valid image with no `SEED/DRIVERS/` directory; a NIC-present boot from
  that image should fail as `driver setup failed` and offer retry/restart.
  Individual-image trims use `INCLUDE_NIC_DRIVER_NE`,
  `INCLUDE_NIC_DRIVER_WD80X3`, `INCLUDE_NIC_DRIVER_3C503`,
  `INCLUDE_NIC_DRIVER_3C501`, `INCLUDE_NIC_DRIVER_PCNET`, and
  `INCLUDE_NIC_DRIVER_TULIP`, `INCLUDE_NIC_DRIVER_RTL8139`, and
  `INCLUDE_NIC_DRIVER_EPIC100`.

## Representative Profiles

The checked-in 86Box profiles are the representative matrix: failure paths,
NIC families, memory tiers, and the CPU classes implied by those tiers. Profile
generation remains for automation and exact hardware mixes that should not be
tracked combinatorially.

- **16 KiB 8088 sidecar**: `vm-net-ne2k8` with the default `--entry basic`.
- **32 KiB 8088 direct**: `vm-net-ne2k8 --entry direct`.
- **256 KiB 8088 far conventional**: `vm-net-ne2k8-xt --entry direct`.
- **256 KiB 8088 + 4 MiB EMS**: `vm-net-ems --entry direct`.
- **286 conforming floor**: use an exact 6 MHz 286 with 512 KiB conventional
  RAM for the TLS gate. Larger tracked `vm-net-286` profiles remain useful for
  HMA/native-extended regression, but do not prove the floor. The exact-floor
  harness recognizes and bypasses the AMI286 BIOS memory count with one Escape
  key; Seed still performs its own CPU/RAM and silent platform-clock admission.
- **386 unreal**: tracked `vm-net-386` (`adi386sx`/`i386sx`, 4096 KiB RAM), or
  `python3 tools/run-386-86box.py` for generated automation.
- **16-bit ISA NE/DP8390 cards**: `vm-net-ne2k`, `vm-net-novell-ne2k`,
  `vm-net-ne2kpnp`, and `vm-net-de220p` use the 386SX direct-boot shape with
  the 360K image. The PnP profiles first exercise ISA PnP resource activation,
  then reuse `NE.DRV`.
- **16-bit ISA WD/DP8390 cards**: `vm-net-wd8013ebt` uses the 386SX direct-boot
  shape with the 360K image.
- **16-bit ISA PCnet/LANCE cards**: `vm-net-pcnetisa`, `vm-net-pcnetracal`,
  and `vm-net-pcnetisaplus` use the 386SX direct-boot shape with the 360K image.
  `vm-net-pcnetisaplus` first exercises ISA PnP activation, then uses
  `PCNET.DRV`.
- **PCI NE/DP8390 cards**: `vm-net-ne2kpci` uses a PCI-capable 486 direct-boot
  shape with the 360K image. It first exercises PCI BIOS discovery for the
  RTL8029AS I/O BAR, then reuses `NE.DRV`.
- **PCI PCnet/LANCE cards**: `vm-net-pcnetpci` and `vm-net-pcnetfast` use the
  same PCI-capable 486 direct-boot shape with the 360K image. PCI BIOS
  discovery resolves the AMD PCnet I/O BAR, then reuses `PCNET.DRV`.
- **PCI Tulip cards**: `vm-net-dec21040`, `vm-net-dec21140`,
  `vm-net-dec21140vpc`, and `vm-net-dec21143` use the same PCI-capable 486
  direct-boot shape with the 360K image and the shared `TULIP.DRV` path.
- **Other PCI bus-master cards**: `vm-net-rtl8139` and `vm-net-epic100` use
  the same PCI-capable 486 direct-boot shape with the 360K image and dedicated
  `RTL8139.DRV` / `EPIC100.DRV` paths.
- **VLB PCnet/LANCE cards**: `vm-net-pcnetvlb` uses the CS4031 VLB direct-boot
  shape with the 360K image. Fixed-base I/O discovery finds the AMD PCnet-32,
  then reuses `PCNET.DRV`. The profile includes checked-in AMI setup NVR so
  BIOS POST does not stop for CMOS setup.
- **MCA cards**: `vm-net-ethernextmc`, `vm-net-wd8003eta`,
  `vm-net-wd8003ea`, and `vm-net-wd8013epa` use an IBM PS/2 Model 55SX direct
  boot shape with the 1.44M image. The profiles include configured PS/2 NVR so
  BIOS POST does not stop for 162/163 setup errors. Seed scans MCA POS IDs,
  configures the selected NIC, then loads `NE.DRV` or `WD80X3.DRV`.

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
`vm-net-wd8013ebt`, `vm-net-pcnetisa`, `vm-net-pcnetracal`, and
`vm-net-pcnetisaplus`.

Additional PCI coverage profiles:

`vm-net-ne2kpci`, `vm-net-pcnetpci`, `vm-net-pcnetfast`,
`vm-net-dec21040`, `vm-net-dec21140`, `vm-net-dec21140vpc`,
`vm-net-dec21143`, `vm-net-rtl8139`, and `vm-net-epic100`.

Additional VLB coverage profiles:

`vm-net-pcnetvlb`.

Additional MCA coverage profiles:

`vm-net-ethernextmc`, `vm-net-wd8003eta`, `vm-net-wd8003ea`, and
`vm-net-wd8013epa`.

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
- IBM PS/2 MCA profiles require configured NVR. A graphical `162`/`163`
  `OK -> IBM` screen means the profile needs reference-disk autoconfiguration
  before Seed can boot; the checked-in MCA profiles already include that NVR.
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
