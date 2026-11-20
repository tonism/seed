# IBM PC 5150 Target

This is Seed's active bare-metal target: one 160 KiB FAT12 floppy for machines
from a 4.77 MHz 8088 with 16 KiB through later x86 real-mode tiers.

The TLS 1.3 / HTTP/2 integration passes original-speed functional acceptance
on the 16 KiB, 32 KiB and 286/512 KiB paths and all seven ISA NIC profiles.
See [HTTP/2 acceptance](../../docs/http2.md#functional-acceptance) for evidence
and latency limits; physical entropy validation remains separate. External
NIC-driver behavior remains a stable regression surface.

## Artifact and entry

The image contains one self-selecting runtime and optional external drivers:

```text
floppy-160k.img
  SEED.SYS              first FAT data file; all CPU/TLS tiers
  SEED/AGENTS.CFG       shipped OpenAI declaration
  SEED/USER.CFG         optional plaintext local state
  SEED/{IDENTITY,COMPACT,TOOLS}
  SEED/DRIVERS/*.DRV    optional one-sector NIC drivers
```

TLS 1.3 does not package `SEED/LEAF.DER`. The 8088 exact-leaf object and 286
WE1 and YE2 issuer points are immutable `SEED.SYS` assets; certificates, tables,
tickets, keys, and attempt bundles are volatile RAM state.

There are two entries into the same four-sector resident nucleus:

```text
32 KiB and above
  BIOS loads 0000:7c00
  -> stage 1 reads the reserved FAT12 loader
  -> loader follows the SEED.SYS FAT chain
  -> reads only the declared resident prefix to 0000:1000
  -> publishes RAM top/drive and jumps to 0000:1000

16 KiB
  machine enters ROM BASIC
  -> generated SEED24A.BAS or SEED24B.BAS is pasted
  -> helper POKEs a loader at 0000:3a00
  -> BIOS INT 13h reads the same SEED.SYS resident prefix
  -> helper redirects INT 1Ch to the resident IRET at 0000:15ff
  -> publishes 0x4000 RAM top/drive and jumps to 0000:1000
```

The BASIC helpers are build sidecars, not files in the FAT root. Keeping
`SEED.SYS` first lets the normal FAT loader and the tiny BASIC loader share the
same runtime. A 16/24 KiB machine cannot use normal BIOS boot because
`0000:7c00` lies above installed RAM.

The INT 1Ch reassignment quarantines ROM BASIC's 18.2 Hz callback before Seed
reuses BASIC workspace. Both generated sidecars publish the vector atomically
with interrupts disabled; `make basic-bootstrap` verifies the resident target,
both loader sequences, and their encoded BASIC payloads. Direct boot never
changes INT 1Ch.

## Product flow

```text
entry
  -> preserve BIOS text mode; detect columns and CGA/MDA
  -> publish handoff at 0000:0600
  -> detect CPU and BIOS-reported memory
  -> show splash; 8088 profile adds a neutral-gray security note
  -> detect adapter and read its station address when valid
  -> scan SEED/DRIVERS/*.DRV and load one suitable driver
  -> initialize packet path
  -> DHCP, ARP, DNS, TCP 443 for api.openai.com
  -> load/validate OpenAI config and optional USER.CFG
  -> dispatch TLS 1.3 route from CPU/RAM capability
  -> send authenticated OpenAI request after route commit
  -> enter the Default Prompt Interface
  -> reuse the live session for chat and native tools
```

OpenAI at `api.openai.com` is the only current provider route. The config
parser may retain several bounded declarations for future compatibility, but
an alternate ID or endpoint cannot select another TLS path.

## TLS 1.3 routes

### 8088 floor

Admission: 4.77 MHz 8088-compatible CPU, exactly 16 KiB supported through the
ROM BASIC entry.

The route cold-loads a 130-sector K14 phase pack. It uses TLS 1.3,
ChaCha20-Poly1305, SHA-256, and a real target-generated ML-KEM-768
contribution, but fixes the X25519 coordinate to `u=9`. It is therefore an
effective ML-KEM-only Seed boundary, not a standards-conforming
`X25519MLKEM768` hybrid.

Before full FO and dated exact-leaf/CertificateVerify proof, Seed can complete
the TLS handshake, transmit only the compiled credential-free H2 preface/SETTINGS, and retain
one bounded tentative NewSessionTicket after authenticating the fresh SETTINGS/ACK. A close before either fresh result completes fails the attempt.
After offline proof, the same-boot no-0RTT resumed connection performs fresh
KEM work, sends the fixed H2 preface/SETTINGS after client Finished, and authenticates its
response before status-last route commit. The API key, prompt, context,
redirects, and business request remain unreachable throughout. The ticket is
volatile and survives neither restart nor failed proof.

The leaf's hostname/issuer/purpose/validity interval are image-generation
provenance. The 8088 has no trusted runtime clock, so image expiry is an
explicit operational limit and requires a refreshed trusted image.

The route is conventional-RAM-only. It scatters the 1,088-byte ML-KEM
ciphertext around live code/state, reshapes it between regenerated KeyGen and
full FO, and carries only compact status-last capsules across phase epochs.
The bounded post-handshake receiver reuses retired conventional-RAM ranges.
Exact executable composition gates guard config, arena/context, all display
apertures, and adapter RAM. No video RAM, NIC RAM, or writable floppy slot is
part of TLS storage. On the 32 KiB direct tier, the fixed low root frame's 28
aliased arena bytes are shadowed in the conventional stack guard and restored
on both success and abort, preserving the 224-byte arena and 224-byte context.

### 286 conforming floor

Admission requires both CPU 286+ and at least 512 KiB in the BIOS Data Area.
The lowest validation target is 6 MHz. The route reserves the top 64 KiB of
conventional RAM and leaves `0x10000..0x70000` at the 512 KiB floor; the
current split gives a 192 KiB executable arena and 192 KiB context.

The route implements fully standards-conforming TLS 1.3
`X25519MLKEM768`: real ML-KEM-768 and X25519, ChaCha20-Poly1305/SHA-256,
strict ordinary Certificate parsing, WE1 P-256/SHA-256 or YE2 P-384/SHA-384 issuer authentication, exact
OpenAI hostname/purpose/key-use/time policy, and P-256 CertificateVerify over
the acquisition transcript.

Acquisition verifies the protected flight and server Finished with a
provisional candidate, sends client Finished plus the immutable
credential-free H2 preface/SETTINGS, and authenticates peer SETTINGS/ACK and a tentative
NewSessionTicket. Offline full FO comparison and strict
issuer/hostname/UTC/CertificateVerify proof promote that volatile ticket. The
final no-0RTT PSK-DHE resumption consumes it, uses independent full hybrid
keys, a real binder, `selected_identity=0`, full decapsulation, and a strict
EncryptedExtensions-to-Finished flight. It sends the credential-free H2 preface/SETTINGS,
then requires a complete authenticated ticket and peer SETTINGS/ACK before
publishing credentials and the advanced application-record sequence; it waits for SETTINGS/ACK before publication. There is no
0-RTT, compressed certificate, persisted ticket, mutable leaf file, or no-time
bypass. A coherent BIOS RTC is consumed silently as the machine's configured
platform UTC clock; invalid, incoherent, or out-of-range values fail closed.

Before either live TCP connection, the route stages the immutable 12-sector
symmetric image in its high record quarantine. Before final TCP it also
computes the complemented ticket early-derived value and the 4,608-byte public
ML-KEM A^T matrix. The caches publish status-last and are consumed once; the
symmetric copy is relocated and CRC-checked, the early-derived value is wiped
after import, and the matrix feeds complete full FO after ServerHello. Full
ciphertext comparison and implicit rejection still precede server Finished,
client Finished, and credential publication.

At the 6 MHz floor, matrix generation measures 45 ticks / 2.4716 s outside the
live window and cached full FO measures 43 ticks / 2.3618 s versus 88 ticks /
4.8334 s uncached. Historical exact-floor wire and full activity measurements are
recorded in
[`../../docs/architecture.md`](../../docs/architecture.md#historical-exact-floor-activity-timelines)
and [`../../docs/testing.md`](../../docs/testing.md).

Both product routes pass current HTTP/2 and dual-issuer compatibility verification:
offline composition gates, read-only exact-floor reconnect runs, seven-NIC
matrix, CGA/MDA display cases, dependent conversation and native-tool checks.
Earlier HTTP/1 acceptance remains historical evidence. Physical-entropy
characterization and more provider-edge variation remain. See
[`../../docs/security.md`](../../docs/security.md).

## Read-only and reconnect contract

Both routes gather private input and perform all proofs on the target. The 8088
records PIT phase bytes after floppy sectors Seed already had to read and adds
no entropy-only disk activity. The 286 samples the AT RTC periodic source
against the PIT and likewise performs no entropy-only disk reads. Emulator
timing receives zero credit until each physical source is characterized.
Read-only media simply repeats the cold proof after restart.

Once committed, the TLS session is reused. A human request that fails before
any text appears gets exactly one fresh route and exact same-request resend.
A second failure returns to the prompt. Tool continuations and responses with
visible text are never automatically replayed.

## Drivers

`core.asm` emits one flat runtime; NIC families are the scoped runtime modules.
The build currently emits:

```text
NE.DRV  WD80X3.DRV  3C503.DRV  3C501.DRV
PCNET.DRV  TULIP.DRV  RTL8139.DRV  EPIC100.DRV
```

The runtime validates `SDRV` metadata, ABI version, sector size, and family
mask. One suitable driver autoloads; several produce `which driver?`; none
produces `driver setup failed` through the ordinary retry/restart path.
Station-address PROM reads remain non-fatal.

Use `INCLUDE_NIC_DRIVERS=0` or the per-family
`INCLUDE_NIC_DRIVER_*` switches to omit drivers. A driver-only update can
replace a `.DRV` when the resident ABI is unchanged.

## UI

Seed never switches video mode. It uses BIOS text services and the detected
column count.

```text
hardware/setup     dark "."
TLS setup          dark/normal "o"
agent ready        bright "o"
8088 splash        gray "security note"
fatal              current marker red, low tone, retry/restart
question           bright prompt ending in ?, cursor visible only while typing
```

The detailed UI contract is in [`../../docs/ui.md`](../../docs/ui.md). The
machine handoff ABI is in [`HANDOFF.md`](HANDOFF.md).

## Build and inspect

```sh
make
make inspect
make basic-bootstrap
```

Output:

```text
build/ibm_pc_5150/floppy-160k.img
build/ibm_pc_5150/SEED24A.BAS
build/ibm_pc_5150/SEED24B.BAS
```

Validation recipes, exact boot modes, pcap guidance, and the NIC matrix are in
[`../../docs/testing.md`](../../docs/testing.md).
