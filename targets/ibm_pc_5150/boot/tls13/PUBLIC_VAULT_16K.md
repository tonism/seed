# TLS 1.3 16 KiB linear VRAM vault

`public_vault_16k.asm` is the product backend for the transient
`0x7300..0x7fff` public-object range used by the 16 KiB TLS 1.3 schedule. It provides
all 13 virtual pages (3,328 bytes), not only the ML-KEM public key and
ciphertext:

```text
virtual 7300..7fff -> volatile video RAM
```

The implementation does not write the boot floppy, does not require writable media, and
does not borrow RAM from any NIC. The same mapping is used for every NIC
family. All payload, generation, update epoch, status, and integrity state
lives in VRAM; the access code owns no mutable conventional byte.

## Direct access ABI

The access leaf matches the current NE-backed call shapes:

```text
write:
  AL = virtual page 73h..7fh
  SI = conventional source
  BP = nonzero count
  destination offset within the first page is zero
  the write may cross pages, but must end at or below 8000h

read:
  BX = virtual source address 7300h..7fff
  CX = nonzero count
  DI = conventional destination
  the read may cross pages, but must end at or below 8000h
```

Both calls return carry clear on success and carry set on failure. The implementation
preserves all input registers plus `DS`, `ES`, `SS`, and `BP`, balances the
`3f00..3fff` stack, and returns with direction flag clear. Source or
destination 16-bit wrap and every out-of-range span fail closed.

Repeated and overlapping writes are supported while the vault has valid active
metadata. This covers ticket receipt and canonicalization, page `73`/`7f`
rewrites, the 1,184-byte public-key write, the 1,280-byte private-object write,
the 1,088-byte ciphertext overlay, early-object publication, FO backup/restore,
and final per-page scrubbing.

## Physical mapping

| Display | Payload | Metadata | Total owned |
| --- | --- | --- | ---: |
| CGA/color text | `B800:1000..1cff` | `B800:1d00..1dff` | 3,584 bytes |
| MDA | `B000:0000..0cff` | `B000:0d00..0dff` | 3,584 bytes |

The CGA window begins immediately after the 4,096-byte page-zero text window.
Normal page-zero text output and scrolling therefore remain available. Video
mode changes, whole-adapter clears, and selecting or drawing into another text
page remain forbidden while the vault is active.

MDA has only one 4,000-byte visible text page. Its `0x03b8` mode-control
register is write-only, so Seed does not try to read or persist it. At `begin`,
Seed clears the video-enable bit using the BIOS Data Area shadow at
`0040:0065`. It also narrows the 6845 scanout to one column and redirects its
start address to 25 zeroed cells at `B000:0fa0..0fd1`, outside the ordinary
4,000-byte page. The second hold is required because some adapters and
emulators retain the mode write without honoring its output-enable bit.

All BIOS text output, scrolling, direct video writes, ENV screen restoration,
and mode changes are forbidden until `zeroize` or failure has scrubbed the
vault. There is deliberately no changing MDA UI during this interval: the
last safe screen remains visible on real hardware, while implementations that
ignore output-disable scan only the zero quarantine.

MDA zeroization scrubs all 4,000 bytes at `B000:0000..0f9f`, including the 416
bytes beyond the vault. Only after that scrub does Seed restore page-zero,
80-column scanout and write the BIOS shadow with video enabled to `0x03b8`.
The shadow affects post-scrub presentation only and is not a confidentiality
authority. The product must redraw the screen after output is restored. The
CGA failure/zeroize path scrubs only its 3,584-byte off-screen window.

## Lifecycle and integrity

The full image starts with a nine-entry near-pointer table:

| Offset | Entry | Input |
| ---: | --- | --- |
| `+0` | `begin` | `DX=nonzero generation` |
| `+2` | `write` | direct write ABI above |
| `+4` | `read` | direct read ABI above |
| `+6` | `seal` | none; verify every page |
| `+8` | `verify` | `DX=expected nonzero generation` |
| `+10` | `zeroize` | none |
| `+12` | `retire` | erase owned bytes but retain MDA quarantine |
| `+14` | `enter_raw` | verified deadline handoff |
| `+16` | `rebind_raw` | restore checked off-deadline mode |

The backend is detected from the BIOS CRT-controller word at `0000:0463`; it
is not a new caller-visible architecture choice. A successful MDA `begin`
holds both output-disable and quarantine scanout through the complete lifetime.
`zeroize` erases first and restores ordinary scanout/output afterward.

Each 256-byte page has an independent redundant corruption tag:

```text
CRC32-IEEE(preimage) || bitwise_inverse(CRC32-IEEE(preimage))
preimage = generation_le16 || page_index || page[256]
```

Metadata also contains redundant magic, generation/inverse, epoch/inverse,
backend/inverse, access mode/inverse, and inverse/status bytes. The three
formerly mode-related bytes are reserved zeroes. A write:

1. validates active metadata;
2. verifies the old value of a partially overwritten final page (complete
   pages have no surviving old bytes);
3. clears status and inverse-status before its first payload byte;
4. writes the complete requested span;
5. recomputes every touched page tag;
6. advances epoch and its inverse; and
7. publishes inverse-status and then status as the last two writes.

An interruption cannot expose a partially updated image as valid. There is no
in-place recovery from a torn update: the next access detects invalid metadata,
scrubs the mapped vault, and requires a new `begin`.

A read verifies every touched page before copying any byte to conventional
RAM, then revalidates scalar metadata. `seal` and generation-bound `verify`
scan all 13 pages. Page-local validation means corruption in an unrelated page
is discovered when that page is next touched or at a full `seal`/`verify`.

The CRC and its redundant inverse detect accidental corruption, torn writes,
and stale lifecycle state. They are not an authentication primitive and do
not defend against an attacker with arbitrary local-memory writes; that
attacker is outside Seed's machine boundary.

## Stateless phase loading

Building with `PV_ACCESS_ONLY=1` emits:

```text
+0  write pointer
+2  read pointer
+4  stateless access leaf
```

Measured image sizes are:

| Image | Bytes | Purpose |
| --- | ---: | --- |
| full lifecycle image | 1,422 | `begin`, access, full verify, raw-mode transition, retire, zeroize |
| duplicated access leaf | 867 | direct read/write plus validation and scrub |
| access-only pointer table | 4 | two near pointers |
| access-only image | 871 | table plus exact leaf |

The access leaf has no mutable conventional data and no references tied to its
assembly origin. The offline gate assembles it at `0x1800`, `0x2400`,
`0x2800`, and `0x2c00` and requires the 867 leaf bytes to be identical. It
erases every code image and reloads a different access image before every read
or write, proving that neither code nor state must remain pinned between
consuming phases.

The 867-byte duplicated leaf is therefore a real product cost: each phase
that directly consumes the virtual card range needs roughly two sectors of
access code, or must stage the same leaf into safe scratch before the call.
The 1,422-byte lifecycle image can likewise be demand-loaded for lifecycle
operations. Read-only floppy media is sufficient because loading is read-only.

On the 8088 acquisition route, Seed loads that three-sector lifecycle
image into retired KeyGen code at `0x1800..0x1dff`. That placement is disjoint
from both the still-live public key at `0x08c0..0x0d5f` and the preconnect
continuation at `0x2400..0x27ff`. Seed can therefore publish raw mode without
restoring or revalidating the public key inside the provider deadline.

## Conventional-memory exclusions

The checker protects these current 16 KiB bands across every call:

| Range | Purpose |
| --- | --- |
| `3600..3e3f` | live TLS and pre-auth high state |
| `3e40..3eff` | arena/context |
| `3f00..3fff` | stack |

No mutable vault metadata is placed in any of them. The proof performs no disk
or NIC I/O.

## Failure behavior

Bad bounds, bad metadata, a bad page tag on data that must be preserved or
read, payload corruption, generation mismatch, or torn publication returns
carry set after scrubbing the resolved vault. A complete-page replacement may
heal a bad old payload/tag because no old byte survives. MDA page-zero scanout
and output are restored only after the scrub, using the BIOS shadow as a
post-scrub presentation value. If the BIOS CRT-controller word names neither CGA
nor MDA, the code cannot safely identify a vault to erase and returns failure
without touching either candidate window.

## Offline gate

Run:

```sh
python3 tools/check-tls13-public-vault.py
```

The gate assembles the source with NASM and executes it as 8086 code under
Unicorn. For both CGA and MDA it replays 29 product write shapes and 37 product
read shapes, including the 1,184-, 1,280-, and 1,088-byte cross-page writes and
the repeated page `7e`/`7f` lifecycle. It reloads access code before every
call, checks the physical status-last write order, guards the stack and high
RAM bands, exercises 73 hostile/corruption cases, verifies the exact
mode-disable, one-column quarantine, page-zero/80-column restore, and
post-scrub BIOS-shadow output sequences for four mode values, and requires
final zeroization. This CPU model does not prove a physical adapter or emulator
actually honors display control; live MDA screenshots during the active vault
and after restore are a separate acceptance gate.
