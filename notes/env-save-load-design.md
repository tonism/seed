# Environment Save/Load — Design

Resolved design (2026-06-27). Replaces the charter brief. Everything below is settled; the
build plan at the end is the order to execute. When it ships, the load-bearing parts graduate
into `docs/architecture.md` (the writable-media tier) and `HANDOFF.md` (the flag bit).

## The idea

Everything the user/agent builds at runtime — the conversation, and whatever the agent writes
into the arena via `$w`/`$x` — lives in RAM and is wiped on every restart. If the machine can
write to its boot medium, Seed can persist that state and restore it at the next boot, so the
agent **accumulates across restarts** instead of booting fresh.

It is a **capability tier gated on "writable media present"**, orthogonal to the RAM and CPU
tiers, exactly like the 286 secure tier. Purely additive: no writable media → the feature is
simply absent, and the 16 KiB functional floor is untouched.

## What persists, and what doesn't

The Build-12 layout already isolates everything the user/agent owns into **one contiguous
block** — the conversation window + arena, `[chat_context_start, ceiling)` (see
`core/data.inc`), above the reconnect-safe line. That block is free of live/code/hardware
bytes *by design*. Everything else in segment 0 is machine-specific and rebuilt every boot:

| Region | What's there | Why it is rebuilt, never restored |
|---|---|---|
| `0x0000–0x04FF` | IVT + BIOS data area | This boot's live vectors + tick/keyboard/disk state |
| `0x0600` | handoff / capability vector | This boot's detected RAM, NIC, IP, MAC, drive |
| `0x1000`,`0x1600`,`0x1800` | nucleus, active NIC driver, crypto window | Freshly loaded code for *this* machine's NIC/build |
| `0x3600+` | TLS session keys, scratch, stack | The session is dead after power-off — must re-handshake |
| loop cache (32K) | preloaded phase code | Code, rebuilt at boot |

So persistence has a clean unit: **the contiguous user region.** A literal full-RAM dump would
be wrong — restoring any of the rows above would clobber the booting machine's live state with
a dead snapshot. Instead we **boot the machine as itself** (a full normal boot rebuilds the HAL,
the network, and a fresh TLS session) and then drop the saved user region into the
already-configured pool. This is what removed the hard part: there is **no capability-vector
matching on restore** (no CPU/NIC/crypto comparison) — the machine configures itself for
whatever hardware it has.

Anything the agent built *outside* the arena is not Seed's concern (Authority Model). Seed
persists the region it advertises as the arena; the rest belongs to the user/agent environment.

## Boot-as-self, restore-after-splash

```text
full normal boot   hardware → network → fresh TLS handshake (live session established)
splash             the "ready" screen
restore            read ENV.DAT from the boot drive; gate it (below)
  · valid + fits   copy the saved region back to chat_context_start; set the metadata vars;
                   neutralize line-start '$' in the restored window; redisplay the recent dialogue
  · valid, bigger machine   restore at the OLD size, warn + continue (see the fit gate)
  · won't fit / corrupt     the fit menu, or a silent clean boot
DPI prompt         the live session sits underneath; the first real prompt carries full context
```

Restore **pre-loads memory; it does not resume a session.** The TLS session cannot survive a
power-off. There is no cold-greeting round-trip on a restore boot.

**Boot integration (verified against the code).** The cold greeting is the bare `"Greet."`
request sent while `handoff_status != ready`, and it happens *inside* `prepare_agent_path`
(`net_phase.inc:12`) — that routine does config (A/U/Q/S) and then **falls through into
`prepare_agent_endpoint_path`** (the connect + handshake + exchange). So the clean hook is
**after config, before that fall-through**: try restore; if it restores, **`ret` (skip the
greeting entirely)**; else fall through to the normal greeting. Consequences, all decided:
- **Restore is not gated on the writable-media bit** — it is a *read*, so it works from a
  write-protected floppy too. The bit gates only `$s` (save).
- **The handshake is deferred.** A restore boot opens no connection; the user's first message
  does the (cold) handshake carrying the restored window. (A fresh boot makes you wait ~14.5 s
  for the greeting anyway; this just moves the wait to when you engage. Establishing a live
  session at boot with no message sent is a later polish.)
- **The splash is rendered explicitly** by the restore path (the `"seed build N / insecure"`
  identity normally rides inside the skipped greeting's stream phase), then the redisplay.

## The redisplay UX — repaint the actual screen

Seed persists **the literal screen** the user was looking at — the video text buffer (char+attr
cells) — and **paints it back to video memory verbatim** at restore, so the user lands on the
*exact* screen they left: the model's prose, the dim tool lines, the prompts, the wrapping, all of
it. This is deliberately **not** a reconstruction from the conversation window: the window is the
*model-facing* serialization (role-labeled `You:`/`Assistant:` turns, the compacted note), which
looks materially different from what was on screen and would land the user somewhere unfamiliar.

So restore handles two representations for two audiences: the **window** (restored into
`chat_context_start`, rides into the next request — the model remembers) and the **screen snapshot**
(painted to `0xB800`/`0xB000` — the user's familiar view). The paint is a straight `rep movsw`;
it runs only when the saved `screen_cols` matches this machine's (a 40↔80 mismatch can't be
painted — then the screen is just cleared, the window still restored). `$s` captures both (step 4).

## Medium

**The boot drive, best-effort.** `ENV.DAT` lives on the boot floppy beside `CORE.SYS` /
`USER.CFG`. This fits the recovery-boundary model exactly: a **write-protected** floppy →
persistence silently no-ops (the hard kill-switch still wins); a **writable** floppy →
persistence. The capability bit advertises that a FAT12 boot drive exists; the real writability
truth surfaces at `$s` time (`int 13h` error `03h` = write-protected), the same best-effort model
`save_user_cfg` already uses. Any other medium (second floppy, HDD, network) is the user/agent's
problem, not Seed's.

## Triggers

All three are issuable by **both user and agent** — the tool scanner is provenance-blind
(`phases/tool_call.inc:66` scans the whole window for a line-start `$`, never checking who wrote
it), consistent with the Authority Model's no-privilege-boundary stance.

```text
$s   save    build the snapshot, real FAT12 write to the boot drive (room-checked, best-effort)
$l   load    mid-session revert: discard the current context+arena, restore the saved one
auto-load    automatic at boot (the agent boots remembering)
```

`$s` reports a system line when the medium is not writable or there is not enough room; it only
writes once it has verified both. `$l` reuses the boot restore path between turns (same machine →
addresses hold), then redisplays.

## Format: `ENV.DAT`

A header plus two payload sections — the window+arena region (for the model) and the screen
snapshot (for the user). The window/arena split is metadata, so neither section needs a table:

```text
offset  size  field
0x00    4     magic "SEDV"
0x04    1     format_version           (the compatibility axis)
0x05    1     flags                    (reserved)
0x06    2     build_number             (provenance, informational)
0x08    2     ram_top at save time     (hint for the warning text)
0x0a    2     chat_context_len_var     (the OLD window/arena split boundary)
0x0c    2     chat_context_used        (valid conversation bytes)
0x0e    2     note_len                 (compacted-memory prefix length)
0x10    2     region_len               (window+arena bytes -> chat_context_start, for the model)
0x12    1     screen_cols              (snapshot width; 0 = no snapshot)
0x13    1     screen_rows              (snapshot height)
0x14    2     payload checksum         (16-bit sum of the whole payload)
0x16    2     header checksum          (16-bit sum of bytes 0x00..0x16)
0x18    ..    payload: [region_len window+arena bytes][screen_cols*screen_rows*2 snapshot cells]
```

The snapshot cells are row-major char+attr, exactly as in CGA/MDA text memory, painted back to the
video segment verbatim. `tools/env-dat.py` is the byte-for-byte reference; `layout.inc` mirrors the
offsets in asm.

**Versioning.** Compatibility hinges on `format_version`, not the build number (a later build
that does not touch the format stays compatible). Seed carries `min_supported_format` and
`current_format`; the gate is `min ≤ dat ≤ current`. `build_number` rides along as provenance.
Migrations are a future problem — we add them when we first break the format.

## The restore fit gate

Two tiers:

**1. Silent fail-safe** — `magic` / `format_version` / checksum. Any failure → ignore `ENV.DAT`,
clean boot. A corrupt, foreign, or incompatible file **never bricks the boot** and never shows a
menu (there is nothing coherent to offer).

**2. Memory-fit** — the file is readable but the machine's geometry may differ. We saved the whole
pool verbatim, so restore is `copy region → chat_context_start; set chat_context_len_var /
chat_context_used / note_len`. Addresses fall back into place because the base is fixed. Fit is
one comparison — `region_len` vs this machine's `(ceiling − chat_context_start)`:

```text
equal               silent restore + redisplay        (the common same-machine case)
smaller than machine restore at the OLD window size,   warn + continue  (surplus → arena)
larger than machine  will not fit                      error: { start new, restart }
```

Why the **warning** on a bigger machine: to keep restored arena programs runnable we preserve
their absolute addresses, which forces the window/arena boundary to stay where it was — a larger
window would overlap the restored arena. Seed cannot grow the window for you because it cannot
know how to relocate whatever you put in the arena. So the extra RAM lands above as arena, the
context window keeps its old size, and the pause tells you so. The on-screen text is terse; its
meaning is: *"more memory than when this was saved — your context is restored at its old size,
the surplus went to the arena; to use it for context, move your arena programs and set a new
context size yourself."*

The fit menu is dim one-line boot UI: `continue` / `new` / `restart`, where `restart` reboots
(`int 19h`) and `new` discards `ENV.DAT` and boots fresh. With an error, `continue` is absent.

## The window-cap knob

For the warning's "set a new context size yourself" to be actionable, the ledger advertises the
window cap (`chat_context_len_var`'s address) alongside the existing `compact@` threshold. The
agent already has `$w`; today the ledger simply does not name it. To reclaim surplus arena RAM for
context, the agent relocates its arena programs and writes the new cap.

## Trust

`ENV.DAT` is the agent's own **non-secret** state on the boot medium — which already holds the
plaintext API key in `USER.CFG`. So: a checksum for corruption, the version/magic gate against
foreign files, and fail-safe. No cryptographic integrity (no key survives a read-only boot, and
it is not a secret).

One correctness guard: **neutralize any line-start `$` in the restored window** so last session's
tool directives do not re-fire. A faithfully-saved window already has them neutralized after
execution (`tool_call.inc:183` turns `$`→space on a real call); this guarantees it for a mid-turn
save or a crafted file. With the arena restored on the same machine addresses hold, so even a
re-fire would be consistent — this is belt-and-suspenders, per the Authority Model.

## RAM interaction / 16 KiB parity

Writable-media-gated, **RAM-agnostic mechanism**. Save and restore are cold phases (~0 resident
bytes) → it fits 16 KiB. The restorable *volume* scales with RAM exactly as the live window
already does. **Uncapped**: more RAM means more room above the restored block; the saved region
just fits with the surplus becoming arena. Restore dodges the ~15 s crypto race trivially — it
runs after the handshake, at the splash.

## Forward-looking (out of scope now)

- **Beyond segment 0 (>64 KiB).** When MB-scale RAM becomes addressable (EMS / unreal / protected
  mode), cap window growth and let the surplus flow to arena — a literal 50/50 split at MB scale
  hands the window megabytes it can never use (the model's context limit and the 3/4 compaction
  threshold already bound the useful window). Settle the split-cap policy with that work.
- **Other media.** The format is drive-addressed; a second floppy or HDD (`int 13h 0x80`) is a
  later *detection* add, not a rewrite.
- **Auto-save** (between turns) is a later convenience tier; per-turn-during-render is ruled out
  (the chat loop is a no-floppy zone).
- **Arena high-water / cap** only matters on a >32 KiB machine with a large arena — not a config
  that boots today; the whole region is a few KB on 16K/32K and fits the floppy trivially.

## References

- `docs/architecture.md` — Capability Tiers, Memory Shape, Floppy Policy, Recovery Boundary,
  Authority Model.
- `targets/ibm_pc_5150/HANDOFF.md` — the capability vector (where the new flag bit rides).
- `targets/ibm_pc_5150/boot/phases/save_user_cfg.inc` — the existing FAT12 write precedent
  (root-dir find, `int 13h` AH=03h with LBA→CHS, size patch); updates an existing entry only.
- `targets/ibm_pc_5150/boot/phases/tool_call.inc` — the `$`-verb tool phase + the provenance-blind
  scanner.
- `targets/ibm_pc_5150/boot/core/data.inc` — `chat_context_start` and the contiguous user region.

## Build plan

Staged, matrix-green increments (no big-bang). Load is built and validated *before* save, against
an offline-generated `ENV.DAT` — the project's proven read-path-first pattern (cf. `tools/x509/`,
`tools/tls-decrypt.py`).

1. **Capability bit + detection.** Add `handoff_flag_writable_media (0x0040)`; set it at boot via a
   non-destructive boot-sector write-back probe (honest: set ⟺ writable; clear on write-protected).
   The **ledger advertisement is deferred** to the verb steps — surfacing a capability before its
   tool exists made the model hallucinate tool calls before (`agent_api_stream.inc:501`). *Validate:*
   assembles clean; a normal boot still greets (the probe is non-destructive). Bit *value* (rw vs ro)
   becomes runtime-observable in step 3, when restore consumes it.

2. **Format + offline tool.** Freeze the `ENV.DAT` layout; build `tools/env-dat.py` to
   create/inspect one. *Validate:* the tool round-trips a known file; checksum + header verified.

3. **Restore path + fit gate + redisplay.** A new cold phase (its own FAT root scan + cluster read,
   like `user_cfg`; the FS find/read helpers are phase-local, not resident), hooked into
   `prepare_agent_path` after config (skip the greeting on a successful restore — see Boot
   integration). Decomposed:
   - **3a** find `ENV.DAT` + validate (magic/format/header+payload checksum) + fit check + copy the
     region to `chat_context_start` + set `chat_context_len_var`/`used`/`note_len` + neutralize
     line-start `$`. *Validate (tool-made `ENV.DAT`):* type a follow-up → the model answers from the
     restored context (it remembers); corrupt/foreign → clean boot (normal greeting).
   - **3b** render the splash, then redisplay the recent dialogue on screen. *Validate:* the prior
     conversation shows before the prompt.
   - **3c** the fit menu (`continue`/`new`/`restart`, `int 19h` reboot) for the bigger-machine
     warning + the won't-fit error.

4. **Save path + `$s`.** The real FAT12 writer: free-cluster scan, room check (free clusters +
   reclaim of any existing `ENV.DAT`), cluster allocation, FAT-chain write, root-dir
   create-or-update, multi-sector data write. `$s` in the tool phase, best-effort. Now that the verbs
   exist, advertise persistence in the ledger + explain `$s`/`$l` in the instructions (deferred from
   step 1). *Validate:* `$s` → reboot → restored (closes the loop end-to-end); write-protected →
   system line, no crash; no room → system line.

5. **`$l` + polish.** Mid-session load/revert reusing the restore path; redisplay formatting;
   finalize the window-cap knob. *Validate:* `$l` restores + redisplays mid-session.

6. **Graduate + matrix.** Fold the tier into `docs/architecture.md`, the flag into `HANDOFF.md`, a
   `builds.md` entry; NIC-matrix spot-check; refresh the memory map.
