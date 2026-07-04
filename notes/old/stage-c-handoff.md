# Stage C handoff (work/scaling, Build 12 memory-scaling milestone 1 "8088 far")

Fresh-context brief. Supersedes the confused "pre-existing >64K video bug" trail in earlier notes/memory.

## Where the build is
- Branch `work/scaling`, on top of committed `7195fb2` (Stage A far addressing + Stage B far-arena advert).
- Uncommitted wip (CORE.SYS `9fe89d…`): C1a window→far copy in `agent_request` entry, far@ ledger field
  ALWAYS-EMIT (fixed width — fixes a Content-Length over-count), and the `mac` ledger field dropped
  (freed ~23 B in `agent_api_stream` for C1b's renorm). Build green.
- Untracked test profile `targets/ibm_pc_5150/86box/vm-net-ne2k8-xt/` (machine=ibmpc82, gfxcard=cga) for
  >64K testing — `ibmpc` caps conventional RAM at 64K, so use ibmpc82 (or ibmxt) with `--ram-kib 256`.

## The "video corruption" — RESOLVED, two separate things (do not re-chase)
1. **Real, keyed, FIXED:** the ledger-RELOCATION bug — pre-building the 113-B ledger at `0xF0E` overwrote
   resident attr vars (`cursor_row=0xF55`, `seed_attr=0xF5B`, `error_attr=0xF61`, … `0xF65`), so the
   renderer painted ledger ASCII as attributes → "orange-bg splash / bright-bg expanding as you type."
   This is what the user actually witnessed (they were in the DPI = keyed). It is REVERTED. The current
   plan keeps the ledger in place (no `0xF0E` buffer) and frees C1b's ~20 B by the mac-drop instead.
2. **Not a bug (test artifact):** building in a `git worktree` excludes untracked/gitignored files, so the
   floppy had no `config/USER.CFG` → keyless → seed parks on the "agent? / key?" config form; junk typed as
   the key left a half-filled form that LOOKED scrambled. ALWAYS copy `config/USER.CFG` into a worktree
   before testing the chat path, or build from the main tree.
- Render path is sound >64K: instrumented dump @256K = correct layout vars (ram_top=0xFFF0, cols=80,
  seed_col=38, form_left=24, form_field=48, video_seg=0xb800); `int 10h AH=06` clears cleanly; base+USER.CFG
  @256K reaches the greeting and chats with clean layout. The dim "insecure" splash is NORMAL (8088 insecure
  tier), not corruption.
- OPEN: only a SHORT keyed exchange was tested at >64K. A keyed LONG-typing session at >64K (= the relocation
  bug's symptom zone) has NOT been re-confirmed clean. The Stage C commit gate covers this.

## C1b — DONE (implemented + validated, NOT yet committed)
Far-log-canonical FLUSH model. Implemented across data.inc / hardware_setup / agent_request /
agent_api_stream (CORE.SYS still 4 resident sectors, build green):
- `far_flushed_len` (DWORD) + `far_flushed_esc` (DWORD) state in reconnect_state (boot-zeroed). At the
  compaction threshold agent_request FREEZES the seg-0 window into the far log: `far_flushed_esc +=
  json_bytes_len(window)`, `far_flushed_len += used`, `used = 0` (the window was already mirrored at
  `far_flushed_len` by the phase entry, so the freeze is just an offset advance). Reconnect-safe: the
  flush zeroes `used`, so a rebuild re-mirrors 0 bytes and re-flushes nothing.
- Dialogue streamed = far-log [note_len .. far_flushed_len+used), a 32-bit count. agent_request
  PRECOMPUTES the range (`dialogue_off` + DWORD `dialogue_cnt`) so the maxed agent_api_stream phase just
  loads + streams it (kept that phase inside its 3-sector window). `append_context` takes a 32-bit dx:cx
  count and renormalizes ds +0x1000 each time si wraps a 64K boundary.
- Content-Length is now 32-bit (`api_body_len_hi:api_body_len`) via a new `.append_u32_decimal`.
- **CRITICAL GATE (not in the original plan):** the far log needs real RAM at flat 0x10000, which only
  exists when conventional RAM > 64 KB. `far_log_seg_var` (= far_log_seg when active, else 0) is set at
  boot from BDA 0x0413. On a <=64 KB machine (the 16K matrix / RAM floor) it is 0: the mirror is skipped,
  the flush falls through to the Build-11 model-summarize compaction, and the dialogue/note reads use the
  seg-0 window. So <=64 KB machines are byte-for-byte Build 11; only >64 KB streams the canonical far log.
  Without this gate, C1a/C1b would have fed garbage context to every 16K machine.
- A code-review pass (subagent) caught + fixed ONE critical bug: `append_context.ctx_flush_failed` left
  the entry `push ds` on the stack (carried from C1a, worsened by adding dx) -> `ret` to 0x0000 on a
  flush-send failure; fixed with `add sp,8` + `pop ds` (also restores ds=0 per contract).

### C1b validation done (2026-06-29, NOT committed)
- **Big machine (ibmpc82 @256K, ne2k8, direct boot, far log ACTIVE):** boots + greets; 5 consecutive chat
  turns render coherent answers; then a NEEDLE-RECALL test (plant "ZEPHYR" in turn 1, bury it under 5
  turns that vastly overflow the ~1-2KB seg-0 window -> forces multiple flushes, then ask for the word) ->
  the model answered **"zephyr"**. Only the far log could carry it. Flush model proven end-to-end.
- **Small machine (ne2k8 @32K direct, far_log_seg_var=0):** boots + greets; 2-turn chat with correct
  recall ("cat and a fox") -> the Build-11 seg-0 fallback ready-path is intact.
- The literal >64K renorm (far log past 0x1FFFF) is NOT hardware-exercised (would need ~64KB of typed
  chat); the logic was traced in review.

## C2 + C3 — DONE (implemented + validated 2026-07-03, NOT committed)
Far-region SPLIT (fixes the arena/far-log overlap) + 50/50 sizing + 1 MB cap. CORE.SYS still 4 resident
sectors, build green; a code-review pass (subagent) found NO bugs.
- hardware_setup boot-computes: conv_top = conv_KB(BDA 0x0413)<<10; far region = conv_top-0x10000;
  `far_window_cap` = min(region/2, 1 MB) [C2 50/50 + C3 1 MB cap]; `far_arena_base` = 0x10000+cap;
  `far_arena_top` = conv_top. All DWORDs in reconnect_state. Inactive (<=64 KB): cap 0, base==top==0x10000.
- The ledger now advertises `far@<arena_base>-<arena_top>` (the ARENA, ABOVE the log — overlap gone) via a
  new `agent_api_stream_ledger_hex32` (falls through into hex16). `api_ledger_len` far term 6->17; still
  fixed-width == the emitted bytes (CL-exact; review hand-verified 98 == 98). C3 spill-to-arena is
  automatic (arena = region - window_cap).
- agent_request bounds the far log at the cap: at phase entry, if far_flushed_len+used >= far_window_cap,
  RESET the log (drop old history) before the mirror. Hard drop-oldest; can't trigger on realistic tiers
  (seg-0 window ~8-16 KB << cap >= ~32 KB). drop-oldest/summarize is the future refinement.
- Validated on 256K: the model reported **far@00028000-00040000** (region 0x30000, cap 0x18000, arena base
  0x28000) — the split is live and correctly sized.
- **Splash regression fixed:** the far detection clobbered `ah` (= screen cols, from int 10h) before
  seed_col was computed -> splash + loading glyphs shifted right. Fixed by reloading cols from
  [screen_cols] before the seed_col math. USER-CONFIRMED centered on the VM.

**Milestone 1 (8088 far) is functionally complete** (C1a+C1b+C2+C3), uncommitted on work/scaling.

### C3 1 MB cap — MATH-VERIFIED, HW-validation DEFERRED to milestone 3
The 1 MB window cap + spill-to-arena is correct but UNREACHABLE on any milestone-1 build, so it was NOT
hardware-validated. Two independent blockers, both lifted only by milestone 3 (286 extended memory):
1. **Sizing is conventional-only.** far_window_cap is derived from BDA 0x0413 (<=640 KB), so region/2 is
   always <=288 KB -- the `.cap_1mb` clamp never fires. Even a 4 MB 286 sees only conventional memory until
   the `int 15h AH=87h` block-move (windowed) path feeds the far region (milestone 3). Extended RAM is read
   via int 15h AH=88h / CMOS, NOT 0x0413.
2. **Real-mode far can't reach 1 MB anyway.** The far log is addressed by seg:off with a `ds += 0x1000`
   renorm; a 16-bit segment caps at ~flat 0x10FFEF, so a 1 MB window at base 0x10000 (top 0x110000)
   overflows the segment. The 1 MB domain therefore belongs to the WINDOWED access path (milestone 3),
   not real-mode far.
Offline sim (the exact 16-bit sizing sequence) confirms the clamp: 4 MB -> 1 MB window + far@00110000-
00400000 (~3 MB arena); 16 MB -> far@00110000-01000000. **Milestone-3 gate: validate the 1 MB cap +
spill-to-arena on a >=4 MB 286 once extended memory + windowed addressing land.**

## Deferred (user-set order, after milestone 1)
1. Fix the provider-selection menu.
2. Proper testing INCLUDING the 16K matrix. NB the matrix is NOT actually flaky — the ROM-BASIC sidecar
   was mis-driven this session (wrong harness setup, --foreground-launch beeps/focus-steal). Relearn the
   correct 16K setup before the testing pass.
3. Investigate RETRIES on slower machines (user strongly suspects the reconnect/retry path is broken on
   slow CPUs). Comes after 1+2.

## Commit gate (user-set) — status
Done: the FORCED long-answer/flush turn + a recall follow-up (needle test, far log active) + the far-split
advert. WAIVED for now: the full 7-NIC matrix (deferred to the proper-testing pass). User has NOT approved a
commit yet — nothing on work/scaling is committed. Per commit discipline: ASK before committing; Stage C /
milestone 1 commits as ONE piece.

## Process reminders
- Read FULL build output + confirm fresh CORE.SYS md5 before any `--no-build` run.
- One 86Box at a time (`pkill -f 86Box` first). `@` can't be typed by the harness. ibmpc82@256K POST is slow
  (~150s) — type prompts late.
