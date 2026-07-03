# UI unification — one terminal style, boot → chat (Build 12)

Settled design (2026-07-03, with the user). Supersedes the provider-menu "fix" — the whole boot UI is
being unified to the DPI's terminal style instead of the centered/animated splash + slide menu.

## The problem
Three disconnected visual styles: (1) centered minimalist boot splash + centered load glyphs; (2) a
centered, animated slide "miller-column" config menu (buggy, near-impossible to iterate); (3) the DPI chat
= a clean terminal scroll. The config menu regressed unnoticed (users almost always have USER.CFG, so the
menu is rarely seen). Trying to fix the centered/slide menu was the wrong direction.

## The design — PURE NEWLINE FLOW (no absolute positioning)
Everything is one stream of text + newlines + scroll-when-full, exactly like the DPI already does. The key
insight (user): we do NOT need absolute row/col positioning. Print the banner as a few lines at the top;
because the "insecure" line + its newline is simply skipped on a 286+, everything below shifts up on its
own — no `seed_row`/`text_top_row` constants, no tier-dependent math.

Banner (printed once at the top of a cleared screen, as newline flow):
```
<blank line>
seed build NN            <- splash (bright)
insecure                 <- 8088 tier ONLY; 286+ skips this line entirely (and its newline)
<blank line>
> ...                    <- terminal text begins here (flows down, scrolls when full)
```
- Boot progress = minimalist `> something` system lines (like the DPI's dim system lines), replacing the
  centered load-marker glyph animation.
- If a user selection is needed (e.g. no USER.CFG → agent/key setup), present it the SAME way a model turn
  is presented: a system line asks, then a temporary DPI-style input field appears INLINE (right after the
  current text, not pinned to the bottom), the user types, and on Enter the answer stays on screen in the
  same style/color as a user message in the chat loop.
- Prompt-follows-output (inline) is the unifying rule; once the screen fills during chat it naturally
  coincides with the bottom. (The DPI's `.render_prompt` already mostly does this.)
- Consequence: the banner scrolls away naturally once the terminal fills (same as today's splash, which
  already scrolls within the rows-1..23 region). Pure terminal.

## Convergence point
Both boot paths (BIOS boot sector AND ROM-BASIC sidecart loader) load CORE.SYS and far-jmp to `start:`
(core/main.inc:26). The screen is cleared in `hardware_setup_phase_display` (int 10h AH=06). Draw the
banner right after that clear (earliest point with video initialized), so it's up from the start and boot
progress flows below it. (Today the splash is drawn LATE, in the cold-greeting path via a separate splash
phase — move it early.)

## Architecture facts (from the code map)
- RESIDENT (reusable by any phase): `print_char` (ui_core.inc, int10 AH=09, honors BL attr, advances
  cursor_col), `wait_ticks` (ui_core.inc), `scroll_text_area` (nic.inc, int10 scroll using `scroll_br`),
  `show_load_marker` (ui_core.inc). State: cursor_row/cursor_col/screen_cols/video_seg + the attrs, all
  resident.
- PHASE-LOCAL: the DPI input loop + `.advance_line`/`.render_prompt`/wrap (dpi.inc); the response
  streamer + its advance (agent_response.inc); the splash typing (splash.inc); the config menu (agent_setup.inc).
- Scroll today: region rows 1..scroll_br(=dpi_prompt_row-1=23) via CX=0x0100; prompt pinned at
  dpi_prompt_row=24; text flows and scrolls, prompt drawn after the last response line (already ~inline).
- Attrs (CGA): ready/seed/question/menu_selected = 0x0f bright; crypto = 0x07 normal gray; build/load/
  menu_idle = 0x08 dim; error = 0x0c red. User-typed value should be 0x07 (normal) — already fixed.
- NUCLEUS IS ~FULL (resident code). Any shared newline/print-line helper must fit or be golfed for.

## Implementation plan (incremental, each a visual checkpoint)
1. **Banner at the top, newline flow.** Draw blank/splash/[insecure]/blank via print_char + newline right
   after the screen clear (early, hardware_setup). Retire the centered absolute positioning. Self-verifiable
   via a cold-greeting screenshot (no keypresses).
2. **Boot progress = `> ` lines.** Replace the centered load-marker glyph with minimalist `> ...` system
   lines as bring-up proceeds. (A small shared "print line + newline-with-scroll" helper.)
3. **Config = chat exchange.** Rewrite agent_setup: system prints `> agent?` etc., a DPI-style input field
   appears inline, Enter echoes the answer as a user message (0x07). DELETE the slide/menu code
   (slide_selected_agent_left/right, draw_selected_agent_slide, centered form). Arrows still cycle the
   agent list in place. Needs keypress verification (synthetic input into the boot menu is unreliable from
   the harness — lean on the user, or drive via the DPI once it's chat-style).
4. **Seamless hand-off into the chat loop** (banner + terminal already in place; prompt already inline).

## Step-1 attempt (2026-07-03) — reverted; SPACE is the real blocker
Tried: draw the banner early (right after the hardware_setup screen clear), splash as newline flow, remove
the late splash invocation. Hit a wall on every side — this is why the refactor needs a dedicated golf pass:
- **Nucleus is FULL.** Adding a `call_core_phase core_splash...` in hal_start (to draw the banner early)
  overflowed resident code ("shared resident code overflows past the NIC driver slot" / "TIMES -6").
- **hardware_setup is FULL.** Inlining the banner (~90 B code+text) there overflowed its low-scratch window.
- **Phase-from-phase same-address conflict.** hardware_setup and splash both load at low_scratch_start, so
  hardware_setup can't `run_core_phase_at` splash (it would clobber its own code; the return lands in the
  overwritten bytes → crash). So the banner can't be drawn by loading the splash phase from within an
  early phase.
- **Cold-greeting flow ordering** needs untangling too: on the first turn dpi_phase draws the "> " prompt
  (at dpi_prompt_row-2) BEFORE agent_api_stream runs the splash, and handoff_status is already `ready`
  before chat_loop — so exactly when the not-ready "cold splash" path runs needs re-confirming before
  moving the banner + making the greeting flow below it.
Conclusion: the banner-early + terminal-flow needs (a) reclaiming resident/phase bytes via golf (the
Build-12 pattern — every addition freed space first), OR restructuring so the banner draws from a phase
with room; and (b) interactive verification for the config/prompt parts, which the harness can't drive
(synthetic keys into the boot menu are dropped). Best done as a focused pass, not tail-of-session.

## Step 1 — DONE (2026-07-03, not committed): banner top + greeting flow + instant
Landed and hardware-verified (keyed boot, 256K screenshot):
- **Banner at the top, cold-phased.** The splash phase now CLEARS the screen and draws the banner as pure
  newline flow at the top (blank / "seed build NN" centered / 8088-only "insecure" / blank), leaving the
  cursor just below it. It stays a cold phase (invoked from agent_api_stream's not-ready cold-greeting
  path) -- NO resident/hardware_setup cost (that was the earlier wall; keeping it cold-phased sidesteps it).
- **Greeting flows naturally.** Removed the absolute row-22 positioning in agent_api_stream (cold) and
  agent_response (.position_cold_greeting) -- the greeting now renders from where the banner left the
  cursor, so it lands right under the banner (no gap), prompt inline below it.
- **Fast-type retired in splash** -- instant print (the type animation + per-char wait_ticks are gone).
  (agent_setup still has fast-type; it's being deleted in step 3 anyway.)
Result on screen: `seed build 12` / `insecure` / (blank) / `Hello! How can I help you today?` / `>`.
CORE.SYS abe61ee9. Files: splash.inc (rewrite), agent_api_stream.inc + agent_response.inc (drop the
row-22 resets), main.inc (no change kept). NB the banner is still drawn LATE (at the cold greeting), so
the ~150s boot before it is blank-ish (just the load marker) -- see the boot-messages decision below.

## Boot-progress messages ("> ..." lines) — DECISION: defer to step 3
The messages themselves are cheap (phase-local strings + resident print_char), BUT they're only useful if
the banner is drawn EARLY -- otherwise the cold-splash's screen-clear WIPES them (they'd flash then vanish
at the greeting). Drawing the banner early is the resident/phase space wall. So: keep boot clean for now;
FOLD boot messages into the step-3 config-as-chat rework, which deletes the slide/menu code (frees bytes)
and is where the banner-early + terminal-input infra get sorted -- messages ride along persistent + free.

## Step 3 plan refinement (next): config as a terminal exchange
Rewrite agent_setup rendering to terminal style: print `> agent?` / `> key?` (/ `> server?`) as system
lines; capture the answer INLINE (reuse agent_setup's existing key loop, but render at the current cursor,
not a centered form); on Enter echo the answer as a user message (attr 0x07). DELETE the slide/menu/
centered code (slide_selected_agent_left/right, draw_selected_agent_slide, the centered form, the load-
marker dance) + agent_setup's fast-type. Only OpenAI in the builtin, so likely just TYPE the agent name
(no arrow menu) -- confirm with the user. Needs interactive verification at the VM (synthetic keys drop).

## Steps 2+3 progress (2026-07-03, not committed): banner-first + config-as-chat prototype
- **Banner drawn FIRST** (hal_start, right after hardware_setup's video-init+clear, before network/config).
  Splash phase = clear + newline-flow banner, cursor left below. Freed the resident bytes for this hal_start
  call by RETIRING the boot load-glyph (main.inc + hardware_setup) -- nucleus still 4 sectors. Removed the
  now-redundant cold-splash from agent_api_stream. CORE.SYS 85cb4ec5.
- **Config = chat-style exchange** (agent_setup fully rewritten, menu/slide/form/fast-type DELETED): the
  system asks with a model-style bright message that explains + gives the option
  ("which provider? (press enter for openai)"), then a "> " user prompt captures the typed answer in normal
  gray; Enter accepts. Empty agent answer defaults to "openai". Then "paste your api key:" -> "> ". Flows
  below the banner, no absolute positioning. HW-verified render (keyless 256K screenshot): banner + question
  + prompt read as one terminal. Interactive drive (typing/echo/connect) still needs the user at the VM.
- Loading glyphs (show_load_marker boot calls) removed from main.inc + hardware_setup. NB show_load_marker
  itself + the load marker are STILL used by (a) hardware_setup's adapter_select_phase (the NIC-selection
  centered menu -- a SECOND old-style menu not yet terminalized) and (b) failure_action. Terminalizing the
  NIC adapter menu + failure screen is remaining unification work.

## Config-as-chat REFINED (2026-07-03, HW-verified flow): numbered list + validation
agent_setup now: normal-color (0x07) messages (not bright -- bright is banner-only); the agent field is a
NUMBERED LIST ("which provider?" / "1. openai") built from agent_ids/agent_count; the user types a number
(1..count) OR the full name (strcmp), anything else -> "incorrect option" + re-prompt; a blank line sits
between each message and its "> " prompt. Then "paste your api key:" (free text). HW-verified the exact
flow on a keyless 256K boot: `> 3` -> "incorrect option" -> re-prompt -> `> 1` -> "paste your api key:" ->
`>`. No default (removed). CORE.SYS 3c5cef0d. Reads as one terminal, top to bottom. Remaining nicety: a
visible input cursor while typing (echoed text shows, no block cursor).

## Config + failure REFINED again (2026-07-03): colors, DPI-style submit, terminal failure
- User-typed input is now BRIGHT WHITE (0x0f); agent messages normal (0x07); system/error messages DIM
  (0x08, "dark style" -- NO red-message type, per user; red stays banner-only). On Enter the config erases
  the "> " marker (DPI-style .submit_line) so the submitted line reads as the user's message; a blank line
  separates turns.
- "incorrect option" is a DIM system message (was briefly red), then re-prompt.
- FAILURE SCREEN TERMINALIZED (failure_action.inc rewritten): on a setup/connect failure -> dim system
  error line ("agent setup failed" + dim net code NN/NN) then the agent asks "retry or restart?" as a
  terminal list (1. retry / 2. restart); a single keypress 1/2 acts (1=retry->ret->hal_start, 2=reboot),
  other keys ignored. No centered menu / arrow-toggle / absolute positioning. Flows below in the terminal.
  Fit the 1-sector phase by using a single-key read (not the full line editor). CORE.SYS 15520721.
- Explained the earlier "dark failed3": it was the config key prompt echoing STRAY-typed input in the old
  dim color -- now white. NOT a system message.
- NB the failure prompt keeps "> 1" (single-key, no "> "-erase) -- minor inconsistency vs the config's
  DPI-style submit; erase would need the save/restore code (didn't fit the sector). Revisit if wanted.

## Failure screen + system-message polish (2026-07-03)
- System messages are "> "-prefixed + dim (like the chat), with a BLANK line before the following agent
  message: config "> incorrect option" and failure "> agent setup failed NN/NN".
- Key question shortened to "api key:" (no clipboard on a PC).
- Fixed the orphaned dim " failed": on reconnect exhaustion agent_endpoint drew " failed" unconditionally,
  but the "> reconnect" prefix is mid-chat-only -- so a cold setup showed a bare " failed". Now gated on
  chat_context_used != 0 (cold stays silent; CF=1 exhaustion signal kept for the fatal-screen path).
- Failure retry/restart bug: .option_line called .newline (clobbers al = the digit) before printing it, so
  the numbers showed as garbage (")"). Fixed by saving al across .newline.
- Failure retry/restart now behaves EXACTLY like the provider list: numbered ("1. retry"/"2. restart"),
  type a number OR the full name, Enter; invalid -> "> incorrect option", re-prompt (full line editor,
  DPI-style "> " erase, white input). Needed the space, so failure_action is now a 2-SECTOR phase
  (core.asm times 1024 / %if>1024; rare error phase, +1 floppy sector). CORE.SYS 7c79f1d4.

## Remaining UI work
- Terminalize the NIC adapter-select menu (hardware_setup adapter_select_phase -- still centered/blink) and
  the failure screen (failure_action) the same way; then show_load_marker can be fully retired.
- Boot-progress "> " lines now UNBLOCKED (banner is early): the boot phases can print "> net" / "> connect"
  etc. below the banner, persistent (no more wipe). Cheap (phase-local strings + resident print_char).
- Config: a visible input cursor during typing (currently the echoed text shows, no block cursor); dynamic
  option listing (list agent_ids) if more providers return; endpoint prompt for local agents (wired, untested).

## Already landed this session (kept)
- Provider menu: duplicate-option bug fixed (full-width clear on re-render); typed key now normal-gray
  (render_text_input uses 0x07). These stay regardless of the rewrite.

## Verification note
Synthetic Enter into the boot menu via the harness (pidkeycode) is unreliable — the first keypress is
dropped and it can't be driven cleanly. Boot/banner/greeting states (no input) ARE self-verifiable via
`--oracle-only` screenshots. Interactive config verification needs the user at the VM (or a reliable
key-injection method — TBD). One 86Box at a time; the keyless-boot test = build a floppy WITHOUT USER.CFG
(cp over build/.../floppy-160k.img; `make` restores it).
