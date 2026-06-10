# Build 11 #4 — Real LLM Compaction: REDESIGN spec (fresh-session brief)

Self-contained. A fresh session should be able to implement from THIS file + the code. The long
debugging session that produced it is not needed.

## Goal
Replace the Build-10 raw byte-trim (drop-oldest-to-25%) with a model-MAINTAINED compact note, so a
16K-RAM conversation keeps key facts instead of losing the oldest bytes. (At 32K+ the window is
~8.5 KB and compaction rarely fires; 16K is the case that matters. Window is ~532 B at 16K.)

## What was tried and WHY IT FAILED — do not repeat
First attempt = a 2-pass loop + a short "summarize" directive. Mechanically sound, but the SUMMARY is
the problem. Tested hard (16K passcode + neutral-codename recall; on-screen summary dump; wire):
- Given the conversation as ONE "input" blob + a short directive, the model CONTINUES the conversation
  (re-answers the last turn — a non-sequitur) and emits VERBOSE free-form prose (a topic recap) that
  dominates the next turn. Small user facts (a passcode, a tool name) get dropped -> recall fails.
- VARIABLE: one run extracted correctly ("Your tool is named zephyr." + correct recall); most recapped
  the dominant topic. Viable but unreliable.
- NOT clipping: the fact reaches the model (verified by an on-screen dump of the exact request window).
  It is the summary QUALITY, not the request content.
- CF bug (already fixed, do not reintroduce): `.pass_done` used `cmp byte [compacting_msg],1` on the
  SUCCESS path; cmp borrows on 0 -> CF=1 -> `.restore` (pushf/popf) returned failure though the exchange
  succeeded (greeting rendered, then "agent setup failed"). Fix = `test byte [compacting_msg],0xff` /
  `jnz .pass` (TEST clears CF). Lesson: nothing between a success `jnc` and the shared CF-preserving
  `.restore` may touch CF.

## The redesign (AGREED)
1. FLOW (already built): window(excluding the new prompt) >= 75% (chat_compact_threshold) -> show the
   "compacting" system message -> compaction request (NO user prompt, NO identity, NO ledger) -> wipe
   the window, replace with the model's note -> THEN the normal turn (identity + ledger + note + prompt).
2. FLOPPY-STREAMED STATIC PROMPTS. identity + compaction-sysprompt are STATIC -> put them in a file on
   the floppy and stream them into the TLS record during the request build. `fs.inc` (FAT reader) is
   RESIDENT, so it can read mid-chat. Floppy has tons of room (160 KB; CORE.SYS ~27 KB). This frees
   ~600-800 RAM bytes AND removes the prompt-length cap (the reason the detailed contract didn't fit).
   - Normal chunk 2  = prefix + [floppy: identity] + [RAM: ledger] + input-open
   - Compaction chunk2= prefix + [floppy: compaction-sysprompt] + [dynamic char targets] + input-open
   - Dynamic parts (ledger, window) stay in RAM. Per-turn cost: one short floppy read (~tens of ms,
     negligible vs the ~15 s handshake); keep it off the keep-alive ping timing.
3. HARDWARE-AGNOSTIC — HARD REQUIREMENT. Static prompts MUST NEVER name the hardware ("IBM PC", "8088",
   "the PC you run on", "until reboot"). A future ARM port reuses them verbatim. Reword the identity's
   RAM-tools text machine-generically (e.g. "reach all memory including the running code; a bad write or
   jump hangs the machine"). Applies to ALL static prompt text, not just #4.
4. STRUCTURED WINDOW = NOTE + DIALOGUE.
   - NOTE  = terse labeled fields, inline (the window flattens newlines): "goal: ...; facts: ...;
     state: ...; open: ...".
   - DIALOGUE = verbatim recent turns (" User: <p> You: <r> ..."), appended AFTER the note.
   - EMERGES from the existing replace-window-with-the-compaction-reply + append-turn mechanics — little
     new seed code. The note is just the front of the window; turns append after it.
   - Future compaction: the model sees the PRIOR note (carries facts forward + reinforces the field
     format) + the new dialogue -> outputs the UPDATED note. The verbatim dialogue tail is the SAFETY
     NET: real recent turns mean the model answers the actual question even on a bad-extraction turn (no
     non-sequitur).
5. COMPACTION SYSPROMPT = static CONTRACT (NO worked example — examples bleed into real notes; schema
   only) + dynamic TARGETS.
   - CONTRACT (floppy, hardware-agnostic), schema + rules only:
       "You keep a compact running note. Input: the current note (if any), then recent dialogue. Output
        ONLY the updated note, EXACTLY this shape:
        goal: <one line: what the user wants done>
        facts: <user-stated specifics - names, ids, numbers, values - verbatim, '; '-separated, or ->
        state: <facts you established: addresses, results - or ->
        open: <unresolved or next - or ->
        Copy every prior fact forward verbatim; add new ones from the dialogue; omit anything already in
        the ledger; be terse; output only the note."
   - DYNAMIC TARGETS (seed-computed, appended after the contract, in CHARACTERS — model does no byte
     math): "Target about <N> characters, at most <M>." with N = window/4 (25%), M = window/2 (50%).
     The seed already has chat_effective_cap = M (the hard capture cap); N is the quarter. Render N,M as
     decimals (.append_u16_decimal exists).
6. VERIFICATION: on-screen request-window dump + un-suppressed summary (debug toggles, see below) + wire
   (tools/tls-flow.py <pcap> <ip-substr>, e.g. 172.66 / 162.159). Test recipe: 16K, establish a NEUTRAL
   fact (a codename, NOT a passcode — the model's safety reflex confounds passcodes), fill past 75%,
   recall it. "invisible compaction" recipe in docs/testing.md.

## SEPARATE issue (NOT #4)
Reconnect slowness: compaction's extra round-trip keeps hitting the ~15 s handshake-margin (the server
intermittently Alert+FINs after a response; the reconnect handshake races the server's ~15 s patience
and often loses -> 12 client flight-retransmits over 29 s -> RST). Makes compaction turns crawl
(>10 min/3 turns in tests). This is the handshake-speed / reconnect-reliability item — orthogonal,
tackle separately. Reuse itself works (one connection held 357 s / 14 requests).

## Current code state — uncommitted working tree, branch work/draining-fifo. KEEP as the base.
- core/net_phase.inc: 2-pass loop (.pass / .pass_done) + the CF fix (test/jnz).
- phases/agent_request.inc: compacting_msg decision (window >= chat_compact_threshold in
  .build_ready_openai_request) + chat_effective_cap set (full / halved) + compute_ready_body_lengths
  compaction branch (prefix + directive instructions; no identity/ledger; no input-prompt).
- phases/agent_api_stream.inc: chunk-2 split into api_json_reasoning_prefix + api_json_identity_text;
  compaction sends prefix + api_compaction_directive_text (instructions) + input-open (skips
  identity/ledger); chunk-3 sends the window alone for compaction; append_prompt_to_context resets the
  window for compaction. The directive string MOVES to the floppy + becomes the contract.
- phases/agent_response.inc: emit_char capture (cap at chat_effective_cap; .set_seen_ret suppress +
  text_seen) + the completion golf (api_stream_completed = 3 - tls_key_schedule_ready).
- core/data.inc: chat_effective_cap (in the reconnect_state block). phases/hardware_setup.inc:
  chat_effective_cap boot init (= chat_context_len_var). identity has self-mod warning TRIMMED (debug) —
  moot, it's being reworded + moved to floppy.

## Build order (fresh session)
(a) Floppy-stream the static prompts: add a prompt file to the floppy image (Makefile) + FAT-read-and-
    stream it in the request build (chunk 2). Frees the byte budget; do this FIRST.
(b) Rewrite the identity hardware-agnostic.
(c) Compaction sysprompt = the contract (no example) + the seed-appended dynamic char targets (N=¼, M=½).
(d) Confirm NOTE/DIALOGUE emerges + recall works at 16K (on-screen dump + wire). Then 7-NIC re-validate.
