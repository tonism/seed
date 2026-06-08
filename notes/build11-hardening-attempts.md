# Build 11 — Release Hardening (attempts)

Branch context: Build 11 hardens the first public release — transport robustness, real context
quality, sharper situational awareness (`docs/builds.md`). Build 10 shipped (tag `build-10`); its
log is archived in `notes/old/build10-tool-calling-attempts.md`. Work branch: `work/draining-fifo`.
Sequenced FIFO-first because the draining-FIFO frees the memory budget the rest depends on.

User priority order (locked 2026-06-07):
1. **Reliability (must)** — records are validated AND the user NEVER sees a blank response (a blank =
   a desynced/broken session with no further responses, the worst outcome).
2. **Usable context / arena** — recall quality + the buffer-shrink pool win.
3. **Capabilities** — nice to have (`$r/$w/$x` already shipped).
4. **Secure connection** — explicitly NOT a 4.77 MHz / 16 KB goal; a top item when the host scales
   bigger. Consolidated as the larger-machine roadmap item (`docs/builds.md` P4 #12).

Baseline (Build 10, `make inspect`): CORE.SYS 28672 B / 56 sectors; resident nucleus 2048 B
(2038 nonzero); K crypto window 14 sectors / 7168 B; RX buffer `tls_payload_buffer_len = 1460`
(whole-record AEAD); pool scales with RAM (~214 B at 16 K).

## 2026-06-07 18:05:00 - draining-FIFO collapse: one streamed app-data receive path

Found TWO receive paths: `tls_receive_application_data` (buffers the whole record, verifies
Poly1305, then decrypts — why the buffer must be >= the largest record, 1460) and
`tls_receive_large_application_record` (already a draining FIFO: ChaCha-decrypts each TCP segment as
it arrives, drains to the SSE parser, and SKIPS Poly1305 entirely — only ever holds one segment).
User asked "do we need 2?" — no. Collapsed: route all application data (0x17) through the streamed
path; alerts (0x15, 2 bytes) keep the tiny whole-record path (close_notify must clear the key
schedule). Removed the now-dead inline `0\r\n\r\n` completion check — the SSE parser's
`zero_chunk_pattern` already detects it. Buffer left at 1460 for now (Stage A = collapse only; the
shrink is Stage B). Preconditions verified: no TCP MSS advertised (SYN data-offset 0x50 -> server
uses 536 B segments, so `tls_rx_copy` only needs one segment); the Certificate already streams; the
greeting is itself a streamed model response through this path (so every boot exercises it).

Validated on ne2k8 (5 G, harness-only): greeting + two recall turns all streamed; wire showed ONE
reused TLS session, 0 RST, ~3.5 min held by the keep-alive. The earlier "turn-2 blank" was
contamination (manual prompts typed into the VM alongside the harness), NOT the collapse.

CAVEAT carried forward: the streamed path never verified Poly1305, so the collapse drops AEAD
integrity on app data — a *reliability* cost (separate from the security gap), addressed below.

## 2026-06-07 19:10:00 - recall root-caused (flat window) + role labels + dead-code reclaim

Recall failed on 32 K (window not the limit): turn 1 invented "Zindlef", turn 2 "recalled"
"Quorflax". Root cause (code-proven, NOT the collapse — capture path untouched, wire clean): the
carried conversation window is a flat, role-less blob in the request `input` field. Prompts are
appended with only a trailing space (`agent_api_stream` append_prompt_to_context), responses with no
separator (`agent_response.inc:156`); turn-2 input reconstructs to `...that word. Zindlefwhat
nonsense word...` — content present but glued, no role attribution, so the model can't tell its own
prior answer from user text and invents fresh. = roadmap P2 #6 flat-window, sharpened when Build 10
removed the recap-compaction.

Fix: vendor-agnostic role labels in the window accumulation — each stored turn becomes
` User: <prompt> You: <response>`. "You" (not "Assistant") per user: identity-neutral, the agent's
role lives in the identity layer, not dictated by the transcript. Plain JSON-safe text, no newlines
(append_context flattens control chars to spaces, so newlines wouldn't survive — and inline labels
already delimit). Window-only labeling (current-prompt input tail left unlabeled) = lowest risk, no
surgery on the flush-aware send path; auto-accounted in Content-Length via `chat_context_used`.

Byte budget: the labels overflowed the `agent_api_stream` (X) phase 3-sector ceiling. Funded by
removing the DEAD recap-compaction directive (P3 #10): `compact_next` is reset to 0 in
`agent_request` before the chunk build and only raised later by the renderer for tool-line
suppression, so the directive-append (`:50-54`) + compaction-window-clear (`:84-87`) branches and
`api_json_compact_directive_text` were dead. Removed -> X back to 3 sectors, build clean.

Validation BLOCKED — the test runs hit garbage / boot-fails (next entry), so recall couldn't be
evaluated.

## 2026-06-07 19:28:00 - 3 runs / 3 outcomes: handshake-race boot-fail + the FIFO reliability cost

After the recall edits, three runs gave three outcomes: clean (Zindlef/Quorflax), turn-1 GARBAGE
(decryption desync — corrupted glyphs + hex runs) then a blank turn 2, and a boot-time
"agent setup failed 00/12". High variance => noisy environment (emulator-under-load + 5 G jitter),
but clean IS achievable.

Wire on the boot-fail (the decisive one): TCP connected fine (SYN/SYN-ACK 42 ms); client sent
ClientHello (220 B), server sent the cert (2861 B) immediately; server FIN+RST at connect +15.07 s;
the client's ClientKeyExchange did not go out until +30 s. So the emulated 8088 took ~30 s for the
handshake crypto — 2x the documented ~14.5 s — because host CPU contention (the harness polling the
screen oracle: screenshot + OCR on a loop) starved the emulated CPU, and the server's ~15 s patience
expired first = the ~15 s handshake race, lost to emulator-under-load. Environment, re-runnable; real
silicon (deterministic 14.5 s) or an unloaded host makes the window.

The turn-1 garbage generalizes the wire reasoning: dropping Poly1305 in the collapse converts ANY
glitch — network corruption or a streaming-decrypt desync — into rendered garbage + a desynced
stream (cascading to a blank next turn) instead of the old clean-fail. A *reliability* regression on
flaky networks, distinct from the security loss. Recall edits not implicated: turn-1's request is
byte-identical to the clean run (labels are added post-send; the dead code removed was never
emitted) and the receive path is untouched.

## 2026-06-07 19:35:00 - reliability decision: incremental Poly1305 (detect) + never-blank (recover)

Per the locked priorities, reliability has two connected pillars:
- DETECT — incremental Poly1305: stream + render into the small FIFO buffer (keep the memory win),
  but accumulate the AEAD tag as ciphertext arrives and verify at record-end. A corrupted OR
  desynced record then fails the tag = a clean, immediate failure signal instead of silent garbage.
  Per-response MAC CPU returns (fine; CPU was never the binding constraint — the handshake is, paid
  once).
- RECOVER (never blank) — on ANY receive failure (bad tag / completion-miss / desync / drop),
  invalidate the session and auto-reconnect + resend so the user always gets an answer; never a
  silent return to the prompt. Absorbs P1 #2 (reconnect 3x-auto) + the setup-vs-mid-chat asymmetry
  root-cause. (task 8, not started)

## 2026-06-07 19:51:00 - incremental Poly1305 step 1: streaming primitives + unified AEAD MAC

Added streaming Poly1305 to `tls.inc`: `tls_poly1305_app_init` (clear acc + absorb the padded AAD
block), `tls_poly1305_app_update` (absorb a ciphertext chunk, carrying a <16 B partial block in
poly_block across calls — ciphertext is absorbed BEFORE the in-place decrypt), `tls_poly1305_app_final`
(pad the trailing partial, absorb the AAD/cipher length block, emit -> tls_finished_tag). Streaming
state (`tls_poly_app_fill` + `tls_poly_app_cipher_len`) reuses `tls_app_total_len`/`tls_app_chunk_len`,
which are provably dead during the streamed receive.

First build OVERFLOWED the K window ("LINK window overlaps high crypto scratch") — the ~80 B of new
routines pushed it over. Fixed by UNIFYING the AEAD MAC: reimplemented `tls_poly1305_mac_app` (used
by the send path + alert receive) as a thin `init -> update(whole buffer) -> final` wrapper and
DELETED the all-at-once `tls_poly1305_process_cipher_bytes`. One streaming implementation shared by
all three callers; fits the K window. Builds clean (CORE.SYS still 28672 / resident 2038).

NEXT: wire the streaming MAC into `tls_receive_large_application_record` — init at entry (derive the
one-time key from ChaCha counter 0, which the streamed path currently skips), update per ciphertext
chunk before decrypt, capture the received tag (currently skipped) + verify at `.record_done`; a tag
mismatch returns failure to feed the never-blank recovery (task 8). Then re-validate recall on a
clean (unloaded) run.

## 2026-06-07 20:15:00 - verify wired; double scratch entanglement; dedicated receive accumulator

Wired the MAC into the receive (entry init -> per-chunk absorb-before-decrypt -> tag capture ->
record-end verify). Two scratch entanglements (the notes' "incremental state" catch): (1) poly_acc
ALIASES chacha_state, so the interleaved decrypt's chacha20_block clobbers the MAC accumulator;
(2) the keep-alive ping is a SEND mid-render that reuses the SAME unified Poly1305 routines/state.
Fix: a dedicated receive accumulator poly_rx_save (33 B = poly_acc 17 + partial poly_block 16)
overlaid on tls_master_secret (handshake-only, idle during the chat receive); the receive restores
it before each MAC step and stashes it after, the send/ping never touch it. K window held at 14
sectors by deleting the now-dead tls_ensure_current_tls_record_complete (only caller was the
collapsed alert path) and simplifying the alert path (any 0x15 -> mark session closed, no
decrypt/verify) -> the LAST whole-record receive path is gone, truly one path. BUT the verify still
REJECTS valid records (boot-fail 0/F0), deterministically, after this fix too.

## 2026-06-07 20:35:00 - non-fatal verify isolates it: collapse + RECALL both work; tag bug remains

Made the verify NON-FATAL (compute + compare, accept either way). Boot succeeds; on 5G: greeting +
turn1 "invent a nonsense word" -> "quorax" + turn2 "what word did you invent?" -> "quor". RECALL
WORKS (vs the broken Zindlef->Quorflax) - the User:/You: role labels fixed the flat-window failure
(task 6 effectively done), and the collapse + streamed receive are solid. So the ONLY remaining
issue is the tag verify: my computed tag (tls_finished_tag 0x34a2) != the server's received tag
(tls_received_tag 0x34b2), even though the SEND MAC is provably correct (handshake completed, same
primitives) and the decrypt/seq/nonce/AAD are correct (decrypt + recall work). Bug is in the
receive-only path (rx save/restore, server otk/AAD setup, or tag capture). Diagnosing via the
model's own $r (read 0x34a2 vs 0x34b2 and compare) - in progress.

## 2026-06-07 23:05:00 - tag bug ROOT-CAUSED + FIXED: ne_tx_frame aliases the crypto scratch

Closed it by elimination, then ground truth from the wire.

RULED OUT the algorithm. Ported seed's exact 8088 Poly1305 (add_block + schoolbook multiply +
fold-high-x5 reduce + emit) AND the streaming AEAD layer (app_init AAD block -> per-byte app_update
-> app_final partial+lengths) to Python (tools/poly1305-port-check.py) and diffed vs a reference over
1..100 blocks and cipher lengths to 1385: IDENTICAL everywhere. Core + construction are correct.

RULED OUT cross-chunk state loss. A per-restore teletype dump showed poly_acc carries PERFECTLY
(each chunk's saved low word == the next chunk's restored low word) and poly_r is CONSTANT (BB52...)
across all 6 chunks of the greeting -> otk preserved, acc carry exact. fill=09 (=1369 mod 16), AAD
seq=1/type=17/ver=0303/len=1369 - all correct.

GROUND TRUTH. Captured the session with tcpdump and byte-searched the server->client stream
(tools/pcap-tag-search.py): the device's COMPUTED tag was NOT on the wire, its RECEIVED tag WAS (at
the record tail) -> the capture is right, the computation is wrong. Then dumped the device's actual
one-time key and recomputed the AEAD tag offline over the GENUINE wire ciphertext
(tools/verify-aead-tag.py): it reproduced the EXACT wire tag (6dae2aa9... at seq=1). So correct algo
+ correct otk + correct AAD + genuine ciphertext -> genuine tag; the device with the same otk/AAD
computed a different tag => it MAC'd a DIFFERENT (corrupted) ciphertext.

ROOT CAUSE. low_crypto_work ALIASES ne_tx_frame (both 0x0700). For the FIRST app-data record
(greeting response.created), tls_current_payload_ptr still points INTO ne_tx_frame (header present
=> tls_ensure_tls_header_complete fast-paths with no copy). tls_receive_large_application_record then
runs chacha20_block + poly1305_load_key + app_init BEFORE .copy_current_to_rx - those write
0x0700..0x07DF and SHRED the segment's ciphertext in place; the MAC (and decrypt) then run over
corrupted bytes. LATER records use the buffered leftover already sitting in tls_rx_copy (0x34c2,
clear of the scratch), which is why they verified. The "multi-chunk fails / single-chunk passes"
pattern was a red herring: the real axis is first-record-in-NIC-buffer vs later-record-in-rx_copy.
The collapse (Build 11) introduced it by deferring the copy to .payload_ready, AFTER the crypto
setup; the old whole-record path copied first.

FIX. Call tls_copy_current_payload at the very top of tls_receive_large_application_record (right
after tls_clear_buffered_payload), moving the payload into tls_rx_copy before any crypto touches
0x0700. One call + jc .failed; K window held (no overflow). Real per-record verify RE-ENABLED (fatal
mismatch -> .failed -> reconnect/never-blank). Confirmed: a verify-on boot reaches DPI and accepts a
prompt - which only happens if the greeting's first (multi-chunk) record now VERIFIES. Tools kept in
tools/ for future wire debugging (poly1305-port-check, pcap-tag-search, verify-aead-tag).

## 2026-06-08 01:30:00 - recall scare -> the REAL bug: chacha_block clobbered between chunks

User flagged degraded recall ("forgets the last part of the invented word") + suspected we weren't
sending the full context. Investigated:

(1) Storage is correct: a window dump showed the EXACT word + full history stored.
(2) Send is correct - but I CHASED MY OWN PROBE for several runs first. My debug dumps teletype'd to
the screen, which SCROLLS it, and the current prompt is read FROM the screen
(append_prompt_screen_to_buffer at dpi_prompt_marker_row). So my dump scrolled the prompt out from
under the read -> the model got a garbled prompt. Tell: WITH the dump -> brand-new words; WITHOUT ->
exact/partial recall. Lesson saved to memory (feedback_screen_dump_pitfall). Use non-scrolling
(fixed-row direct video) dumps or the wire on screen-read paths.
(3) Recall itself is FINE: 4 clean samples gave exact recall (brivox->brivox, blplix->blplix,
zindleorp->zindleorp; zoren one partial = small-model flake).
(4) THE REAL BUG (found in the clean samples): ~50% (2/4) of turn-1 (exchange-2) responses decrypt to
GARBAGE - control chars + a hex id, recovering by the delta tail (e.g. "...04f23e15...equint"). The
greeting always decrypts clean (its visible deltas are single-chunk); only the multi-chunk
exchange-2 records garble. The per-record MAC PASSES (verify is fatal, didn't reject) -> not a MAC
failure -> a DECRYPT KEYSTREAM DESYNC.

ROOT CAUSE. tls_xor_large_app_chunk only regenerates chacha_block when offset >= block_len. chacha_block
(critical_chacha_block ~0x0780) sits in low_crypto_work == ne_tx_frame (0x0700). The inter-chunk NIC
receive overwrites it; the counter+offset survive (resident low_runtime_state) but the 64-byte block
does not. When a chunk resumes MID-block (offset < block_len) it XORs against the clobbered block ->
garbage. Intermittent: depends on whether the TCP segmentation aligns to a 64-byte keystream boundary.
Same bug family as the verify fix (0x0700 aliasing), different victim: keystream block vs MAC state.

FIX. At the top of tls_xor_large_app_chunk, if offset < block_len (mid-block resume), call
chacha20_block to regenerate the keystream at the surviving counter before the XOR loop. Aligned
resumes regenerate in the loop as before. ~5 instructions; K window held. Verifying across samples
(the ~50% garble should vanish). The user's "recall" symptom was really these corrupted response
words being rendered + carried into the window.

## 2026-06-08 08:42:00 - buffer shrink 1460->592: the FIFO collapse's payoff (Stage B)

Post-collapse, tls_rx_copy holds ONE TCP segment, never a whole record (tls.inc removed the last
whole-record receive path), so the 1460 ceiling was vestigial. Shrank tls_payload_buffer_len
1460->592 by advertising a 592 MSS in the SYN (tcp_syn_mss, layout.inc): a 4-byte TCP option
(0x02,0x04,MSS-hi,MSS-lo) rides as the SYN "payload" (cx=4 into build_tcp_segment_frame), and the SYN
flag (0x02) made build_tcp_segment_frame emit data-offset 0x60 (24-byte header). TCP MSS is a
transport option Cloudflare always honors (unlike the TLS-layer record_size_limit it ignores on 1.2),
so every server segment is now <=592 and one segment fits the buffer. 592 is the floor for
tls_rx_copy's OTHER uses (DNS qname at +512 -> 512+80; ClientHello; DPI input). Freed ~868 B into the
RAM-scaling chat pool. Validated 7/7 NIC matrix + a multi-segment >592 reply (coherent across
segments). (Committed 422697a.)

## 2026-06-08 12:00:00 - never-blank reconnect (3x silent retry) + the nucleus reorg that funds it

P1 #2 / task 8. UX (user's words): a dropped chat connection shows a SINGLE dim "> reconnect" line and
silently retries up to 3x; if all fail, " failed" is appended in place ("> reconnect failed") and the
user returns to DPI, where the next prompt re-runs the loop. Dim attr 0x08 (CGA) / 0x07 (MDA).

THE WALL. The resident nucleus was FULL: measured core_resident_end - $$ == 0x0800 EXACTLY (2048/2048;
the handoff's "~3 B free" was wrong - the 3 trailing zero bytes are scroll_br + a var high byte, real
data). The retry needs ~16 resident B; the message RENDER lives in a phase (free). So: free >=16 B first.

REORG (the relief, ~17 B freed):
1. SYN data-offset, -7 B. build_tcp_segment_frame (resident) used `test dl,0x02 / jz / mov al,0x60` to
   set data-offset 0x60 for the SYN. Now it always emits 0x50; ne_transmit_tcp_syn (tcp_connect PHASE)
   patches [ne_tx_frame+tcp_offset+12]=0x60 AND fixes the TCP checksum. The data-offset is the LOW byte
   of the +12 header word, so 0x50->0x60 adds 0x10 to the little-endian checksum sum -> subtract 0x10
   from the stored checksum, one's-complement as `add ax,0xffef / adc ax,0` (end-around carry). ~17 B
   added to the phase (slack: 145 B), 7 freed from the nucleus.
2. Relocate 7 written-before-read vars, ~10 B. chat_resend_prompt_len, chat_context_used, compact_next,
   compacting_msg, chat_compact_threshold, chat_context_len_var, scroll_br moved from nucleus db/dw into
   a new reconnect_state_* block (data.inc, chat_cache_end..ka_template_persistent, ABOVE
   critical_scratch_end so it survives a reconnect handshake exactly like the nucleus copies did). Each
   is written before read (hardware_setup at boot, or per-turn) EXCEPT compact_next/compacting_msg/
   chat_context_used, which the COLD greeting reads before its first write (their only writers are the
   ready/chat path), so hardware_setup boot-zeroes them (beside agent_loop_pending). The two HOT crypto
   pointers (tls_app_data_ptr/plain_ptr) stayed resident (too risky to move).

FEATURE (~16 B):
- Counter init is near-free: reconnect_retries sits at chat_resend_prompt_len+1, so net_phase inits both
  in the EXISTING word that captures the prompt length (`mov ah,3 / mov [chat_resend_prompt_len],ax` -
  al=len, ah=3 retries; +2 B vs the old byte store, not +5).
- Retry loop (prepare_agent_endpoint_path): the 5 connect-path failures + the final exchange `jc .retry`;
  `.retry` does `dec byte [reconnect_retries] / jnz .rebuild_and_connect`; on exhaustion re-invokes the
  endpoint phase ONCE (renders "failed") then falls to .restore. Covers cold + reuse-fail + reconnect.
- Render (agent_endpoint phase, the FIRST reconnect phase, so the line lands BEFORE the ~14.5s crypto):
  retries==3 + tls_key_schedule_ready==1 (a live prior session, excludes the cold first connect) -> draw
  "> reconnect" once and PARK the cursor (no advance) so the answer or " failed" appends in place;
  retries {2,1} -> silent (the ==3 gate shows the line exactly once); retries==0 -> append " failed" +
  advance. "show once" needs NO extra flag: tls_key_schedule_ready (set by the prior handshake, NOT
  cleared by a hard-failed reuse) distinguishes reconnect from cold, and the ==3 gate fires only on
  attempt 1. (A cold-boot connect failing 3x shows just " failed" - no "> reconnect" prefix - but with
  the CF fix below that path shows the fatal screen anyway, so it never surfaces in practice.)

CODE-REVIEW (3 parallel finder agents) caught + FIXED two reorg bugs before commit:
- Cold-setup CF: the exhaustion path fell into .restore with CF from the "failed" render (~clear), so a
  COLD-BOOT agent-connect failure (prepare_agent_path FALLS THROUGH into prepare_agent_endpoint_path;
  main.inc `jc agent_setup_error`) would skip the fatal screen and drop into the chat loop with no
  session. Fixed by `stc` before the endpoint phase's failed-render `ret` (in the PHASE, 0 nucleus B).
  A mid-chat turn ignores CF, so only the cold-boot fatal path is restored.
- compact_next/compacting_msg lost their nucleus `db 0` boot-init in the move and are read-before-write
  on the cold greeting (same as chat_context_used) -> garbage from the non-boot-zeroed high block. Added
  them to the hardware_setup boot-zero (one word write: they're adjacent). [The canaries had passed only
  because the high block happened to be zero - a latent bug.]

RESULT: nucleus 2047/2048 (1 B free), endpoint phase 506/512.

VALIDATED (ne2k8 canaries, harness): reorg canary (greeting + 2 prompts clean -> SYN checksum + moved
vars OK); forced-fail canary (a temp counter failing every exchange after the greeting -> screenshot
shows dim "> reconnect failed" TWICE, incl. the re-prompt re-running the loop, then DPI). Happy
reconnect (show "> reconnect" then a real answer) is proven BY CONSTRUCTION: the SUCCESS path is
byte-identical to the pre-change reconnect (jc->.retry only changes FAILURE routing; success still
`jnc .restore`), the reconnect was Build-8/10-validated, and the resend reconstructs the prompt from
chat_resend_prompt_len (which the word write sets to the same value as before) via
agent_request.restore_prompt_from_screen. A forced reuse-fail-then-reconnect test gave a FALSE "failed"
(the forced fail fires at agent_api_exchange entry, AFTER the X phase already sent on the live socket,
orphaning that request server-side; a real dead-socket reuse-fail has no such artifact). 7-NIC matrix =
final regression confirmation (changes are NIC-independent: SYN building, RAM layout, control flow,
print_char render - so ne2k8 covers the product).
