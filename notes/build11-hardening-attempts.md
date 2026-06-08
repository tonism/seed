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

## 2026-06-08 14:30:00 - never-blank gating fix (real idle-close) + reconnect failure ROOT-CAUSED on the wire

GATING FIX (committed b078269). The forced-fail test PASSED but masked a bug the AUTHENTIC idle-close
demo caught: "> reconnect" was gated on tls_key_schedule_ready==1, but a real idle-close's TLS
close_notify CLEARS key_ready during the failed reuse, BEFORE the reconnect's endpoint phase -> the
line silently skipped and exhaustion left an orphaned " failed" (no "> reconnect"). The forced test
hard-failed before any close_notify, so it never hit this. Fixed by gating on handoff_status==ready
(we are in the chat loop => a prior session => a reconnect, not the cold greeting); survives the
close_notify, same signal the endpoint phase already uses for provider routing, 0 nucleus B. Re-
validated on a real 470s idle-close: "> reconnect failed" now renders as ONE dim line. Plus the splash
bump build_number 10->11 ("seed build 11" confirmed) and a docs sync. Lesson: "validated" means the
REAL path, not a convenient forced proxy.

RECONNECT-FAILURE ROOT CAUSE (corrects the 2026-06-07 19:28 entry's "CPU starvation" theory). User
watched the emulator on a second screen across THREE runs: it held 99-100% speed the WHOLE time and
the reconnect still failed -> NOT CPU starvation, NOT the OCR loop, NOT macOS background-throttling.
Captured the wire (whole-host pcap is noisy - SLiRP NAT shares the host IP and the VM/host even hit the
same CDN IPs - but the reconnect's 3 attempts to the VM's Cloudflare IP 162.159.140.245, ~28s apart,
were cleanly isolable). Attempt-1 timeline: SYN/SYN-ACK instant; ClientHello (102 B) at +1s; server
ServerHello+Cert (2793 B) at +1s; then the VM emits its handshake records ~7 SECONDS APART (t+553 ->
+560 -> +567) -> those gaps are the 8088 grinding the TLS-PRF (master secret, then key block; SHA-256/
HMAC is the cost); client flight done ~+19s; server FIN ~+20s. All 3 attempts identical -> "> reconnect
failed". So: a GENUINE handshake-too-slow race at FULL 8088 speed - the handshake is ~20s (the docs'
~14.5s was optimistic), the provider's patience (~20s here) runs out. The "~14.5s" + "CPU starvation"
framing is retired: the crypto is simply ~20s, CPU-bound, on a 4.77 MHz part.

ASYMMETRY (initial connect succeeds, mid-chat reconnect fails - the long-standing observation): both
run the IDENTICAL ~20s handshake (the PRF crypto is independent of the request), so it is NOT a Seed-
side speed difference between them - it is a razor-edge race (~20s handshake vs ~20s window) that the
reconnect loses and the initial usually wins. Likely tipping factor: provider patience (a fresh
connection may get slightly more handshake grace than an immediate reconnect from the same IP) or pure
edge variance. Pinning it needs a clean initial-connect capture to compare; OPEN. Also open: whether
the server's final ~1.6 KB-then-FIN means the handshake JUST completed and the exchange then failed vs
a pure timeout (needs TLS-record-type parsing). The real FIX to make reconnect SUCCEED is a faster
handshake (optimize PRF/SHA-256 or cut a round-trip) - a perf work-item, not a quick patch; never-blank
covers the symptom gracefully meanwhile.

## 2026-06-08 17:30:00 - warm-up attempt (GET-ping) FAILED - the fresh connection RSTs the ping

Implemented the warm-up: agent_api_warmup_reconnect helper (link window, 0 nucleus) that, gated to
mid-chat (handoff_status==ready), sends the keep-alive GET ping + drains its 401, called from net_phase
after tls_probe (before .stream_and_exchange); freed the 3 net_phase bytes by relocating tls_app_data_ptr
/tls_app_plain_ptr STORAGE into reconnect_state_* (nucleus 2046/2048). Built clean. Tested a real 470s
idle-close reconnect: STILL "> reconnect failed". Wire (port 65488 -> 162.159.140.245, by TCP seq):
  ClientHello -> ServerHello+Cert -> CKE(seq103) -> CCS+Finished(seq178) -> server CCS+Finished
  seq221 VM 298B   (request prefix)
  seq519 VM 63B    (the 42B GET ping)
  seq2838 SERVER RST  (no response at all)
TWO problems: (1) the ping went AFTER the prefix (seq 519 > 221) - the warm-up did NOT prepend as
intended (gate skipped it, or a flow bug - unresolved). (2) MORE FUNDAMENTAL: the GET ping got NO 401
- the server RST'd the connection with no data. So a bare "GET /" on a FRESH connection is REJECTED
(RST), even though the SAME ping 401s fine on a WARM connection (keep-alive) and the boot's valid POST
greeting is accepted on its fresh connection. => the warm-up cannot use the GET ping; it needs a VALID
small POST to prove a fresh connection (a deeper change - a real minimal request whose response must be
drained/suppressed), OR the fix is to speed up the real request itself (PRF/ChaCha/Poly perf, or fewer
records) so it beats the fresh-connection timeout without warming. The GET-ping warm-up is a dead end.
Note also: the warm-up made it WORSE on the wire (RST+nothing vs the pre-warm-up FIN+1.6KB), so it must
not ship as-is. Reverted (kept the committed never-blank graceful "> reconnect failed" + re-prompt).
The reconnect-SUCCESS fix needs a fresh focused session; never-blank remains the shipped safety net.

## 2026-06-08 18:00:00 - CORRECTION: the send is ~2.4s back-to-back (NOT ~5s/3s-gap); mechanism = fresh-connection STRICT first-request timeout

Read the actual send path (agent_api_stream.inc .ready_tail -> .stream_chunk2 -> .send_tail) to chase
the "~3s gap between records" the 15:30 entry claimed. The code DISPROVES it: the 4 records are sent
BACK-TO-BACK via .send_app_record (build -> tls_send_application_data_current_seq) with NOTHING between
them - no wait_ticks, no phase load. The only post-send delays are AFTER the last record: the optional
"> compacting context" typewriter (wait_ticks, compaction turns only) and the response-phase floppy
load (load_core_sectors_at). So the reconnect request takes ~2.4s (4 x ~0.6s per-record ChaCha/Poly) -
EXACTLY the warm-reuse timing (949-1015 B over 2.2-2.4s, 16:30 entry), which SUCCEEDS. The "~3s apart /
~5s+ total" in the 15:30 entry was a pcap MISREAD (likely handshake PRF gaps or mis-grouped records).
=> The failure is NOT "the send is too slow" - the warm path sends the identical ~2.4s request fine.
The real mechanism (consistent with all data): a FRESH connection's FIRST request has a STRICT timeout
(< ~2.4s); the tiny boot greeting (no context, well under 1s) fits and "proves" the connection, after
which big requests get the lenient warm timeout. The reconnect's first request is the big ~2.4s context
request -> exceeds the strict fresh-first timeout -> server errors/FIN/RST. IMPLICATIONS for the fix:
(a) request-speed (user's preferred) would need to get the big request UNDER the strict fresh timeout -
i.e. roughly halve ~2.4s - a ~2x ChaCha/Poly speedup, large effort, likely not viable as a quick win;
(b) the warm-up (small valid FIRST request to prove the connection, like the greeting) is the right
shape, BUT it must be a VALID minimal POST - the bare GET keep-alive ping is RST'd by a fresh connection
(17:30 entry) - and its response must be drained. Best done in a fresh focused session that opens with
ONE clean VM-isolated capture to re-confirm the strict-first-timeout mechanism before building on it.

## 2026-06-08 18:45:00 - warm-up RE-ATTEMPT hits the BYTE WALL; correct architecture = warm-up INSIDE the X phase

Re-implemented the GET-ping warm-up (agent_api_warmup_reconnect: gate on handoff_status==ready, save
tls_app_len/total/plain_ptr, send ka ping, drain its 401 via tls_receive_application_data, ack, restore)
called from net_phase after tls_probe. Does NOT BUILD: BOTH regions are full (core.asm:39 "resident
nucleus exceeds the 2KB window" from the 3B net_phase call AND core.asm:72 "LINK window overlaps high
crypto scratch" from the ~50B helper). Reverted (tree builds, nucleus 2043). Two things learned:

1. handoff_status flips to ready at main.inc:54 BEFORE chat_loop, so it's true for EVERY chat_loop fresh
   connect (greeting + reconnect) - it does NOT distinguish them. The gate is fine (greeting tolerates a
   warm-up ping) but it is NOT "reconnect-only".
2. The prior (reverted) warm-up's ping went SECOND on the wire (prefix at seq221, ping at seq519) even
   though net_phase calls it BEFORE .stream_and_exchange and tls_send transmits immediately (tls.inc:824
   build->tcp_send_payload, no buffering). That means the helper's ping-send did NOT execute before the
   X phase on the reconnect - an unexplained control-flow/state issue with the separate-call structure.

CORRECT ARCHITECTURE (fresh session, sidesteps BOTH the byte wall placement AND the ordering mystery):
put the warm-up (ping + drain) at the START of the X phase's .ready_tail (agent_api_stream.inc:27),
BEFORE the prefix send. This GUARANTEES ping-before-prefix (sequential, same phase - no separate-call
timing) and reuses the phase's send/receive machinery. Gate it on a FRESH-CONNECTION flag in
low_phase_state (0 nucleus B): set it in the fresh-path-only run_tcp_connect_phase (or tls_probe), read
+ clear it at .ready_tail (so a warm reuse, which skips tcp_connect, never warms). Budget: the X phase
is a tight 3-sector overlay (~24B was golfed to fit the Build-10 loop) so ~40B of warm-up may need it to
grow to 4 sectors (check the load window) OR more golf. The net_phase-call approach needs a nucleus
reorg (relocate the hot tls_app_data_ptr/tls_app_plain_ptr to reconnect_state_*, +4B) AND ~50B freed
from the crypto window (no clean relief per the golf scan) - so the X-phase placement is preferred.

STILL UNVERIFIED (verify FIRST, before any of the above): does a FRESH connection accept the GET /v1
ka ping (quick 401, proving the connection) or RST it? The boot greeting is an authed POST and IS
accepted; the GET ping's fate on a fresh connection was never cleanly captured (the prior test had the
big request going first). If the GET ping is RST'd, the warm-up must build a small authed POST instead.
Open the fresh session with ONE clean VM-isolated reconnect capture that sends the ping FIRST.

## 2026-06-08 20:30:00 - X-phase warm-up BUILT + VM-tested: TWO blockers (multi-record 4xx drain + path)

Built the warm-up INSIDE the X phase (agent_api_stream .ready_tail), gated on a reconnect_warm_pending
flag set by tcp_reopen_cached_target (low_phase_state). Builds clean (nucleus untouched, 2043; the ~49B
fit the X-phase overlay). VM-tested on ne2k8 (premise pre-verified by curl: GET /v1 -> 404 + keep-alive,
NOT RST). Findings from the wire (162.159.140.245, gap+IP isolation; host SLiRP noise filtered):

GATED (Test A): NO warm-up ping before the greeting request (330B@t+15) -> the flag did not fire on the
fresh greeting (clobber or path; reconnect_warm_pending lands ~0x0F00 area, the X phase loads 0x0900-
0x0F00, so the X-phase LOAD may clobber a flag SET before it - agent_loop_pending survives only because
it is set AFTER the load, never tested across it). Effectively a no-op -> reconnect still failed.

UNCONDITIONAL (Test B, gate removed to isolate code-vs-flag): the warm-up ping fired on the REUSE turn
(63B@t+71.3 -> SRV 337 + 23) but STILL NOT on the greeting (330B@t+15, no ping) - an unresolved PATH
puzzle (both paths reach .ready_tail with handoff_status==ready, yet only reuse warmed). And the REUSE
then RECONNECTED: the 4xx response is TWO records (337 + 23B) and the warm-up's SINGLE
tls_receive_application_data drains only the 337, leaving the 23B -> the stream desyncs -> the next
receive fails -> reconnect. This is the SAME under-drain the keep-alive has (agent_api.inc .success
".drain_one" does one receive per ping and "Under-drain self-heals via the reuse->reconnect path") -
the keep-alive TOLERATES it by reconnecting, but a warm-up CANNOT (reconnecting is what it exists to
avoid). User watching live confirmed: quick back-and-forth produced a fast reconnect (the unconditional
warm-up desyncing the warm reuse) - correctly NOT product behaviour; reverted to never-blank.

TWO BLOCKERS for the warm-up, both needing careful fresh-session work:
  1. ROBUST DRAIN: the warm-up must FULLY consume the multi-record 4xx (loop tls_receive_application_data
     until the SSE zero-chunk sets api_stream_completed==3, like agent_api_exchange's main loop, with a
     stream-state reset before+after) - a single receive under-drains -> desync. ~25-30B in a tight phase.
  2. PATH/FLAG: the warm-up fired on reuse but not the fresh greeting (the OPPOSITE of what's needed -
     fresh is exactly where it must fire). Resolve why .ready_tail's warm-up runs on reuse but not the
     fresh path, and put the flag in load-safe memory (e.g. the reconnect_state high-scratch block, not
     low_phase_state which the X-phase load region overlaps).

SIMPLER ALTERNATIVE to weigh: DEFER-CONTEXT. On a reconnect, send the request WITHOUT the carried window
(greeting-sized) -> fits the strict fresh-first-request timeout (the boot greeting PROVES a small request
succeeds on a fresh connection) -> normal SSE response (drained by the existing machinery, no special
drain, no ping, no path puzzle). Cost: that one post-reconnect turn loses conversation context (recovers
next turn on the now-warm connection). Sidesteps BOTH warm-up blockers; the trade-off is context, which
is exactly what the warm-up was trying to preserve. A product call for the user.

## 2026-06-08 19:05:00 - PREMISE VERIFIED (curl): a fresh connection ACCEPTS the GET ping (4xx + keep-alive), NOT RST

Probed the provider directly with the EXACT seed ping on a fresh connection (real TLS, HTTP/1.1, no auth):
  curl --http1.1 -isS https://api.openai.com/v1  ->  HTTP/1.1 404 Not Found  + "Connection: keep-alive"
  curl --http1.1 -isS https://api.openai.com/    ->  HTTP/1.1 421 Misdirected + "Connection: keep-alive"
So the server returns a QUICK 4xx and KEEPS THE CONNECTION ALIVE - it does NOT RST a bare GET on a fresh
connection. This DISPROVES the 17:30/18:45 "fresh connection RSTs the GET ping" claim: that RST was the
big-request timeout in the mis-ordered warm-up test, never the ping. => the warm-up can use the GET ka
ping AS-IS (no authed-POST build needed). HTTP-layer response is decided post-handshake, and the seed's
handshake completes (boot greeting works), so the seed's ping should get the same 404+keep-alive.
Two caveats for the build's VM validation: (a) curl uses modern TLS; Cloudflare *could* fingerprint the
seed's weak TLS differently - but the handshake completing argues against it. (b) the 404 sets __cf_bm /
_cfuvid cookies; the seed does not echo cookies, so if Cloudflare's first-request-timeout relaxation is
cookie-based (not connection/TCP-based) the ping might not relax the big request's timeout. The SUFFICIENCY
(does ping-first actually let the big request beat the strict timeout?) is the one thing curl can't test -
it is the VM validation when the X-phase warm-up is built. Net: GET-ping warm-up is GO; build it next.

## 2026-06-08 15:30:00 - reconnect failure RE-ROOT-CAUSED on the wire (TLS records): NOT the handshake - the slow request

CORRECTION of the entry just above (and the old CPU-starvation theory). User escalated reconnect to
CRITICAL: walk away -> idle close -> every reconnect fails -> stuck. Parsed the TLS RECORD TYPES off
the captured wire (tools-style python at /tmp/tls_flow.py, reconnect connection = port 64147 ->
162.159.140.245, the SAME IP the boot used at port 64084). Both the boot AND the reconnect handshake
COMPLETE: ClientHello -> ServerHello+Cert -> ClientKeyExchange -> CCS+Finished, and the SERVER sends
its own CCS+Finished back (= it accepted the session). So it is NOT a handshake race; the ~7s gaps are
the PRF but the handshake finishes (~15s) and is accepted on BOTH paths.

The failure is the APPLICATION exchange AFTER the handshake. The request is split into 4 TLS app
records (agent_api_stream .stream_chunk2: instructions / ledger+input-open / context+prompt+close,
because api_request_plain caps the plaintext at 440 B), each built + ChaCha20-Poly1305-encrypted +
sent sequentially -> on the wire the request records come out ~3s apart (~5s+ total for the bigger
reconnect request). The fresh server gives the first request ~5s, then returns a ~1.6 KB error and
FINs - WHILE the VM is still transmitting (168 B + 100 B go out AFTER the server FIN). You cannot get
a valid chat answer to an incomplete request, so the ~1.6 KB is an error/timeout, not a response.
Compare the boot: tiny greeting request (no context) sent fast -> server streams ~10 KB back. So the
ASYMMETRY is resolved: boot request tiny -> fits the read-timeout; reconnect request big (carries the
whole conversation context) -> too slow -> server times out. Same handshake on both. (Implies long-
conversation REUSE turns trend toward the same edge as the context grows.)

The lever is the per-record crypto (ChaCha20-Poly1305; Poly1305's 130-bit multiply is the likely hot
spot on the 8088, and it is also hot on the Build-11 per-record receive verify). FIX OPTIONS (open,
user to steer - meaty perf with trade-offs): (a) confirm the per-record bottleneck (encrypt vs JSON
build) by instrumenting the send, then optimize the hot op; (b) send the request in FEWER/bigger TLS
records (cuts per-record overhead + round-trips) - helps if overhead dominates, not if it is per-byte;
(c) optimize ChaCha20/Poly1305 inner loops (broadest - helps send AND receive verify, biggest effort);
(d) pragmatic: on reconnect resend a SMALLER request (trim/drop context) so it beats the timeout, at
the cost of carried context. never-blank still covers the symptom while this is worked.

## 2026-06-08 16:30:00 - warm-vs-fresh CONFIRMED on the wire; fix = warm the reconnect with a small first request

User escalated reconnect to CRITICAL (walk-away -> stuck) and proposed: send a small request first to
"prove" the fresh connection, then the big real request. Validated the underlying hypothesis directly
with a no-idle REUSE capture (/tmp/seed-reuse.pcap, VM session port 64797 -> 162.159.140.245, parsed
TLS record bursts). Result, on ONE reused connection:
  boot greeting:  330 B request (no context) -> 9328 B response   [small first request -> OK]
  say apple:      949 B req over 2.2s -> 8327 B response          [warm: big req OK]
  say banana:     977 B req over 2.4s -> 9197 B response          [warm: big req OK]
  say cherry:    1015 B req over 2.4s -> 9799 B response over 30.9s [warm: big req + 30s stream OK]
So a WARM connection handles the very ~1 KB request the fresh reconnect FIN'd at ~5s, and tolerates
30s+ streamed responses. The asymmetry is fully explained: BOOT's FIRST request is the tiny greeting
(no context) -> fits the strict fresh-connection (anti-slowloris) timeout -> the connection becomes
"proven" and every later big request gets the lenient timeout. RECONNECT's FIRST request is the big
context request -> exceeds the strict fresh timeout -> FIN. (So it was never the handshake NOR the
absolute request size - it is the strict timeout on a fresh connection's FIRST request.)

FIX (chosen direction, user's idea, confirmed): on a reconnect, after the handshake, send a small
first request (reuse the keep-alive GET ping, ka_template_persistent / ka_request_len) and FULLY drain
its 401/421, THEN send the real big request on the now-proven connection - exactly mirroring the boot's
greeting-first pattern. Placement: net_phase reconnect path (after tls_probe, before .stream_and_
exchange), gated to mid-chat (handoff_status==ready) so cold boot stays fast. Cost: ~10-28 resident B
(gate + ping-send + one-receive drain) -> needs another small nucleus reorg; the drain is one
tls_receive_application_data (the keep-alive drains a ping response in one receive). NOT yet implemented.

## 2026-06-08 21:15:00 - RECONNECT FIXED: it was a chunk-1 DOUBLE-SEND, not a timeout (wire-proven)

Fresh session, "continue the warm-up". Traced the send architecture end-to-end BEFORE building it - the
warm-up premise collapsed, and a clean capture then found the REAL bug. Reconnect now SUCCEEDS.

ARCHITECTURE (corrects the handoff). The cold greeting does NOT reach the X phase .ready_tail: at
greeting time handoff_status is not yet ready (main.inc sets it AFTER prepare_agent_path returns), so the
X phase takes the SPLASH branch, which sends nothing. The greeting's request is shipped by the HANDSHAKE
itself - tls_probe_server prebuilds it and sends it via tls_send_prebuilt_after_server_finished right
after the client Finished. Only READY turns (reuse + reconnect) reach .ready_tail. So the greeting was an
INVALID warm-up test proxy: the "path puzzle" (warm-up fired on reuse but not the greeting) was simply
that the greeting never reaches .ready_tail; and tcp_reopen_cached_target is the reconnect-ONLY signal
(cold uses tcp_connect_target; reuse skips connect). A warm-up at .ready_tail is also architecturally too
late on a reconnect: the POST headers (chunk 1) already rode the handshake prebuilt before .ready_tail
loads, so a ping there injects mid-request.

CAPTURE (user chose "capture a reconnect first" over building). Authentic 470s idle-close reconnect on
ne2k8 @ 32K; whole-host pcap filtered to the provider IP; parsed with a new tools/tls-flow.py (pure-
stdlib TCP reassembly + TLS-record walk, both directions, timestamped). The failing reconnect's client
AppData records were [293, 293, 400, 163, 101] - chunk 1 (293 B = POST line + Host + Authorization +
Content-Length + {"model") sent TWICE: once as the handshake prebuilt (t+14.88, right after the server
Finished), then AGAIN by .ready_tail (t+17.7) because tls_app_len was still set. The server read the
duplicate "POST ..." as the first request's BODY, returned a 400 (a 1244 B record) + Alert + FIN. All 3
never-blank retries identical. DECISIVE: the server sent its CCS+Finished in every attempt -> the
HANDSHAKE WAS ACCEPTED. So it is NOT a handshake race and NOT a fresh-connection request timeout (both
theories retired) - it is a DETERMINISTIC double-send, which fits "reconnect almost always fails" far
better than any race. Greeting sends chunk 1 ONCE (prebuilt only; splash; no .ready_tail) -> works; reuse
sends chunk 1 ONCE (.ready_tail only; no handshake) -> works; only RECONNECT did both -> 400.

FIX (6 B, K-window slack, resident nucleus untouched at 2048 B). `mov word [tls_app_len], 0` at
tls_probe_server.done - all 3 NIC app-send paths converge there, after the prebuilt send. .ready_tail
then sees tls_app_len==0, skips the chunk-1 prefix, and streams only chunk 2 + context + prompt - i.e.
the reconnect's send becomes byte-identical to the proven REUSE path. Reuse never runs tls_probe
(untouched); the cold greeting takes the splash branch (never reads tls_app_len) and the receive resets
it regardless, so the clear is harmless on both. (The old net_phase "Do NOT reset tls_app_len here ... no
answer" comment was a DIFFERENT experiment that also zeroed chat_prompt_len_cache, which skips the prompt
send - not evidence against clearing tls_app_len alone.)

VALIDATED (ne2k8, authentic idle-close, wire + screen). Same 470s idle reconnect: client AppData now
[293, 400, 163, 101] - chunk 1 ONCE - and the server replies with a real ~8 KB SSE stream (1385/1385/
1263/253/...) instead of 400+FIN. Screen: the dim "> reconnect" line followed by the answer "4", then the
DPI prompt - so never-blank's "> reconnect" became a brief honest status before the REAL answer rather
than "> reconnect failed". 7-NIC matrix (boot+greeting, the cold-path regression surface for the
tls_probe.done change): 6/7 first pass + 3c503 2/3 on a focused re-run (the fails are the documented
3c501/3c503-on-5G boot flake, not the fix; the cold path is NIC-common and unchanged in shape). The
entire warm-up line of work (GET-ping, defer-context, the byte-wall placements) is now moot - there was
no timeout to defeat. Tool tools/tls-flow.py kept for future reconnect wire analysis. (Committed af2cbb9.)

## 2026-06-09 - drop the redundant boot connectivity probe (+ NET.CFG); loss-vs-latency wire findings

User asked to UNIFY the retry logic rather than add a second one (a boot-time 3x beside the mid-chat 3x).
Tracing it: the agent-connect retry is ALREADY shared - boot and mid-chat both run prepare_agent_endpoint_
path, whose .retry/.rebuild_and_connect loop (reconnect_retries=3) wraps endpoint+client_hello+cache+
tcp_connect+tls_probe+exchange, and it runs on the cold greeting too (the "> reconnect" line is gated to
handoff_status==ready, so it stays silent at boot). So the boot's agent connect already retries 3x; the
ONLY un-retried network step was prepare_internet_path's port-80 connectivity probe.

That probe (a single-shot TCP connect to NET.CFG's "probe example.com") was redundant + harmful: it tested
the WRONG host+port (example.com:80, not the agent's api.openai.com:443), so it could FALSE-FAIL when the
agent was reachable but example.com was not; it had no retry (the dominant spotty-network boot failure,
"network setup failed 0C/10"); and the agent connect already proves real connectivity with the 3x retry.
DELETED it entirely - the probe call, the net_probe_cfg phase, NET.CFG, and its FAT parser. Verified safe:
seed_endpoint is owned by agent_setup (AGENTS.CFG) / user_cfg (USER.CFG), NOT NET.CFG (probe_cfg's write
is transient + overwritten + only fed the probe, and the endpoint phase uses it only for 'l'-prefixed
custom agents, never OpenAI/Anthropic/Google); the probe's FAT helpers were phase-local; the build already
treated NET.CFG as optional (wildcard). Frees ~19 resident/nucleus bytes (nonzero 2043->2024) + a whole
phase + NET.CFG. Build clean, phase table auto-recomputed (--check passes).

LOSS TESTING (macOS dummynet via tools/netcond.sh, scoped to the provider's Cloudflare ranges; on 5G):
- 8% loss, pre-removal: 0/4, "network setup failed 0C/10" = the un-retried probe. Post-removal: 0/4, now
  "agent setup failed" - the failure correctly MOVED off the probe to the real agent connect.
- 3% loss + 150ms delay, post-removal: 0/3, "agent setup failed 0D/12" (net_status 0x12 = tcp_connected,
  net_error_tls). A pcap (tools/tls-flow.py) showed the decisive detail: EVERY handshake record arrived
  (no loss that run); the client's CCS+Finished landed at t+15.46s and the server FIN'd at t+15.35s - it
  missed by 0.1s. The ~7.5s gap between CKE (t+7.9s) and CCS+Finished is the 8088 grinding the master-
  secret + key-block PRF; the +150ms delay slowed the round-trips ~0.6s and pushed a borderline ~14.8s
  handshake (which just made it on clean 5G - server accepted at 14.86s) past the server's ~15.3s patience.

So there are TWO orthogonal fragilities, and neither is the probe (now gone) nor a regression:
  1. LOSS - every un-retransmitted client send (SYN/handshake records/request records) is a single point
     of failure; request-level retry re-runs the whole ~15s handshake per attempt, so it papers over LOW
     loss (~0.97^8 ~= 78%/attempt at 3%, ~99% in 3 tries) but cannot make a genuinely lossy link robust.
     The principled fix is packet-level retransmit (P4 #14) - a dropped packet becomes a ~300ms in-place
     resend, not a ~15s re-handshake.
  2. HANDSHAKE MARGIN - the ~15s handshake sits ~0.2s inside the server's ~15s patience, so any latency
     spike tips it. The fix is handshake SPEED (faster PRF/SHA-256), which also shrinks the loss window.
Both are deliberate post-Build-11 robustness work (roadmap P4 #14 + a handshake-speed item); the +150ms
netcond delay is satellite/bad-cellular latency, not home wifi, so it over-states the real envelope. The
probe removal is a clean win regardless and ships in Build 11.
