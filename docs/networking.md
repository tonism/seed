# Networking And NIC Transport Contract

This documents the behavioral contracts the boot core must honor when reaching a
provider over the TLS 1.2 ChaCha20-Poly1305 path: the shared transport rules that
apply to every adapter, and the per-NIC carve-outs that exist because of real
hardware differences. These are durable behavioral requirements, not status notes.
The lane-validation history and per-card evidence behind these contracts are
recorded in `docs/builds.md` (the Build 6 and Build 8 checkpoints).

## Shared transport rules

These hold for every supported adapter:

- **Large-record completion.** Always decrypt and scan a large TLS application
  record to its end. Do not fast-drain it: a terminal HTTP zero chunk
  (`0\r\n\r\n`) or an SSE completion marker can be bundled into a large
  `response.completed` record, and fast-draining drops the completion signal and
  stalls the loop.
- **Completion marker.** Treat the transport zero chunk and the
  `response.completed` / `*_text.done` SSE marker as completion. Do not rely on a
  contiguous `output_text.done` alone — a provider can split the event name across
  TLS records — so key on `response.completed` as the semantic marker.
- **Session reuse.** Reuse the live keep-alive TLS session for follow-up prompts.
  Do not force a fresh handshake per follow-up; a reconnect immediately after a
  long stream races the provider's reconnect window. Reconnect and resend only
  when a real close/stale condition is seen.
- **Text-seen fallback.** On a receive or ACK failure *after* response text has
  already rendered, accept the rendered answer and invalidate the session rather
  than reconnecting mid-exchange. A mid-exchange reconnect's full handshake races
  the provider window and surfaces a connect/handshake error for an answer the
  user already read.
- **Durable prompt tail.** Hold the prompt tail in memory that TLS setup cannot
  overwrite, so it survives a reconnect-and-resend.
- **Chunked request (Build 9).** Send the provider request as several TLS application
  records (headers+model / instructions+ledger / conversation+prompt). When the
  conversation+prompt would overflow the send buffer, flush across further records rather
  than truncating — one HTTP request, more TLS records, transparent to the adapter.
- **Receive-buffer floor (Build 10).** The TLS receive buffer must hold the largest
  application record whole — AEAD decrypts a record as a unit. A streamed response batches
  into records far larger than one MSS, and Cloudflare honors neither `max_fragment_length`
  (RFC 6066) nor `record_size_limit` (RFC 8449) on TLS 1.2, so the client cannot negotiate a
  smaller cap. The buffer therefore stays MSS-sized (1460 B) — the floor for receiving a
  streamed answer at all, and the reason the pool can't reclaim it. See `docs/builds.md`
  (Build 10).

## Per-NIC contracts

### 3Com 3c501 (el1, single-buffer)

The most constrained adapter and the source of most carve-outs, because the el1 is
a single-buffer card.

- Send ClientKeyExchange before the expensive PRF and key-block work.
- Keep the prebuilt application-frame path separate from the other adapters.
- Prepare the receive latch around post-prompt sends (the stable path prepares the
  3c501 receive latch before and after the ready-tail application-data send).
- Use render-before-ACK during active chat once response text has started: the
  single-buffer card must not acknowledge a long text stream faster than the 8088
  renderer can consume it. Cold greeting, setup, and pre-text metadata still use
  ACK-before-render.

### 3Com 3c503 (DP8390)

- Keep the request phase loaded away from the HTTP body scratch; the enlarged
  ready-request builder must not execute from a region it overwrites.
- Use the pre-server-Finished application-data send path. Moving the send to after
  server Finished regressed into server FIN/RST races.
- Do not force split-body sending for short prompts: prompts at or below
  `api_ready_short_prompt_max` inline the whole request when it fits; longer
  prompts use the split lane.
- Metadata records may ACK before rendering; once response text has started, use
  render-before-ACK.
- Oversized TLS application records can carry real output text — chunk-decrypt and
  parse them and preserve the following TLS record tails; do not blanket
  fast-drain.

### NE1000 / NE2000 (and Novell NE1000)

- After response text has started, use render-before-ACK pacing for long
  responses.
- NE2000 has the strongest focused validation evidence of this family.
- Treat Novell NE1000 as a separate verification target; do not assume NE2000
  evidence covers it until it passes the focused gates.

### WD8003 (WD8003E / WD8003EB)

- Use the ACK-before-render shape. Global delayed-ACK experiments regressed
  WD8003E.
- Treat WD8003E and WD8003EB as related but verify both independently; one passing
  does not certify the other.

## Why the carve-outs exist

The shared rules above cover the DP8390-class cards (NE1000/NE2000 and 3c503) and
WD8003. The 3c501 is the outlier: its el1 single-buffer hardware forces the
render-before-ACK pacing and the receive-latch handling. The remaining per-NIC
branches in the boot core are therefore hardware-driven; most of the behavioral
carve-outs are 3c501's. Reducing that surface — folding carve-outs back into the
shared path where a card allows it — is tracked as a roadmap investigation in
`docs/builds.md`. A per-card rule may only be retired once a documented shared
replacement rule and cross-NIC evidence exist; see `docs/builds.md` for the
validation history and the unification investigation.
