# Packet-level TCP retransmit — design review (post-Build-11 robustness, roadmap P4 #14)

Context: Build 11 dropped the redundant boot connectivity probe and leaned boot connectivity on
the agent connect's shared 3x retry (commit 4b1d357). Loss testing then showed the path's two
remaining fragilities are (1) packet loss and (2) the ~0.2s handshake-patience margin. Request-
level retry cannot make a genuinely lossy link robust — it re-runs the whole ~15s handshake per
attempt, so per-attempt success falls off with packet count (~0.97^8 ~= 78%/attempt at 3% loss).
Packet-level retransmit is the principled fix: a dropped packet becomes a ~300ms-1s in-place
resend instead of a ~15s full re-handshake. This note reviews how to build it. NOT Build 11 scope.

## Today's TCP (the starting point)
- SEND (core/net_tx.inc `tcp_send_payload`): build a segment, transmit ONCE, advance tcp_local_seq.
  No copy kept, no ACK tracking, no timer. Fire-and-forget.
- RECEIVE (core/net_rx.inc `parse_tcp_payload`): accept ONLY the in-order segment (seq ==
  tcp_remote_ack), advance the ack, REJECT out-of-order. No reassembly buffer.
- State: tcp_local_seq (our next send seq), tcp_remote_ack (next byte expected from server),
  tcp_source_port_word / tcp_dest_port_word / tcp_target_ip. ne_transmit_tcp_ack sends an ACK.
=> The entire gap is the CLIENT->server direction. The server is a real TCP and already retransmits
   its own losses; the seed just has to drive + wait for that.

## The simplification that makes it tractable
We do NOT need full sliding-window TCP. The seed's flow is send-a-flight -> wait-for-the-response
(ClientHello->ServerHello; CKE->...; request-records->reply). So STOP-AND-WAIT retransmit per flight
suffices:
  Hold the last flight; if the expected response doesn't arrive within an RTO, RESEND the whole
  flight (the server dedups by seq what it already has); bounded retries.
In the simplest form there is NO ACK parsing: the response arriving IS the implicit ACK; an RTO with
no response is the resend trigger. That collapses "implement TCP" into "buffer one flight + a timer +
a resend in the poll loop we already run."

## Two halves, very different costs
RECEIVE (server->client) — ~80% already there:
  A dropped server segment leaves tcp_remote_ack un-advanced, so the seed keeps ACKing the old value
  -> the server retransmits (its RTO, or our dup-ACKs) -> and it resends IN ORDER, which the seed's
  in-order-only handling already copes with. Needs only:
   - bigger wait budget (tcp_payload_wait_count, a constant) so we don't give up before the retransmit;
   - optional dup-ACKs on out-of-order to trigger the server's FAST retransmit vs its full RTO.
SEND (client->server) — the actual work:
   1. A retransmit buffer holding the unacked flight. Handshake flights are tiny (ClientHello ~100B,
      CKE ~70B, CCS+Finished ~40B); the request flight is the big one (~2KB across its records).
   2. An RTO via the BIOS tick (0x046c): stamp on send; in the poll loop resend if tick-sent > RTO.
   3. Resend with the ORIGINAL seq (do NOT re-advance tcp_local_seq) so the server dedups.
   4. Integrate the resend into the EXISTING receive-poll loops (ne_wait_for_tcp_synack,
      tcp_receive_payload, the TLS receives) so the happy path adds NO round-trips -- it only resends
      on real loss.
   TLS is unaffected (it sits above TCP and sees a clean byte stream) -- purely a transport change.

## Costs & hard parts
- RAM: the flight buffer. Handshake-only is a few hundred bytes; including the request flight is ~2KB
  -- competes with the chat arena at the 16KB floor, comfortable at 32KB+ (larger-machine theme).
- Resident bytes: tcp_send_payload + the poll loops are resident; nucleus ~2024/2048 (a little slack
  from the probe removal) but a buffer + logic likely needs a small reorg, or lives partly in the
  K-window/phases.
- Cycles: negligible -- retransmit only fires on loss; happy path adds one buffer-copy per send.
- Handshake-margin interaction: a resend adds ~1 RTO (~1s) on loss, which can tip the ~0.2s handshake-
  patience race -> retransmit and HANDSHAKE-SPEED are complementary (retransmit recovers the loss,
  speed keeps completion inside the server's window AND shrinks the loss-exposure window).

## Verdict: doable, a real but bounded project
Tractable because flight-stop-and-wait fits the seed's send-then-receive rhythm -- "buffer + timer +
resend-in-the-poll-loop," not a TCP rewrite. OUTCOME (Build 11, 2026-06-09):
  1. Receive-wait — NOT built as planned. The receive (server->client) was already resilient at moderate
     loss (server retransmit + the seed's existing wait; boot 4/4 at 5%). REFRAMED as the heavy-loss lever
     (roadmap P4 #16): at 15% the Certificate RECEIVE is the bottleneck (the seed's wait gives up before
     the server's retransmits all land), so a BIGGER receive wait is the real heavy-loss fix.
  2. SYN-retransmit — SHIPPED (156135a): resend the SYN up to 3x with the same port/seq.
  3. Handshake-flight retransmit — SHIPPED: 3a ClientHello (e3c55c8) + 3b CKE+CCS+Finished flight (69799b4,
     held raw in tls_client_hello_buffer, NE/WD). Every handshake client send now retransmits.
  4. Request-flight retransmit — DROPPED (user, 2026-06-09): the reconnect already recovers a dropped
     request, handshake-speed (#15) makes that recovery fast, and it is not worth the ~2KB buffer.
KEY FINDING (loss test, 5% + 15%, netcond + tls-flow.py retransmit counter): the client-retransmit
(2/3a/3b) is correct insurance but NOT the loss bottleneck -- the RECEIVE (download) is. Moderate loss is
handled (server retransmit + the existing wait; 0 client retransmits needed; boot 4/4 @ 5%); heavy loss
(15%) fails in the cert RECEIVE (boot 1/4). The real levers: handshake-SPEED (#15, the observed
patience-race) + a bigger receive wait (#16). See docs/builds.md P4 #14-16.
