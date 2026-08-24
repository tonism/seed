# Networking And NIC Transport Contract

Seed's one current provider route is OpenAI over TLS 1.3 and HTTP/1.1. The
runtime selects the 8088 or 286 conforming TLS profile from the same
`SEED.SYS`; NIC transport behavior remains behind one resident vtable.

The two TLS routes make different security claims, documented in
[`security.md`](security.md). A NIC success proves packet transport, not the
security tier by itself.

## Shared transport rules

These rules hold for every supported adapter:

- **Cold-load before timing.** Read and validate the required TLS phase or 286
  pack before opening the timed connection. A reconnect may read the
  write-protected floppy first, then opens a wholly fresh socket. No TLS path
  writes temporary state to disk.
- **Large-record completion.** Decrypt, authenticate, and scan every
  application record to its end. A terminal HTTP zero chunk or SSE completion
  event may share a large record with output text; fast-draining can discard
  the only completion signal.
- **Completion marker.** Treat the HTTP terminal chunk and the
  `response.completed` / `*_text.done` events as completion. Event names may
  cross TLS-record boundaries, so do not depend on one contiguous
  `output_text.done` literal.
- **Session reuse.** Keep a successfully committed TLS session open for
  follow-up prompts. Do not pay a fresh hybrid exchange per turn.
- **Credential quarantine.** Before either route commits, only its literal
  credential-free HEAD probe may enter application records. On the 8088
  profile, the fresh connection must authenticate its HEAD response and
  tentative ticket. After offline proof, the resumed connection sends the
  same HEAD after Finished with no early data and must authenticate its
  response before credential publication. API credentials, prompts, context,
  cookies, redirects, and tool continuations remain unreachable. On the 286,
  the authenticated acquisition ticket remains tentative until offline full
  FO/X.509/CV proof, then the final no-0RTT PSK-DHE resumption must complete.
  Tentative and promoted tickets remain same-boot RAM state.
- **Text-seen fallback.** If receive or ACK handling fails after output text
  has rendered, accept the visible answer and retire the channel. Never replay
  a partially visible answer automatically.
- **Durable human prompt.** Keep the submitted human prompt in memory that TLS
  setup cannot overwrite. It must survive one fresh reconnect and exact
  request reconstruction.
- **No tool replay.** A tool/agent-loop continuation is never automatically
  reconnected and resent; doing so could duplicate a local effect.
- **Chunked request.** Send one HTTP request over as many TLS application
  records as needed. Never truncate the conversation or prompt because the
  current record buffer is full.
- **Bounded receive.** The product TLS 1.3 receive path authenticates records
  incrementally and rejects record, plaintext, spool, sequence, and pointer
  overflow before copying. Keep transport reads within the active NIC's
  advertised sample and ring bounds.
- **Key and sequence retirement.** Every close, parse failure, bad tag,
  interrupted phase load, or route failure invalidates both directions'
  traffic keys, IVs, sequence numbers, pending ticket status, and application
  readiness before returning to UI or setup.

## Bounded same-request reconnect

Reconnect is deliberately one attempt, not a general retry loop:

```text
human request, no response text
  -> retire failed channel
  -> cold-load/rebuild one fresh tier route
  -> reconstruct the same durable prompt from the screen
  -> send that request exactly once
  -> success, or retire and return failure

response text already visible
  -> accept text, retire channel, no replay

tool/agent-loop continuation
  -> retire channel, no replay
```

The fresh route repeats all tier-specific cryptographic gates. No ticket,
same-boot pin, or “reconnect” flag can bypass authentication. The offline
replay contract is gated by `tools/check-tls13-product-reconnect.py`; live
acceptance also requires pcap proof on the exact CPU/RAM floors.

## Per-NIC contracts

### 3Com 3c501

The 3c501 is the single-buffer outlier.

- Keep its prebuilt-frame and receive-latch paths separate.
- Prepare the receive latch around application sends.
- Reject truncated TCP payloads and never ACK bytes not fully retained.
- Once response text starts, render before ACK so the card cannot be
  overwritten faster than the 8088 can display the text.
- Treat cold TLS setup, liveness, and normal application exchange as separate
  validation lanes; passing one does not imply the others.

### 3Com 3c503

- Keep request/controller code outside the HTTP body and record scratch it
  overwrites.
- Metadata may ACK before render; after response text starts, render before
  ACK.
- Preserve following TLS-record tails when a large record is streamed and
  parsed.

### NE1000 / NE2000 and Novell NE1000

- After response text begins, use render-before-ACK pacing for long replies.
- The 16 KiB TLS route uses conventional system RAM only. No product path may
  assume an NE adapter or borrow packet pages or display RAM for crypto state.
- Treat NE1000, NE2000, and Novell NE1000 as separate original-speed gates.

### WD80x3

- Keep ACK-before-render behavior where the existing family path requires it;
  global delayed-ACK changes have regressed WD8003E.
- Keep the shared-memory aperture enabled before DP8390 access.
- Use family-specific ring bounds: 8 KiB WD8003 cards use pages
  `0x06..0x1f`; the 16 KiB WD8013 profile uses `0x06..0x3f`.
- Validate WD8003E, WD8003EB, and WD8013 independently.

### Later ISA and PCI families

PCnet/LANCE, DEC Tulip, RTL8139, and EPIC/100 remain external `.DRV` families
behind the same vtable and shared TLS application contract. Their larger
machine profiles do not authorize a separate provider, TLS version, or boot
artifact. Each family still needs its own cold TLS, first response, reuse,
bounded reconnect, and long-render gates.

## Why the carve-outs exist

Most supported early cards share DP8390-style ring behavior. The 3c501's
single packet buffer and some WD shared-memory details require hardware-specific
pacing and aperture rules. Those branches may be retired only after a common
replacement passes the full original-speed NIC matrix.

The TLS implementation itself must not acquire NIC-family state. Its only
transport authority is the resident vtable plus bounded TCP send/receive/close
callbacks. This is what lets one TLS architecture run across the complete
driver set and keeps inactive adapters out of the 16 KiB resident budget.
