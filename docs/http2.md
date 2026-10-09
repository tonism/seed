# HTTP/2 application transport

Seed's OpenAI route advertises only `h2` through TLS ALPN. Both CPU routes use
one HTTP/2 connection for successive Responses requests. There is no HTTP/1
fallback and no dependency on the provider honoring `record_size_limit`.
The implementation passes the original-speed functional acceptance for the
16 KiB, 32 KiB and 286/512 KiB paths, including the seven-profile ISA NIC matrix.
[The campaign ledger](optimization-campaign.md) binds the source, captures and
reviewed answers; physical entropy validation remains separate.

After client Finished, the credential-free liveness exchange sends the fixed
HTTP/2 preface and SETTINGS: dynamic table size zero, push disabled, initial
stream receive window zero and decoded header-list limit 4,096 bytes. The
protected peer SETTINGS and acknowledgement of Seed's SETTINGS must complete
before route publication. Fresh acquisition also requires a bounded authenticated
NewSessionTicket. The 286 final route retains its ticket requirement. No stream,
Authorization header, prompt or tool result is opened before full route commit.
The key-establishment distinctions in [security.md](security.md) are unchanged.

A request opens one odd-numbered stream with literal HPACK fields, then sends
JSON through the peer's stream and connection windows. It preserves the source
while waiting for credit and limits each TLS plaintext send to 436 bytes so
Ethernet/IP/TCP/TLS framing still fits the 512-byte packet scratch. After request
END_STREAM it grants 512 response bytes at a time. Authenticated control replies
are drained before receiving more response DATA. The transport acknowledges
complete short TCP payloads before waiting for a new payload; otherwise several
small WINDOW_UPDATE records can exhaust the peer's TCP window.

The receiver accepts a complete legal TLS content record without allocating a
whole-record plaintext spool. Before authentication, fixed-work code keeps
bounded tentative DATA and control journals and a snapshot of parser state.
No display, context, tool, HPACK decoding or protocol reply uses tentative
contents. Whole-record authentication and inner-type checks precede journal
publication. Invalid records discard tentative state. Peer DATA beyond the
advertised window, oversized retained controls or unsupported header geometry
fail closed. Full-record and equal-geometry forged-input gates check these
boundaries; emulator traces do not establish physical timing resistance.

After authentication, a shared parser validates frames, settings, credit,
HPACK/Huffman fields, status, content length and trailers. The Responses parser
sees authenticated DATA only. Success requires both `response.completed` and
HTTP/2 END_STREAM. A captured function call remains unexecuted until both
conditions hold. A failed human request with no visible output gets one fresh
route and one resend; a partially rendered reply or executed tool continuation
is never replayed. Exhaustion returns a visible failure and a usable prompt.
Every tool continuation carries the originating human request with its user
label. Response and tool-status scrolling update that request's display row
before later serialization reads it again.
Older completed results use the bounded native journal described in
[architecture](architecture.md#demo-a-tool-called-request); the current call
and output retain their structured representation. Requests limit the provider
to one function call at a time, and the final budgeted output requests a text
answer with tools disabled.

All transport state remains in conventional RAM. The 16 KiB user arena and
context each remain 96 bytes. Ordinary application ownership is:

| Range | Owner |
| --- | --- |
| `062e..0684` | H2 connection/reply state and resident unwind anchor |
| `1800..2800` | K application crypto/collector, replaced temporarily by post-tag parser |
| `2800..2a00` | request helper |
| `2a00..2c00` | response owner |
| `2c00..2e00` | completed native-result journal helper |
| `2e00..2e70` | live and tentative collector state |
| `2e70..3070` | authenticated DATA, or immutable request-source sector |
| `3070..3570` | control journal |
| `3570..35bc` | HPACK state |
| `35bc..35fd` | saved receive MAC state |
| `3600..3b9c` | keys, record buffers and request work |

The post-tag parser occupies existing K-slot padding plus the unused tail of
S's second sector. The low transition restores K or unwinds to an intact
resident frame after a partial read. A separate six-sector cold NST phase
uses formerly reserved cold-pack sectors; ordinary tickets cannot overwrite
native-tool state. The 286 reuses the same parser through a one-sector adapter
loaded after Finished. These are phases inside the same flat `SEED.SYS`.

The 32 KiB route caches its ordinary loop and assets, but H2 parser transitions
currently still read the floppy. This repair does not claim a floppy-free turn.
Cold NST cleanup preserves the direct-tier root shadow/trampoline below
`7a40`. The 286 reconnect parent reconstructs a pending human prompt from its
ordinary screen text before escrow, since transport retirement clears the
temporary input buffer. Executed/pending tools cannot enter that restoration.

`make` runs the product composition in
`tools/crypto-bench/tls13-product/run_http2_gates.py`; its independent peer
checks real encrypted requests and responses, disk-failure unwinds, window
backpressure, compaction, retries, native effects, far context and erasure.
Use `check_live_h2_case.py` to bind explicit host-pcap flows to a frozen image
and reviewed answer screenshots. Encrypted control exchanges are not evidence
of model replies. Live original-speed evidence accompanies the offline gates;
physical entropy remains a separate acceptance requirement.

## Functional acceptance

The same runtime passes these read-only 86Box cases using `gpt-6.1-sol` with
`max` reasoning:

| CPU / RAM | Entry | Completed scenario |
| --- | --- | --- |
| 4.77 MHz 8088 / 16 KiB | ROM BASIC sidecar | Four dependent text replies, ten-minute idle, one reconnect, native write/execute/read and final answer |
| 4.77 MHz 8088 / 32 KiB | Direct floppy boot | The same conversation, idle recovery and native program |
| 6 MHz 286 / 512 KiB | Direct floppy boot | The same conversation, idle recovery and native program |

The native program is `B8 2A 00 CB`: load AX with 42 and return. Each run executes
one write, one execute and one read, then returns to the input prompt. The
32 KiB model answer spells out the correct value and bytes under the earlier
letters-only instruction; its numeric-format check failed, while independent
visual and capture review established functional completion. The raw automatic
result and that caveat are retained.

All seven original-speed ISA NIC profiles pass first-response reuse and a
dependent reply after ten minutes idle and one bounded reconnect. This includes
3c503 with MDA and two separate 3c501 runs. Read-only images and protected inputs
remain unchanged, and all test VMs close after completion.

Functional completion is slow at the 16 KiB floor: the four text turns took
about 4–13 minutes each, and the post-idle native sequence took about 32 minutes.
These are measured completions, not a latency improvement or a guarantee for
every provider response. The security distinctions and physical-source limits
in [security.md](security.md) still apply.
