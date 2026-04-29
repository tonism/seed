# Agent And User Config

Seed now has three configuration files on the boot floppy:

```text
AGENTS.CFG  optional shipped override for agent interface declarations
NET.CFG     optional shipped override for generic internet probe settings
USER.CFG    ignored, optional local user choices and secrets
```

`AGENTS.CFG` is not general OS configuration. It only describes five
agent-facing interfaces: two gateways first, then three direct vendors. The
file is meant to stay plain enough for both humans and later agents to edit. If
`AGENTS.CFG` is missing, unreadable, unparseable, or contains no `agent`
declarations, Seed falls back to three built-in direct vendors:

```text
openai
anthropic
google
```

When `AGENTS.CFG` parses successfully, it overrides the built-in list.

`NET.CFG` holds generic network-readiness probe settings. It currently supports
one line:

```text
probe <host-or-url>
```

The default tracked value is `probe example.com`. If `NET.CFG` is missing,
unreadable, or invalid, Seed falls back to `example.com` for the dark `"o"`
internet-readiness proof.

`USER.CFG` is user-local state. It should only contain values that were entered
by the user and validated by Seed, such as selected agent interface, endpoint
overrides, model choices, reasoning effort, and API credentials. NIC adapter
family hints are intentionally not stored; the current probes are cheap enough
to rerun each boot.

Seed can remember validated user answers to make later boots faster, but local
stored user configuration is always optional.

Core rule:

```text
missing config      -> ask
unreadable config   -> ask
unparseable config  -> ask
invalid value       -> ask
write failure       -> continue without storing
read-only media     -> continue without storing
```

The runtime must not turn config storage into a boot dependency. If a value is
needed and cannot be loaded, Seed asks the user through the minimal text prompt
flow, uses the answer in memory, and attempts to persist it only after the value
has been validated.

Writes are best-effort. A failed write is not an error state and should not
interrupt the user after the validated answer has already been accepted. This
keeps read-only boot media, write-protected floppy images, and emulator-mounted
images usable.

Only normalized, validated values should be stored. Raw failed input should not
be retained. Early PC-class targets do not have trustworthy secret storage, so
persisted credentials must be treated as plaintext convenience state on the boot
medium.

The first filesystem target is FAT12 because it is period-appropriate, simple,
and widely compatible with early PC tooling. The initial filesystem discipline
is intentionally narrow:

```text
root directory only
uppercase 8.3 filenames
no subdirectories
no long filenames
no dependency on writes succeeding
```

The current build 6 checkpoint parses up to five `agent ` declarations from
`AGENTS.CFG` when that file is available and valid; otherwise it uses the
built-in direct-vendor fallback. It reads `USER.CFG` when present, accepts a
saved `agent <id>` only if it matches the active agent list, asks `agent?`
otherwise, then asks for any missing `server?` and `key?` values needed by the
selected agent. When the selected agent needs both values, they are shown on
one form panel with Up and Down moving between fields. Saved `model` and
`reasoning` values are preserved when present, but Seed should not ask the user
to type those by hand. Model and reasoning choices belong after the selected
agent endpoint can be reached and its capabilities can be fetched. Seed proves
selected-agent TCP reachability by resolving the selected provider host,
receiving a SYN-ACK on port 443, sending the final ACK, then sending a minimal
TLS 1.2 ClientHello with SNI offering only P-256
ECDHE-RSA-CHACHA20-POLY1305 for the current crypto path, parsing ServerHello
version, random, cipher-suite, session-id, known extension flags, selected
cipher path, and the following Certificate handshake header before draining
that Certificate handshake to the next handshake boundary. It then parses the
ECDHE ServerKeyExchange header, captures the uncompressed P-256 public point,
converts X/Y into 16-bit little-endian field words, range-checks them below
the P-256 prime, verifies that the point satisfies the P-256 curve equation,
provides Jacobian point double, mixed-add, scalar multiplication helpers, and
Comba-style field product accumulation for the upcoming ECDHE shared-secret
path, parses ServerHelloDone, and maintains a live SHA-256 handshake transcript
context through ServerHelloDone. Seed writes validated values back on a
best-effort basis:

```text
agent <id>
model <model>
reasoning <effort>
key <credential>
endpoint <host-or-url>   optional; currently required for LiteLLM
```

The `server?` prompt maps to the stored `endpoint` line. The on-disk name stays
`endpoint` for compatibility with existing local config.

OpenAI, Anthropic, and Google define the supported TLS compatibility surface.
Extra shipped agent entries are allowed only when they fit that same path;
Seed should not grow alternate crypto paths just to keep a gateway in the
default config. On 29 April 2026, `openrouter.ai` was verified against the same
TLS 1.2 P-256 ECDHE-RSA-CHACHA20-POLY1305 path, so it remains in
`AGENTS.CFG`. `litellm` is a user-supplied endpoint, so it cannot be certified
at ship time; it is supported only when the configured server negotiates the
same path.

`reasoning` is stored as a plain text effort value such as `xhigh`; provider
specific request mapping is later Build 6 work. The `key` value is plaintext on
the boot medium. Reducing scalar multiplication from the current full
double-and-add cost and wiring it into the live ECDHE path, converting the
Jacobian shared point into the affine x-coordinate pre-master secret, TLS
transcript digest finalization, the remaining TLS handshake, authenticated API
calls, capability fetches, model selection, and reasoning selection are still
build 6 follow-up work.
