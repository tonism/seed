# Agent And User Config

Seed has three configuration files on the boot floppy:

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
Seed stores agent IDs in 12-byte slots, so IDs may use up to 11 visible
characters plus the terminator. The shipped IDs fit this cap.

`NET.CFG` holds generic network-readiness probe settings. It currently supports
one line:

```text
probe <host-or-url>
```

The default tracked value is `probe example.com`. If `NET.CFG` is missing,
unreadable, or invalid, Seed falls back to `example.com` for the dark `"."`
internet-readiness proof.

`USER.CFG` is user-local state. It should only contain values that were entered
by the user and validated by Seed, such as selected agent interface, endpoint
overrides, model choices, reasoning effort, and API credentials. NIC adapter
family hints are intentionally not stored; the current probes are cheap enough
to rerun each boot.

Seed caps stored API credentials at 192 bytes. Anthropic and Google document
how API keys are passed to their APIs, but do not publish a longer key-string
maximum; this is Seed's runtime policy cap for the currently supported
OpenAI/Anthropic/Google provider surface.

Seed stores endpoint overrides in 80-byte slots, so endpoint values may use
up to 79 visible characters plus the terminator. Reasoning effort values use an
8-byte slot, which covers the current `low`, `medium`, `high`, and `xhigh`
efforts.

Seed can remember validated user answers to make later boots faster, but local
stored user configuration is always optional.

This follows the architecture contract in `docs/architecture.md`: the boot
medium is the recovery boundary and may be write-protected. `USER.CFG` is a
fast-boot convenience when storage is writable, not part of the trusted boot
requirement.

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

The current config path parses
up to five `agent ` declarations from `AGENTS.CFG` when that file is available
and valid; otherwise it uses the built-in direct-vendor fallback. It reads
`USER.CFG` when present, accepts a saved `agent <id>` only if it matches the
active agent list, asks `agent?` otherwise, then asks for any missing `server?`
and `key?` values needed by the selected agent. When the selected agent needs
both values, they are shown on one form panel with Up and Down moving between
fields. Saved `model` and `reasoning` values are preserved when present, but
Seed should not ask the user to type those by hand. Model and reasoning choices
belong after the selected agent endpoint can be reached and its capabilities
can be fetched. Seed then proves selected-agent reachability and runs the full
TLS 1.2 / application-data path (ClientHello through encrypted application data),
documented once in [architecture.md](architecture.md), "Provider Timing Model".
Seed writes validated values back on a best-effort basis:

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
default config. On 30 April 2026, `api.openai.com`, `api.anthropic.com`,
`generativelanguage.googleapis.com`, and `openrouter.ai` were verified against
the same TLS 1.2 P-256 ECDHE-ECDSA-CHACHA20-POLY1305 path without extended
master secret. `openrouter.ai` therefore remains in `AGENTS.CFG`. `litellm` is
a user-supplied endpoint, so it cannot be certified at ship time; it is
supported only when the configured server negotiates the same path.

`reasoning` is stored as a plain text effort value such as `xhigh`, but it is not yet
applied: the chat-loop request pins `"reasoning":{"effort":"high"}` rather than reading
the saved value back. The saved `model`, by contrast, IS substituted into the request.
Honoring the stored reasoning effort, and dynamic model/reasoning capability fetches,
remain later work. The `key` value is
plaintext on the boot medium. The shipped build does not perform real key agreement: the P-256 scalar multiply
is compiled out (one real scalar multiply is 110.8 s measured on this CPU — it fits the
size budget, the wall is speed), so the premaster is taken from the server's public
value rather than a Diffie-Hellman exchange, and client randomness is a placeholder LCG.
Seed still runs the rest of the path for real — it
sends ClientKeyExchange, ChangeCipherSpec, and an encrypted client Finished, can send
the API request early as TLS application data before the server Finished, and
receives, authenticates, decrypts, and verifies the server Finished and application
records on the ChaCha20-Poly1305 path — but because the key exchange is stubbed, the
session is not confidential. Real key agreement is the blocker: the premaster is public,
so a better client-random RNG alone would not make the session confidential (entropy
matters only once a secret per-session value exists). Both real key agreement and
server-certificate authentication are out of reach on this CPU (minutes per handshake),
so this is not secure TLS — see `docs/architecture.md` (CPU And Crypto Budget) for the
measured costs. Capability fetches, model selection, reasoning selection,
and environment handoff remain later work.
