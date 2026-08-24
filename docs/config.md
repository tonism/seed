# Agent And User Config

Seed reads two optional files under the boot floppy's `SEED/` directory:

```text
SEED/AGENTS.CFG  shipped agent-interface declarations
SEED/USER.CFG    optional local choices and credentials
```

The current product supports one provider route: `openai` at
`api.openai.com`. The parser retains the bounded multi-entry `AGENTS.CFG`
format for future interfaces, but an alternate agent ID or endpoint is not a
supported TLS 1.3 product path and must fail closed rather than select another
crypto profile.

`AGENTS.CFG` is not general OS configuration. The shipped file declares the
OpenAI interface. If it is missing, unreadable, or invalid, Seed uses the
built-in OpenAI declaration.

`USER.CFG` is user-local convenience state. It may contain validated values
such as:

```text
agent openai
model <model-id>
reasoning <effort>
key <credential>
endpoint api.openai.com
```

The on-disk `endpoint` name remains for compatibility, but the current product
route accepts only the OpenAI endpoint. Seed stores agent IDs in 12-byte slots,
endpoint values in 80-byte slots, reasoning values in 8-byte slots, and API
credentials in 192-byte slots.

The configuration contract is:

```text
missing config      -> ask
unreadable config   -> ask
unparseable config  -> ask
invalid value       -> ask
write failure       -> continue without storing
read-only media     -> continue without storing
```

Seed asks for a required value through the text UI, validates it, uses it in
RAM, and only then attempts a best-effort save. A failed write must not prevent
boot, TLS, or the agent loop. NIC family hints are not persisted; hardware is
detected on every boot.

Only normalized, validated values are stored. Raw failed input is not retained.
The key is plaintext on the floppy: read-only media provides recovery and
immutability, not secret storage. Use a scoped, rate-limited key and do not
share an image containing one.

## TLS 1.3 credential boundary

The TLS routes may parse and escrow the selected OpenAI configuration before a
connection, but they may not make the key reachable by a request constructor
until their tier-specific capability is committed:

- On the 8088 profile, only TLS handshake state, one bounded
  tentative ticket, and the compiled credential-free liveness request are
  reachable during provisional and quarantine states. The fresh connection
  must authenticate both its HEAD response and tentative ticket; a close
  before either completes fails the attempt. Full ML-KEM FO validation, exact
  dated leaf possession, CertificateVerify, and a no-0RTT resumed connection
  with authenticated post-Finished HEAD liveness must precede status-last
  route promotion.
- On the 286 conforming profile, acquisition may transmit only the immutable
  credential-free HEAD and retain an authenticated ticket as tentative state.
  Full ML-KEM FO comparison and strict WE1/hostname/UTC/CV authentication must
  promote that ticket before the final no-0RTT PSK-DHE connection can consume
  it. The final connection must use an independent full hybrid exchange, a
  valid binder with `selected_identity=0`, full decapsulation, and a verified
  resumed Finished before application keys and the request are published.

Every failure path retires the escrowed capability and private TLS state.
Automatic same-request replay is limited to one fresh reconnect for a human
request that produced no text. Tool continuations and partially rendered
responses are never replayed automatically.

## Filesystem discipline

The FAT12 product image stays narrow:

```text
root SEED.SYS runtime file
SEED/ directory for runtime-owned config and prompt files
optional SEED/USER.CFG local state
optional SEED/DRIVERS/ directory for one-sector NIC drivers
uppercase 8.3 filenames
one-cluster subdirectories
no long filenames
no dependency on writes succeeding
```

TLS 1.3 trust is not stored in a mutable leaf file. `SEED/LEAF.DER` is absent:
the 8088 exact-leaf object and the 286 WE1 issuer point are immutable program
assets in `SEED.SYS`; same-boot leaf objects and generated tables are volatile
RAM state.

Driver files are not config, but follow the same optional-media discipline.
Seed scans the `.DRV` files under `SEED/DRIVERS/`, selects a suitable driver by
validated metadata, asks when multiple drivers match, and reports
`driver setup failed` through the normal retry/restart path when none match.
