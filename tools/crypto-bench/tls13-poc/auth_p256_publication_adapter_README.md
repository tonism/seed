# Live P-256 publication adapter proof

This proof closes the authority gap between the existing live compact
CertificateVerify overlay and ROG3. The old compact status byte at `0x3c9a`
remains part of the P-256 overlay ABI, but ROG3 never trusts that byte.

A fixed one-sector adapter at `0x3200`:

1. clears the complete issuer publication;
2. rejects a zero attempt generation at `0x3c2e`;
3. reruns the actual live exact-leaf P-256 verifier through the fixed table
   word at `0x1800`;
4. requires both its `CF=0, AX=1` return and status `0x3c9a = 1`;
5. copies the immutable leaf coordinates, attempt generation, fixed profile,
   and authenticated CertificateVerify digest into one checksummed `LP1!`
   object; and
6. writes status at `0x3600` last.

The adapter accepts no pointer, alternate leaf, generation register, route,
credential, or media handle. A prefilled status byte therefore cannot bypass
strict DER parsing or the full P-256 equation.

## Stable ABI

| item | address |
| --- | --- |
| adapter image | `0x3200`, at most one sector |
| adapter entry | header word; currently `0x321a` |
| fixed auth verifier table word | `0x1800` |
| generation | `0x3c2e` |
| digest | `0x3c30..0x3c4f` |
| signature length | `0x3c50` |
| signature | `0x3c52..0x3c99` |
| existing auth status | `0x3c9a` |
| LP1 publication | `0x3600..0x3671` |
| ROG3 credential-loader callback | `0x1580` |

The publication layout is:

```text
3600 status (written last)
3601 reserved = 0
3602 magic "LP1!"
3606 bitwise inverse magic
360a generation
360c exact-leaf profile 003f
360e leaf x[32]
362e leaf y[32]
364e authenticated CertificateVerify digest[32]
366e checksum A
3670 checksum B
3672 end
```

ROG3 continues to accept the durable `WE1!` issuer publisher and still requires
its relocated pass-2 input. It accepts `LP1!` without that obsolete input only
because the fixed adapter has already rerun exact-leaf authentication.

The two-word publication checksum detects torn or stale phase handoffs. It is
not a MAC against arbitrary code that can rewrite all RAM; LP1 provenance
therefore depends on the fixed read-only phase graph.

## Run

```sh
PYTHONDONTWRITEBYTECODE=1 python3 \
  tools/crypto-bench/tls13-poc/auth_p256_publication_adapter_check.py \
  --output \
  tools/crypto-bench/tls13-poc/auth_p256_publication_adapter_results.json
```

The checker executes the actual dated live CertificateVerify vector, proves
status-last publication, rejects forged status and malformed inputs, then
replaces the auth phase with the real ROG3 gate and reaches the fixed `0x1580`
credential loader in an exact 16 KiB map. It also tests torn magic, inverse,
leaf, digest, checksum, and stale-generation publications.
