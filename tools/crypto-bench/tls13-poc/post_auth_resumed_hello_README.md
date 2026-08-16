# Post-auth resumed HELLO phase

The credential-free secure-FO base keeps its first-flight HELLO phase compiled
with `HELLO_FRESH_ONLY`. The post-auth composition appends two distinct K14
phases:

```text
post_auth_cached_connect:  one sector at 0x2400
post_auth_resumed_hello:   eight sectors at 0x1800
```

The first is the `RHC1` cold cached-target connector. Its four-entry table
contains connect, zero-window ACK, window-update, and a caller-gated 3c501
receive-prime helper. It runs while the symmetric overlay and binder are still
resident.

The second is the existing `T13HEL01` overlay compiled with:

```text
TLS13_POC_K14
HELLO_RESUMED_ONLY
```

Its nine-entry table remains the HELLO ABI. Entry 0 fails closed and entry 1
starts the resumed ClientHello. Keeping it to eight sectors preserves the
critical eight-sector symmetric restore contract: its loaded extent is
`0x1800..0x2800`, never the ninth symmetric sector.

The dispatcher order is fixed:

1. Load and call the `RHC1` connector at `0x2400`.
2. Load the eight-sector resumed HELLO at `0x1800`, overwriting the connector.
3. Restore the attempt's random, session, ticket, PSK, age, and ephemeral key.
4. Call resumed HELLO entry 1.

Candidate and ciphertext callbacks that reuse `0x0900..0x0bbc` must reload
the scattered RSU1 controller before returning to it.

Run the offline phase gate with:

```sh
python3 tools/crypto-bench/tls13-poc/post_auth_resumed_hello_check.py
```

The gate executes the actual 8086 phase under Unicorn, uses poison until the
cached connection succeeds, restores the fixed inputs, checks the emitted
ClientHello and binder against an independent oracle, accepts the exact
resumed ServerHello, proves the connector was overwritten by the eight-sector
HELLO load, and pins the live-target EncryptedExtensions literal. It does not
launch a VM or receive security credit.
