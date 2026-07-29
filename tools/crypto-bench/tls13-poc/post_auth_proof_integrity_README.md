# Post-auth live proof-integrity gate

This offline gate protects the evidence boundary of the 16 KiB
credentialed-live proof. It does not launch 86Box, execute the floppy-timing
collector, use the network, or receive security credit.

It checks two independent contracts:

1. The gate builds its own deterministic credential-free `--secure`
   automatic-floppy-entropy base in its private temporary directory, so
   concurrent functional runs and shared build directories cannot change its
   input. The ROM BASIC machine-code loader and generated BASIC program are
   then rebuilt from checked sources and byte-compared with that base. One-byte
   changes to either base artifact must stop composition.
2. The production builder and runner are exercised twice with public dummy
   `USER.CFG` files of different sizes. After normalizing only the selected
   output-directory path, their public manifests, console transcripts, and
   runner reports must be identical. Credential-dependent core, cold `UCL1`,
   and floppy-image hashes must remain omitted. Both fixed low callback pages
   and the BASIC artifacts retain their size and SHA-256 bindings because they
   are credential-independent.

The runner is also given three hostile builder outputs. It must reject a BASIC
loader changed after hashing, a BASIC program changed after hashing, and a
false deterministic-rebuild flag before a harness can run or a passing report
can be written.

Run:

```sh
python3 tools/crypto-bench/tls13-poc/post_auth_proof_integrity_check.py
```

The fixed dispatcher and all 11 resumption operations are now present in the
complete composition. This gate passes its isolated deterministic-build,
credential-size non-disclosure, BASIC binding, and hostile-output checks and
writes the checked offline result to
`post_auth_proof_integrity_results.json`.

That result establishes only the construction and evidence boundary described
above. It does not execute the composed path on the target, validate a live
provider dialogue, characterize physical floppy timing, or assign entropy
credit. A separate exact credentialed functional live run passed on 28 July
2026; this offline gate neither produces nor substitutes for that evidence.

For forensic comparison, `--base-build` may name an existing
automatic-floppy-entropy base. The gate copies it into its private directory
before reading it and applies the same strict secure-base validation. The
default always performs a fresh isolated build.
