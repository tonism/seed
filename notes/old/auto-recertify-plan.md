# Auto-recertify (silent leaf-rotation handling) + crypto-opt — scoped plan

Build-12's secure tier shipped + pushed (leaf-key pin, 286 @6/@8 validated, 8088 floor unchanged;
work/scaling on origin). This plan is the agreed NEXT step: make leaf rotation **silent** (Seed
re-pins itself, safely) and do the crypto-opt that makes it comfortable. 286-only throughout; the
8088/086 path does none of it (no key agreement, no cert, no pin — just the "insecure" splash).

## The trust model (the non-negotiable)

"Fetch a new pin and trust it" is blind TOFU = no authentication = false security. The ONLY safe
auto-re-pin verifies the new leaf against an anchor Seed already trusts. So:

- **Pin the issuing CA, GTS WR1** (RSA-2048, lives years) as the durable anchor.
- Keep the **leaf key as a fast-path cache** (the current pin), validated against WR1.
- A freshly-presented leaf is trusted iff its signature chains to the pinned WR1 AND its SAN ==
  api.openai.com AND it is within validity. Then adopt it.
- WR1 itself rotates (~years) → that still needs a human re-pin (rare). Leaf rotation (~90 days)
  becomes automatic.

## Architecture — keep the cost OUT of the ~15s race (the unlock)

- **Hot path (every handshake):** verify the ServerKeyExchange RSA sig against the **cached leaf** —
  1 verify, fits 6 MHz (the shipped path, unchanged).
- **Detect stale:** that verify fails (the leaf rotated). Do NOT do the chain-verify in the race.
- **Recertify process (off the race, no ~15s pressure):** take the new leaf from the Certificate
  message, ASN.1-parse it, verify leaf→WR1 (the pinned CA), check SAN + validity, adopt the new leaf
  (in RAM; the read-only floppy can't persist it, so it re-derives from WR1 each boot after a
  rotation). **Mid-chat: render a dim `> recertify` status line** (analogous to `> reconnect` in
  phases/agent_endpoint.inc) while this runs; append " done"/" failed" in place, then continue.
- **Retry** the handshake against the now-fresh cached leaf → back to the 1-verify fast path.

Net: the race is ALWAYS 1 verify (6 MHz holds); the heavy chain-verify runs once, off the clock, only
on a detected rotation. This is what makes "silent re-pin @6" feasible without forcing 2 verifies into
the window.

**Session survival (design goal — confirmed sound).** A mid-chat leaf rotation MUST NOT lose the
conversation. It doesn't, because the chat session (window/ledger/compaction state) lives in RAM,
independent of the per-turn TLS connection. Seed already reconnects per turn and re-sends the context
(the proven reconnect path); **recertify is just "reconnect + the handshake needed a new leaf"** — same
survival. Crucially the off-race chain-verify runs BETWEEN handshakes (on the captured cert, no socket
held open), so it adds no idle-timeout pressure to the reconnect window — it's a ~10–13s compute pause
(shown as `> recertify`), then a fresh fast handshake with the adopted leaf, then the turn proceeds with
full history. On SUCCESS: seamless (the user sees `> recertify`, then the answer). On FAILURE (WR1 itself
rotated, or an attack): fail closed → `> recertify failed` → back to DPI, but the history is still in RAM
intact (recoverable after a human WR1 re-pin). So: history always survives; a good rotation is invisible
beyond the status line; a bad one refuses rather than downgrades.

## Crypto-opt — DO THIS FIRST (measured spike), it pays off immediately

The dominant cost is RSA-2048 verify (~6.37s @6). The lever (FINDINGS "future lever, not built"):
- **Dedicated Montgomery squaring.** s^65537 = 16 squarings + 3 plain montmuls (sig*r2 enter, *sm,
  *one leave); the bench does the 16 squarings as FULL multiplies via the shared CIOS montmul.
- **Baseline MEASURED (this session): 6,917,722 unicorn instrs, ok=true.** Sharper cost model than the
  handover's projection: a montmul is ~half multiply-phase MULs, ~half reduce-phase MULs. Squaring only
  helps the MULTIPLY phase (off-diagonal pairs once → ~0.51× there) and the reduce phase is unchanged,
  so a squaring montmul is ~**0.75×**, not 0.6×. Only 16 of 19 montmuls are squarings, so OVERALL
  ~**0.79× → ~5.0s @6** (≈5.49M instrs), NOT the handover's optimistic 4.3s. (This is exactly why we
  measure.) Needs the SOS structure: separate square-then-reduce (off-diagonal opt + 256-limb product +
  Montgomery reduce) — CIOS interleaving can't exploit the symmetry in place. Correctness-critical
  bignum → implement with fresh rigor, oracle-gate every cut via rsa_eval.py, then 86Box @6
  (run_rsa_286.py). (Further levers: Karatsuba on the 128-limb multiply; r4_v42 SHA on the 286;
  ECDHE-window tuning — the broad frontier is a workflow candidate.)

**KEY FINDING — the squaring is slack-polish, NOT the @6 enabler.** Even at ~5s, the in-race 2-verify
WR1 path is still ~16s @6 (over). What makes silent re-pin @6 possible is the **off-race architecture**
(the hot path stays 1 verify), not the crypto-opt. So the real enabler is the X.509 chain-verify +
off-race state machine below; the squaring's payoff is (a) ~1.4s more slack on the SHIPPED leaf-pin
path @6 (~14s → ~12.6s, more robust today) and (b) a faster off-race re-pin (~13s → ~10s). Worth
landing, but it does not gate the auto-re-pin and is lower priority than the architecture.

Budget reality (baseline measured; rest to confirm by measurement):
- Shipped leaf-pin @6: ~14s (ECDHE 6.6 + 1 RSA 6.4 + SHA/PRF ~1) — knife-edge, greets. Squaring → ~12.6s.
- In-race 2-verify WR1 @6: ~20s (over); with squaring ~16s (still over) → the chain-verify goes OFF the
  race. @6 stays fast via the cached-leaf fast path regardless of the squaring.

## The trust-critical piece — fresh rigor

The **X.509 cert-chain verify** (ASN.1-parse the leaf: TBSCertificate, SPKI, signature, SAN, validity;
verify vs WR1) is the false-security crux — a wrong parser accepts forged certs. Build it standalone,
fuzz against tampered certs (bad sig, wrong SAN, expired, wrong issuer, malformed DER), accept-real /
reject-tampered offline before wiring. It is the piece leaf-pinning deliberately avoided.

## Increments (each build-green + validated)

1. **RSA squaring** — measured spike → land it (helps the shipped tier too). Re-budget.
2. **X.509 leaf parse + verify-vs-WR1** — module entry; offline accept/reject + fuzz. Pin WR1 (config
   blob, see below).
3. **Recertify state machine** — detect stale (cached-leaf verify fails) → off-race chain-verify →
   adopt → retry; the `> recertify` mid-chat line.
4. Validate: 286 @6/@8 steady-state (cached leaf, fast); simulate a rotation (pin an old leaf, present
   a new WR1-signed one) → silent recertify → greets; tamper → reject; 8088 unchanged.

## Related (already agreed, do alongside)

- **Pin as a config file** (not baked): ship a default + let a floppy file override → re-pin without a
  rebuild (gen-rsa-pinned-key.py emits the blob; reuse the AGENTS.CFG root-file find). With WR1 as the
  anchor this becomes "drop the WR1 blob"; the leaf cache is auto-derived.
- **Distinct cert-failure status** (optional): so a WR1-rotation/un-recertifiable failure reads as
  cert (not generic net) on the screen.

## Next-session kickoff (X.509 — the trust-critical crux; fresh rigor)

User picked this as the next focused push. Build + validate OFFLINE before any 286 wiring:
1. Capture WR1's cert + a real api.openai.com chain (openssl); extract WR1's RSA-2048 pubkey → the
   pinned-anchor blob (extend gen-rsa-pinned-key.py with a WR1/issuer mode).
2. Map the leaf DER: TBSCertificate span, SPKI (the leaf RSA pubkey to adopt), signatureValue, the SAN
   extension (api.openai.com), validity (notBefore/notAfter). Document exact ASN.1 tags/offsets.
3. Offline oracle (python): parse + verify leaf→WR1 (RSA-PKCS1-SHA256 over the TBS bytes), check SAN +
   validity. Must ACCEPT the real leaf.
4. Tamper matrix — must ALL reject: flipped sig bit, wrong SAN, expired, wrong issuer, truncated /
   over-long DER, BER-vs-DER length tricks, injected/duplicated extension. Exact DER only, no lax parse.
5. Only then port the parser to the 286 module (new entry point) + re-run accept/reject on hardware.
The crux: a wrong length/tag accepts forged certs. Standalone → fuzz → prove reject-tampered → THEN wire.

## Release

work/scaling is pushed. The user cuts the release (ff main + annotated tag + GH release) when ready —
either now (Build 12 = the shipped secure tier; this plan = the next build) or after this plan lands.
