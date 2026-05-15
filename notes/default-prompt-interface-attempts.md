# Default Prompt Interface Rebuild Attempts

Branch: `work/default-prompt-interface-rebuild`

Baseline: current released `main` / Build 7 (`0c8eb5e`). This includes the
verified 16 KiB ROM BASIC path, the settled 3c501 driver work, and the stable
minimal OpenAI Responses proof that displays `ok`.

Target: Build 8 minimal chat loop without arena cleanup/defrag. Keep the Build
7 memory layout and proven TLS/NIC path, add request/response streaming as the
real I/O shape, render model text into the Default Prompt Interface, then allow
one-line user prompts to repeat through the same path.

Rules for this rebuild:

- Do not reintroduce cleanup, defrag, resident relocation, or a one-big-ocean
  memory handoff until chat works reliably.
- Treat the first request and later DPI requests as the same model-call path.
- Stream request body slices instead of building one large in-RAM prompt blob.
- Stream response text directly to the renderer instead of requiring a full
  response body buffer.
- Use the OCR/background harness for routine canaries; avoid screenshot uploads
  unless local classification is ambiguous and the image is needed for human
  inspection.
- Record failed approaches here before moving on.

## 2026-05-16 00:35:27 - Reset Build 8 onto the stable Build 7 baseline

Created `work/default-prompt-interface-rebuild` from `main` / `build-7`
(`0c8eb5e`) instead of continuing on the cleanup/defrag-derived
`work/default-prompt-interface` branch.

Rationale:

- The released Build 7 path is the stable ground: 16 KiB ROM BASIC entry,
  settled 3c501 behavior, proven TLS session setup, and minimal OpenAI
  request/response.
- The arena cleanup/defrag branch changed too many memory lifetime invariants
  before the chat loop existed. Debugging there led to hidden/erased output and
  unclear ownership of live data.
- The useful newer harness/OCR changes were restored onto the rebuild branch,
  but the cleanup/defrag memory architecture was not.

Verification:

- `make inspect` succeeds from the Build 7 baseline.
- `vm-net-ne2k8` through the ROM BASIC OCR harness reached:

```text
seed build 7
ok
```

Conclusion:

Proceed by adding the smallest real Build 8 chat path on top of Build 7:
stream prompt slices out, stream model response back to screen, then enter the
interactive prompt loop.

## 2026-05-16 00:35:27 - Carry forward portable diagnostics, not arena code

Pulled forward the useful tooling from the abandoned Build 8 branch without
bringing the cleanup/defrag implementation:

- `tools/run-basic-bootstrap-86box.py` — latest background/OCR harness.
- `tools/ocr-vision.swift` — local macOS OCR helper kept as a fallback.
- `tools/run-basic-bootstrap-matrix.py` — bounded repeated canary runner for
  profile/repeat sweeps.
- `tools/memory-map.py` — generated memory-map appendix tool.
- `tools/build-dpi-prompt.py` — build-time JSON escaper for static prompt
  template slices, so the 8088 runtime does not need a general JSON string
  escape routine.
- `docs/memory.md` — regenerated against the Build 7 baseline, not copied from
  the cleanup/defrag branch.
- `make memory-map` — convenience target for refreshing the appendix.

Conclusion:

These are safe to keep. They improve observability and release discipline
without changing Seed's runtime behavior.
