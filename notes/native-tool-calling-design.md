# Native Tool Calling — Shipped Build 12 Record

Build 12 native function calling is implemented on `work/scaling`.

Current behavior:

- The OpenAI Responses request advertises five native tools from `prompts/tools.json`:
  `read_mem`, `write_mem`, `exec`, `save_env`, and `load_env`.
- Ready turns use an `input` array with `store:false`; Seed keeps continuity locally and does not rely
  on `previous_response_id` or a server-side response chain.
- A tool continuation locally replays the submitted user item, the captured `function_call`, and the
  `function_call_output`.
- The old line-start `$` scanner and synthetic "Continue" turn are deleted. The old executor bodies
  remain as the backend for native tools.
- 32 KiB+ machines stream the tools schema from resident `tools_cache`.
- 16 KiB machines stream the one-sector `TOOLS` asset from floppy and use the low `0x0d00`
  function-call capture handoff, so native tools work without the 32 KiB loop-cache band.
- The per-turn model ledger is intentionally terse and actionable only: `r=`, `a@`, `c@`, `F@`, `e@`,
  and `s=`. The legend lives in the cold identity prompt.

Validation at this checkpoint:

- `make`
- `make basic-bootstrap`
- check-layout via the build
- 16 KiB BASIC-sidecar `read_mem(0x00000400,8)` smoke returned `f8 03 f8 02 00 00 00 00`
- Earlier 32 KiB direct-boot smoke on `vm-net-ne2k8` passed plain chat and native `read_mem`

Design history and the superseded Codex handover are archived in
`notes/old/native-tool-calling-design.md`.
