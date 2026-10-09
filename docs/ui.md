# Text UI

Seed's boot UI is text-mode first and keeps the active BIOS video mode.

User-visible messages should appear through the same fast-type path used by the
successful boot banner. This includes:

```text
success text
error messages
questions
menu labels
modal text
field labels
button labels
```

Small status markers can appear immediately because they represent state, not
message content:

```text
none         boot sector, loader, SEED.SYS load
"." dark     hardware, local machine setup, and internet prep/reachability
"o" dark     TLS handshake setup
"o" normal   local TLS crypto/key material setup
"o" bright   agent and environment prep
red marker   fatal error state; keep the current phase glyph
```

Questions should use the low attention tone, blink the current marker while
keeping its phase color, then fast-type the prompt and minimal fields. Question
prompts are always bright and end with `?`. Fatal errors should turn the
current status marker red, play the low failure tone, fast-type the error text,
then fast-type a minimal `retry` / `restart` menu.

`retry` reruns from the dark `"."` hardware phase without rereading floppy
sectors. `restart` performs a warm machine restart through BIOS.

The splash is a short boot banner drawn after the display and CPU class are
known, before driver loading and network setup. The 8088 adds `security note`
in the same neutral gray as the build number; the line is hidden on 286+
machines. It points to the documented 8088 credential-release and assurance
boundary, not fewer product capabilities or an active failure. No driver
validation, network negotiation, key setup, or environment setup happens
during the splash.

Menus use color to indicate selection. The selected item uses the active prompt
color; inactive items use the dim prompt color. Do not add marker glyphs solely
to show selection.

Driver selection is a boot-time question only when more than one shipped driver
metadata block suits the detected adapter family. It fast-types `which driver?`,
lists the matching `.DRV` names, accepts a numeric choice, and otherwise repeats
the question. If no suitable driver is present, the hardware phase fails as
`driver setup failed` and follows the same retry/restart menu as other fatal
hardware setup errors.

Agent setup uses a drill-down panel stack under one bright topic prompt. OpenAI
is the only current provider. The
active panel keeps the selected row bright and inactive rows dim. When a
selection opens the next panel, the selected value slides left and the selected
agent's required fields appear to its right. `Enter` submits the current form.
`Esc` closes the current panel and slides the selected value back to the
previous menu. Opening a child panel does not play a new attention tone.

When a form needs more than one typed value, those values stay on the same
panel. Up and Down move field focus, and typed characters edit the focused
field.

On the 286 conforming profile, certificate validity uses a coherent, valid BIOS
RTC as the platform UTC clock without an interactive question. An invalid RTC
prevents that profile; it must fail closed rather than downgrade to the 8088
profile.

The 16 KiB TLS route never borrows CGA or MDA memory for cryptographic state.
Video RAM remains the user's display throughout cold crypto work, and output
continues through the ordinary BIOS text path. A screen of binary or random
glyphs is memory corruption and an acceptance failure, never a transitional
UI state.

Text fields, including `key?`, render plain typed characters. Long values stay
inside the field row by showing the visible tail without wrapping.

The cursor stays hidden unless a field is actively accepting typed input.

## Default Prompt Interface

After boot, Seed renders a model greeting and takes prompts at a `>` marker. User input
shows in bright text and streamed model responses in normal text; turns reuse one live TLS
session. If a human no-text request needs the one permitted fresh reconnect,
Seed shows one dim `> reconnect` status. A second failure reports
`> reconnect failed`. A tool continuation or partially rendered answer is
never replayed.

A failed response with no usable answer, or an unfinished tool call, returns
to human input with the fast-typed dim status `> response failed; try again`.
Seed discards the failed turn's pending tool capture so it cannot block the
next prompt or execute later. An explicit user stop retains `> stopped`.
An interrupted tool capture that has not executed can use the human turn's
remaining retry; executed tool output and agent-loop continuations cannot.
Already displayed answer text is preserved after a transport failure; Seed
retires that session without replaying the partial answer.

When the rolling conversation window fills, Seed compacts it: a dim status line,
fast-typed like the boot banner, reads `compacting context`. The one-line recap the model
emits to drive that compaction is captured silently and never drawn — the user sees only the
status line, then the answer.
The compaction prompt asks for the latest assistant answer and exact facts
needed by follow-up questions within the available note budget.
A no-text compaction retry retains the original conversation. Seed promotes
captured summary text before constructing the pending question, including
when the replacement note is shorter than the previous note.

## Tool Calls

When the model emits a native tool call (`read_mem`, `write_mem`, `exec`, `save_env`,
or `load_env`), Seed never draws raw protocol JSON. It renders one dim action line in
its place: `read from <addr>`, `write to <addr>`, `execute <addr>`, or the corresponding
save/load status, so the user sees *what* the agent touched, never the wire syntax.
Out-of-range memory calls are recoverable and use the same dim system grouping:
`read failed: <addr> out of range`, `write failed: <addr> out of range`, or
`execute failed: <addr> out of range`.
The structured result is sent back to the model as `function_call_output`; short user-facing
results such as memory bytes may also render as normal answer text when the model responds.
Seed dispatches a captured tool call only after both the response completion
event and the HTTP response terminator arrive. A captured item alone never
authorizes execution.
The agentic loop requests one tool call at a time and carries a bounded journal
of completed results. It allows eight calls per human turn. The last result is
still sent to the model with tools disabled, so reaching that limit produces a
final answer rather than silently returning to input. An unexpected further
call is rejected through the visible response-failure path. After the model's
answer, control returns to the `>` prompt.
