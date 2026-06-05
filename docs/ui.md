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
none         boot sector, loader, CORE.SYS load
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

The splash is only a short ready handoff animation. No loading, probing,
network negotiation, key setup, or environment setup happens during the splash.

Menus use color to indicate selection. The selected item uses the active prompt
color; inactive items use the dim prompt color. Do not add marker glyphs solely
to show selection.

Agent setup uses a drill-down panel stack under one bright topic prompt. The
active panel keeps the selected row bright and inactive rows dim. When a
selection opens the next panel, the selected value slides left and the selected
agent's required fields appear to its right. `Enter` submits the current form.
`Esc` closes the current panel and slides the selected value back to the
previous menu. Opening a child panel does not play a new attention tone.

When an agent needs more than one typed value, those values stay on the same
panel. For LiteLLM, `server?` and `key?` appear together; Up and Down move
field focus, and typed characters edit the focused field.

Text fields, including `key?`, render plain typed characters. Long values stay
inside the field row by showing the visible tail without wrapping.

The cursor stays hidden unless a field is actively accepting typed input.

## Default Prompt Interface

After boot, Seed renders a model greeting and takes prompts at a `>` marker. User input
shows in bright text and streamed model responses in normal text; turns reuse one live TLS
session.

When the rolling conversation window fills (Build 9), Seed compacts it: a dim status line,
fast-typed like the boot banner, reads `compacting context`. The one-line recap the model
emits to drive that compaction is captured silently and never drawn — the user sees only the
status line, then the answer.

## Tool Calls

When the model emits a tool command mid-stream — `$r`/`$w`/`$x` (read, write, or execute
memory, Build 10) — Seed never draws the raw command. It suppresses the `$`-line from the
bright screen and renders one dim action line in its place: `read from <addr>`, `write to
<addr>`, or `jump to <addr>`, so the user sees *what* the agent touched, never the syntax.
The full result — the bytes read, or `ax`/`cf` after an execute — is written back only into
the model's conversation window, not the screen: the agent acts on its own output while the
user's view stays clean. The agentic loop auto-continues until the model stops calling
tools, then control returns to the `>` prompt.
