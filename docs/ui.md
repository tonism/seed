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
" "          project init
"." dark     HAL setup
"o" dark     internet prep
"o" bright   agent prep
red marker   fatal error state; keep the current phase glyph
```

Questions should use the low attention tone, blink the current marker while
keeping its phase color, then fast-type the prompt and minimal fields. Question
prompts are always bright and end with `?`. Fatal errors should turn the
current status marker red, play the low failure tone, fast-type the error text,
then fast-type a minimal `retry` / `restart` menu.

`retry` reruns from the dark `"."` HAL setup phase without rereading floppy
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
