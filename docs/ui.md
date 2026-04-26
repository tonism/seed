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
"+"          fatal error marker
```

Questions should use the low attention tone, blink the current marker while
keeping its phase color, then fast-type the prompt and minimal fields. Question
prompts are always bright and end with `?`. Fatal errors should switch the
status marker first, play the low failure tone, fast-type the error text, then
fast-type a minimal `retry` / `restart` menu.

`retry` reruns from the dark `"."` HAL setup phase without rereading floppy
sectors. `restart` performs a warm machine restart through BIOS.

The splash is only a short ready handoff animation. No loading, probing,
network negotiation, key setup, or environment setup happens during the splash.

Menus use color to indicate selection. The selected item uses the active prompt
color; inactive items use the dim prompt color. Do not add marker glyphs solely
to show selection.

The cursor stays hidden unless a field is actively accepting typed input.
