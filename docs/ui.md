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
" "          Seed reset prep
"." dark     local machine and adapter readiness
"o" dark     internet readiness
"o" bright   agent/environment readiness
"+"          fatal error marker
```

Questions should use the low attention tone, blink the current marker while
keeping its phase color, then fast-type the prompt and minimal fields. Question
prompts are always bright and end with `?`. Fatal errors should switch the
status marker first, play the low failure tone, fast-type the error text, then
fast-type a minimal `retry` / `restart` menu.

`retry` reruns stage 2 from its beginning without rereading floppy sectors.
`restart` performs a warm machine restart through BIOS.

Menus use color to indicate selection. The selected item uses the active prompt
color; inactive items use the dim prompt color. Do not add marker glyphs solely
to show selection.

The cursor stays hidden unless a field is actively accepting typed input.
