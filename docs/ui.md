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
" "   active phase below 33%
"."   active phase from 33% to 66%
"o"   active phase above 66%
"+"   fatal error marker
```

Questions should use the low attention tone, then fast-type the prompt and
minimal fields. Fatal errors should switch the status marker first, play the low
failure tone, then fast-type the error text.

Menus use color to indicate selection. The selected item uses the active prompt
color; inactive items use the dim prompt color. Do not add marker glyphs solely
to show selection.

The cursor stays hidden unless a field is actively accepting typed input.
