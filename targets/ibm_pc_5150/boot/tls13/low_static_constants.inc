; Canonical resident low-constant image shared by the legacy phase publisher,
; the 8088-route state guard, and the conforming 286 parent boundary.
; The labels surrounding this include define and check the destination length.

    db 'master secret'
    db 'client finished'
    db 'server finished'
    db 'key expansion'
    dw 0x7865, 0x6170, 0x646e, 0x3320
    dw 0x2d32, 0x7962, 0x6574, 0x6b20
    db 0xfb
    times 15 db 0xff
    db 0x03
    dw 0xe667, 0x6a09, 0xae85, 0xbb67
    dw 0xf372, 0x3c6e, 0xf53a, 0xa54f
    dw 0x527f, 0x510e, 0x688c, 0x9b05
    dw 0xd9ab, 0x1f83, 0xcd19, 0x5be0
