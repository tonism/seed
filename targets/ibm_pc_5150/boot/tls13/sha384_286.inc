; Bounded one-shot SHA-384 over at most 1024 public certificate bytes.
; FIPS 180-4 schedule/rounds on four little-endian 16-bit words per lane.
s_h equ 0x5000
s_v equ 0x5040
s_w equ 0x5080
s_t1 equ 0x5300
s_t2 equ 0x5308
s_tmp0 equ 0x5310
s_tmp1 equ 0x5318
s_digest equ 0x5330
s_input equ 0x5360
s_len equ 0x5362
s_block equ 0x5364
s_end equ 0x5366
s_wp equ 0x5368
s_kp equ 0x536a
s_round equ 0x536c
s_sigsrc equ 0x536e
s_sigdst equ 0x5370
s_sigcfg equ 0x5372
s_msg equ 0x5400
s_scratch_end equ 0x5900

; SI input, CX length -> s_digest, CF. Caller supplies a disjoint read-only
; input span; the product binds it to the strict parser's near TBS span.
sha384_hash:
 cld
 cmp cx,1024
 ja .bad
 mov ax,si
 add ax,cx
 jc .bad
 mov [s_input],si
 mov [s_len],cx
 mov di,s_h
 xor ax,ax
 push cx
 mov cx,(s_digest-s_h)/2
 rep stosw
 mov di,s_msg
 mov cx,(s_scratch_end-s_msg)/2
 rep stosw
 pop cx
 mov si,[s_input]
 mov di,s_msg
 rep movsb
 mov byte [di],0x80
 mov ax,[s_len]
 add ax,17+127
 and ax,0xff80
 add ax,s_msg
 mov [s_end],ax
 mov di,ax
 mov ax,[s_len]
 shl ax,1
 shl ax,1
 shl ax,1
 xchg al,ah
 mov [di-2],ax
 mov si,sc_iv
 mov di,s_h
 mov cx,32
 rep movsw
 mov word [s_block],s_msg
.block:
 mov si,[s_block]
 mov di,s_w
 mov cx,16
.load:
 mov ax,[si]
 xchg al,ah
 mov [di+6],ax
 mov ax,[si+2]
 xchg al,ah
 mov [di+4],ax
 mov ax,[si+4]
 xchg al,ah
 mov [di+2],ax
 mov ax,[si+6]
 xchg al,ah
 mov [di],ax
 add si,8
 add di,8
 loop .load
 mov word [s_wp],s_w+128
.expand:
 mov si,[s_wp]
 sub si,16
 mov di,s_t1
 mov bx,sc_small1
 call sha_sigma
 mov si,[s_wp]
 sub si,56
 mov di,s_t1
 call sha_add64
 mov si,[s_wp]
 sub si,120
 mov di,s_t2
 mov bx,sc_small0
 call sha_sigma
 mov si,[s_wp]
 sub si,128
 mov di,s_t1
 call sha_add64
 mov si,s_t2
 mov di,s_t1
 call sha_add64
 mov si,s_t1
 mov di,[s_wp]
 call sha_copy64
 add word [s_wp],8
 cmp word [s_wp],s_w+640
 jne .expand
 mov si,s_h
 mov di,s_v
 mov cx,32
 rep movsw
 mov word [s_wp],s_w
 mov word [s_kp],sc_k
 mov word [s_round],80
.round:
 mov si,s_v+32
 mov di,s_t1
 mov bx,sc_big1
 call sha_sigma
 xor bx,bx
.ch:
 mov ax,[s_v+40+bx]
 xor ax,[s_v+48+bx]
 and ax,[s_v+32+bx]
 xor ax,[s_v+48+bx]
 mov [s_tmp0+bx],ax
 add bx,2
 cmp bx,8
 jne .ch
 mov si,s_tmp0
 mov di,s_t1
 call sha_add64
 mov si,s_v+56
 mov di,s_t1
 call sha_add64
 mov si,[s_kp]
 mov di,s_t1
 call sha_add64
 mov si,[s_wp]
 mov di,s_t1
 call sha_add64
 mov si,s_v
 mov di,s_t2
 mov bx,sc_big0
 call sha_sigma
 xor bx,bx
.maj:
 mov ax,[s_v+bx]
 xor ax,[s_v+8+bx]
 and ax,[s_v+16+bx]
 mov dx,[s_v+bx]
 and dx,[s_v+8+bx]
 xor ax,dx
 mov [s_tmp0+bx],ax
 add bx,2
 cmp bx,8
 jne .maj
 mov si,s_tmp0
 mov di,s_t2
 call sha_add64
 mov si,s_v+54
 mov di,s_v+62
 mov cx,28
 std
 rep movsw
 cld
 mov si,s_t1
 mov di,s_v+32
 call sha_add64
 mov si,s_t1
 mov di,s_v
 call sha_copy64
 mov si,s_t2
 mov di,s_v
 call sha_add64
 add word [s_wp],8
 add word [s_kp],8
 dec word [s_round]
 jnz .round
 mov si,s_v
 mov di,s_h
 mov bx,8
.sum:
 call sha_add64
 dec bx
 jnz .sum
 add word [s_block],128
 mov ax,[s_block]
 cmp ax,[s_end]
 jne .block
 mov si,s_h
 mov di,s_digest
 mov cx,6
.emit:
 mov ax,[si+6]
 xchg al,ah
 stosw
 mov ax,[si+4]
 xchg al,ah
 stosw
 mov ax,[si+2]
 xchg al,ah
 stosw
 mov ax,[si]
 xchg al,ah
 stosw
 add si,8
 loop .emit
 clc
 ret
.bad:
 stc
 ret

; Lane helpers advance SI and DI, clobber AX/CX, preserve BX/DX/BP.
sha_copy64:
 mov cx,4
 rep movsw
 ret
sha_add64:
 mov cx,4
 clc
.loop:
 lodsw
 adc ax,[di]
 stosw
 loop .loop
 ret
sha_xor64:
 mov cx,4
.loop:
 lodsw
 xor ax,[di]
 stosw
 loop .loop
 ret
; Rotate/shift source into destination, preserving destination start for the
; bit loop. Counts are fixed public SHA constants, never message-dependent.
sha_rotr64:
 push cx
 push di
 call sha_copy64
 pop di
 pop cx
.loop:
 mov ax,[di]
 shr ax,1
 rcr word [di+6],1
 rcr word [di+4],1
 rcr word [di+2],1
 rcr word [di],1
 loop .loop
 ret
sha_shr64:
 push cx
 push di
 call sha_copy64
 pop di
 pop cx
.loop:
 clc
 rcr word [di+6],1
 rcr word [di+4],1
 rcr word [di+2],1
 rcr word [di],1
 loop .loop
 ret
; BX -> {rotation0, rotation1, rotation2/shift, last_is_shift}.
sha_sigma:
 mov [s_sigsrc],si
 mov [s_sigdst],di
 mov [s_sigcfg],bx
 xor cx,cx
 mov cl,[bx]
 mov di,s_tmp0
 call sha_rotr64
 mov si,[s_sigsrc]
 mov bx,[s_sigcfg]
 xor cx,cx
 mov cl,[bx+1]
 mov di,s_tmp1
 call sha_rotr64
 mov si,s_tmp1
 mov di,s_tmp0
 call sha_xor64
 mov si,[s_sigsrc]
 mov bx,[s_sigcfg]
 xor cx,cx
 mov cl,[bx+2]
 mov di,s_tmp1
 cmp byte [bx+3],0
 jne .shift
 call sha_rotr64
 jmp .combine
.shift:
 call sha_shr64
.combine:
 mov si,s_tmp1
 mov di,s_tmp0
 call sha_xor64
 mov si,s_tmp0
 mov di,[s_sigdst]
 call sha_copy64
 ret
sc_big0 db 28,34,39,0
sc_big1 db 14,18,41,0
sc_small0 db 1,8,7,1
sc_small1 db 19,61,6,1
