; Public-input P-384 ECDSA verification. 16-bit limbs, bounded Montgomery
; products and binary inverses. No secrets or signing operation exist here.
; Scratch is the retired low module overlay; the low controller is code-only.
; Fixed public point formulas are encoded as immutable arithmetic tuples.
; This saves instruction bytes; no input byte selects an operation or address.
%assign PMODE 0
pidx_pc_b_mont equ 0
pidx_pc_one equ 1
pidx_pc_r2_n equ 2
pidx_pc_r2_p equ 3
pidx_pi_x equ 4
pidx_pi_y equ 5
pidx_pt0 equ 6
pidx_pt1 equ 7
pidx_pt2 equ 8
pidx_pt3 equ 9
pidx_pt4 equ 10
pidx_pt5 equ 11
pidx_pt6 equ 12
pidx_pt7 equ 13
pidx_pt8 equ 14
pidx_pv_qx equ 15
pidx_pv_qy equ 16
pidx_pv_r equ 17
pidx_pv_u1 equ 18
pidx_pv_u2 equ 19
pidx_pv_w equ 20
pidx_pv_x equ 21
pidx_pv_y equ 22
pidx_pv_z equ 23
pidx_pv_zj equ 24
pidx_pc_one_p equ 25
pidx_pv_gx equ 26
pidx_pv_gy equ 27
pidx_pv_gqx equ 28
pidx_pv_gqy equ 29
%define PWORDS 24
%define PBYTES 48
%define PW 0x4230
%assign PS PW
%macro slot 1
%1 equ PS
%assign PS PS+PBYTES
%endmacro
slot pv_r
slot pv_s
slot pv_z
slot pv_w
slot pv_u1
slot pv_u2
slot pv_x
slot pv_y
slot pv_zj
slot pv_gx
slot pv_gy
slot pv_qx
slot pv_qy
slot pv_gqx
slot pv_gqy
slot pt0
slot pt1
slot pt2
slot pt3
slot pt4
slot pt5
slot pt6
slot pt7
slot pt8
slot pi_u
slot pi_v
slot pi_x
slot pi_y
slot pi_temp
mm_prod equ PS
mm_a equ mm_prod+100
mm_b equ mm_a+2
mm_out equ mm_b+2
mm_word equ mm_out+2
mm_pos equ mm_word+2
mm_i equ mm_pos+2
pm_mod equ mm_i+2
pm_n0 equ pm_mod+2
pv_anchor equ pm_n0+2
pv_sig equ pv_anchor+2
pv_sig_end equ pv_sig+2
pv_digest equ pv_sig_end+2
pv_mask equ pv_digest+2
pv_index equ pv_mask+2
pi_count equ pv_index+2
pi_output equ pi_count+2
pv_joint_inf equ pi_output+2
pp_pc equ pv_joint_inf+2
pp_op equ pp_pc+2
pv_end equ pp_op+2
%if pv_end > 0x5000
%error "P384 scratch exceeds retired module prefix"
%endif

%macro PCOPY 2
%if PMODE
 db pidx_%1 << 2,pidx_%2,0
%else
 mov si,%2
 mov di,%1
 call pm_copy
%endif
%endmacro
%macro PMUL 3
%if PMODE
 db (pidx_%1 << 2) | 1,pidx_%2,pidx_%3
%else
 mov si,%2
 mov di,%3
 mov bx,%1
 call pm_mul
%endif
%endmacro
%macro PADD 3
%if PMODE
 db (pidx_%1 << 2) | 2,pidx_%2,pidx_%3
%else
 mov si,%2
 mov di,%3
 mov bx,%1
 call pm_add
%endif
%endmacro
%macro PSUB 3
%if PMODE
 db (pidx_%1 << 2) | 3,pidx_%2,pidx_%3
%else
 mov si,%2
 mov di,%3
 mov bx,%1
 call pm_sub
%endif
%endmacro

; SI=a DI=b -> CF a<b, ZF a=b. Preserve all inputs and other registers.
pm_cmp:
 push ax
 push cx
 push si
 push di
 add si,PBYTES-2
 add di,PBYTES-2
 mov cx,PWORDS
.loop:
 mov ax,[si]
 cmp ax,[di]
 jne .done
 lea si,[si-2]
 lea di,[di-2]
 loop .loop
.done:
 pop di
 pop si
 pop cx
 pop ax
 ret
pm_copy:
 push cx
 push si
 push di
 mov cx,PWORDS
 rep movsw
 pop di
 pop si
 pop cx
 ret
; SI -> ZF for zero. Preserve inputs.
pm_zero:
 push ax
 push cx
 push si
 xor ax,ax
 mov cx,PWORDS
.loop:
 or ax,[si]
 add si,2
 loop .loop
 or ax,ax
 pop si
 pop cx
 pop ax
 ret
; DI <- zero, no other memory touched.
pm_clear:
 push ax
 push cx
 push di
 xor ax,ax
 mov cx,PWORDS
 rep stosw
 pop di
 pop cx
 pop ax
 ret
; SI=a DI=b BX=out. Canonical inputs, alias-safe.
pm_add:
 push bx
 mov cx,PWORDS
 clc
.loop:
 mov ax,[si]
 adc ax,[di]
 mov [bx],ax
 lea si,[si+2]
 lea di,[di+2]
 lea bx,[bx+2]
 loop .loop
 pop bx
 jc pm_sub_mod
 mov si,bx
 mov di,[pm_mod]
 call pm_cmp
 jae pm_sub_mod
 ret
pm_sub_mod:
 mov si,[pm_mod]
 mov cx,PWORDS
 clc
.loop:
 mov ax,[bx]
 sbb ax,[si]
 mov [bx],ax
 lea si,[si+2]
 lea bx,[bx+2]
 loop .loop
 ret
pm_sub:
 push bx
 mov cx,PWORDS
 clc
.loop:
 mov ax,[si]
 sbb ax,[di]
 mov [bx],ax
 lea si,[si+2]
 lea di,[di+2]
 lea bx,[bx+2]
 loop .loop
 pop bx
 jnc .done
 mov si,[pm_mod]
 mov cx,PWORDS
 clc
.add:
 mov ax,[bx]
 adc ax,[si]
 mov [bx],ax
 lea si,[si+2]
 lea bx,[bx+2]
 loop .add
.done:
 ret

; Full 24x24 product followed by 24 Montgomery cancellation rows.
; For 0<=a,b<m, REDC is <2m; one final subtraction is sufficient.
pm_mul:
 mov [mm_a],si
 mov [mm_b],di
 mov [mm_out],bx
 xor ax,ax
 mov di,mm_prod
 mov cx,50
 rep stosw
 mov word [mm_i],0
.product:
 mov si,[mm_a]
 mov bx,[mm_i]
 mov ax,[si+bx]
 mov [mm_word],ax
 lea bx,[bx+mm_prod]
 mov di,[mm_b]
 xor bp,bp
 mov cx,PWORDS
 call pm_row
 add word [mm_i],2
 cmp word [mm_i],PBYTES
 jne .product
 mov word [mm_i],0
.reduce:
 mov bx,[mm_i]
 mov ax,[bx+mm_prod]
 mul word [pm_n0]
 mov [mm_word],ax
 lea bx,[bx+mm_prod]
 mov di,[pm_mod]
 xor bp,bp
 mov cx,PWORDS
 call pm_row
 add word [mm_i],2
 cmp word [mm_i],PBYTES
 jne .reduce
 mov si,mm_prod+PBYTES
 mov di,[mm_out]
 call pm_copy
 mov bx,di
 cmp word [mm_prod+2*PBYTES],0
 jne pm_sub_mod
 mov si,bx
 mov di,[pm_mod]
 call pm_cmp
 jae pm_sub_mod
 ret
pm_row:
.loop:
 mov ax,[mm_word]
 mul word [di]
 add ax,[bx]
 adc dx,0
 add ax,bp
 adc dx,0
 mov [bx],ax
 mov bp,dx
 add bx,2
 add di,2
 loop .loop
 add [bx],bp
 jnc .done
.carry:
 lea bx,[bx+2]
 adc word [bx],0
 jc .carry
.done:
 ret

; In-place right shift with carry from caller.
pm_shr:
 lea si,[si+PBYTES-2]
 mov cx,PWORDS
.loop:
 rcr word [si],1
 lea si,[si-2]
 loop .loop
 ret
; SI -> SI/2 mod m. Canonical input; propagate the full addition carry.
pm_half:
 test byte [si],1
 jz .even
 push si
 mov di,[pm_mod]
 mov cx,PWORDS
 clc
.add:
 mov ax,[si]
 adc ax,[di]
 mov [si],ax
 lea si,[si+2]
 lea di,[di+2]
 loop .add
 pop si
 jmp pm_shr
.even:
 clc
 jmp pm_shr
; SI=a DI=b -> a-=b (caller established a>=b).
pm_raw_sub:
 mov cx,PWORDS
 clc
.loop:
 mov ax,[si]
 sbb ax,[di]
 mov [si],ax
 lea si,[si+2]
 lea di,[di+2]
 loop .loop
 ret
; Canonical nonzero SI, DI=output. Binary extended GCD, bounded by 4096
; iterations; this is public verification work. Zero/noninvertible refuses.
pm_inverse:
 mov [pi_output],di
 call pm_zero
 jz .bad
 mov di,[pm_mod]
 call pm_cmp
 jae .bad
 mov di,pi_u
 call pm_copy
 PCOPY pi_v,[pm_mod]
 mov di,pi_x
 call pm_clear
 inc word [pi_x]
 mov di,pi_y
 call pm_clear
 mov word [pi_count],4096
.loop:
 mov si,pi_u
 call pm_one
 jz .x
 mov si,pi_v
 call pm_one
 jz .y
 dec word [pi_count]
 jz .bad
 mov si,pi_u
 call pm_zero
 jz .bad
 mov si,pi_v
 call pm_zero
 jz .bad
 test byte [pi_u],1
 jnz .v
 mov si,pi_u
 clc
 call pm_shr
 mov si,pi_x
 call pm_half
 jmp .loop
.v:
 test byte [pi_v],1
 jnz .subtract
 mov si,pi_v
 clc
 call pm_shr
 mov si,pi_y
 call pm_half
 jmp .loop
.subtract:
 mov si,pi_u
 mov di,pi_v
 call pm_cmp
 jb .v_sub
 call pm_raw_sub
 PSUB pi_x,pi_x,pi_y
 jmp .loop
.v_sub:
 mov si,pi_v
 mov di,pi_u
 call pm_raw_sub
 PSUB pi_y,pi_y,pi_x
 jmp .loop
.x:
 mov si,pi_x
 jmp .copy
.y:
 mov si,pi_y
.copy:
 mov di,[pi_output]
 call pm_copy
 clc
 ret
.bad:
 stc
 ret
pm_one:
 push ax
 push cx
 push si
 mov ax,[si]
 xor ax,1
 add si,2
 mov cx,PWORDS-1
.loop:
 or ax,[si]
 add si,2
 loop .loop
 or ax,ax
 pop si
 pop cx
 pop ax
 ret

; Jacobian a=-3 double, delta=Z^2 gamma=Y^2 beta=X*gamma.
pp_double:
 mov si,pv_zj
 call pm_zero
 jz .done
 mov si,pv_y
 call pm_zero
 jz pp_infinity
 call pp_program
%assign PMODE 1
 PMUL pt0,pv_zj,pv_zj
 PMUL pt1,pv_y,pv_y
 PMUL pt2,pv_x,pt1
 PSUB pt3,pv_x,pt0
 PADD pt4,pv_x,pt0
 PMUL pt3,pt3,pt4
 PADD pt4,pt3,pt3
 PADD pt3,pt4,pt3
 PMUL pt4,pt3,pt3
 PADD pt5,pt2,pt2
 PADD pt5,pt5,pt5
 PADD pt6,pt5,pt5
 PSUB pt4,pt4,pt6
 PADD pt6,pv_y,pv_zj
 PMUL pt6,pt6,pt6
 PSUB pt6,pt6,pt1
 PSUB pv_zj,pt6,pt0
 PSUB pt5,pt5,pt4
 PMUL pt5,pt3,pt5
 PMUL pt1,pt1,pt1
 PADD pt1,pt1,pt1
 PADD pt1,pt1,pt1
 PADD pt1,pt1,pt1
 PSUB pv_y,pt5,pt1
 PCOPY pv_x,pt4
 db 0
%assign PMODE 0
.done:
 ret
pp_infinity:
 mov di,pv_zj
 jmp pm_clear
; SI=affine x, DI=affine y, Montgomery form. Preserve point in pt7/pt8.
pp_add:
 push di
 mov di,pt7
 call pm_copy
 pop si
 mov di,pt8
 call pm_copy
 mov si,pv_zj
 call pm_zero
 jnz .finite
 call pp_program
%assign PMODE 1
 PCOPY pv_x,pt7
 PCOPY pv_y,pt8
 PCOPY pv_zj,pc_one_p
 db 0
%assign PMODE 0
 ret
.finite:
 call pp_program
%assign PMODE 1
 PMUL pt0,pv_zj,pv_zj
 PMUL pt1,pt7,pt0
 PMUL pt2,pt8,pv_zj
 PMUL pt2,pt2,pt0
 PSUB pt1,pt1,pv_x
 PSUB pt2,pt2,pv_y
 db 0
%assign PMODE 0
 mov si,pt1
 call pm_zero
 jnz .ordinary
 mov si,pt2
 call pm_zero
 jz pp_double
 jmp pp_infinity
.ordinary:
 call pp_program
%assign PMODE 1
 PMUL pt3,pt1,pt1
 PADD pt4,pt3,pt3
 PADD pt4,pt4,pt4
 PMUL pt5,pt1,pt4
 PADD pt2,pt2,pt2
 PMUL pt4,pv_x,pt4
 PMUL pt6,pt2,pt2
 PSUB pt6,pt6,pt5
 PSUB pt6,pt6,pt4
 PSUB pt6,pt6,pt4
 PSUB pt7,pt4,pt6
 PMUL pt7,pt2,pt7
 PMUL pt5,pv_y,pt5
 PADD pt5,pt5,pt5
 PSUB pv_y,pt7,pt5
 PADD pt1,pv_zj,pt1
 PMUL pt1,pt1,pt1
 PSUB pt1,pt1,pt0
 PSUB pv_zj,pt1,pt3
 PCOPY pv_x,pt6
 db 0
%assign PMODE 0
 ret
; Convert Jacobian to ordinary affine; leave pv_x/pv_y in Montgomery form.
pp_normalize:
 mov si,pv_zj
 call pm_zero
 jz .bad
 PMUL pt0,pv_zj,pc_one
 mov si,pt0
 mov di,pt1
 call pm_inverse
 jc .bad
 call pp_program
%assign PMODE 1
 PMUL pt1,pt1,pc_r2_p
 PMUL pt2,pt1,pt1
 PMUL pv_x,pv_x,pt2
 PMUL pt2,pt2,pt1
 PMUL pv_y,pv_y,pt2
 PCOPY pv_zj,pc_one_p
 db 0
%assign PMODE 0
 clc
 ret
.bad:
 stc
 ret
; Validate and convert affine pair SI -> pv_qx/pv_qy, never trust off-curve.
pp_validate:
 push si
 mov di,pc_p
 call pm_cmp
 pop si
 jae .bad
 push si
 add si,PBYTES
 call pm_cmp
 pop si
 jae .bad
 push si
 mov di,pc_r2_p
 mov bx,pv_qx
 call pm_mul
 pop si
 add si,PBYTES
 mov di,pc_r2_p
 mov bx,pv_qy
 call pm_mul
 call pp_program
%assign PMODE 1
 PMUL pt0,pv_qx,pv_qx
 PMUL pt0,pt0,pv_qx
 PSUB pt0,pt0,pv_qx
 PSUB pt0,pt0,pv_qx
 PSUB pt0,pt0,pv_qx
 PADD pt0,pt0,pc_b_mont
 PMUL pt1,pv_qy,pv_qy
 db 0
%assign PMODE 0
 mov si,pt0
 mov di,pt1
 call pm_cmp
 jne .bad
 clc
 ret
.bad:
 stc
 ret

; Strict DER ECDSA (r,s): 8..104 bytes, each integer 1..48 significant bytes,
; minimal positive encoding, 0<r,s<n. Caller supplies exact sequence length.
pv_parse:
 mov si,[pv_sig]
 cmp byte [si],0x30
 jne .bad
 xor ax,ax
 mov al,[si+1]
 add ax,2
 add ax,si
 cmp ax,[pv_sig_end]
 jne .bad
 add si,2
 mov di,pv_r
 call pv_integer
 jc .bad
 mov di,pv_s
 call pv_integer
 jc .bad
 cmp si,[pv_sig_end]
 jne .bad
 clc
 ret
.bad:
 stc
 ret
pv_integer:
 cmp si,[pv_sig_end]
 jae .bad
 cmp byte [si],2
 jne .bad
 inc si
 cmp si,[pv_sig_end]
 jae .bad
 xor cx,cx
 mov cl,[si]
 inc si
 jcxz .bad
 cmp cx,PBYTES+1
 ja .bad
 mov ax,si
 add ax,cx
 jc .bad
 cmp ax,[pv_sig_end]
 ja .bad
 test byte [si],0x80
 jnz .bad
 cmp byte [si],0
 jne .width
 cmp cx,1
 jbe .bad
 test byte [si+1],0x80
 jz .bad
 inc si
 dec cx
.width:
 cmp cx,PBYTES
 ja .bad
 call pm_clear
 push di
 add di,cx
 dec di
.copy:
 lodsb
 mov [di],al
 dec di
 loop .copy
 pop di
 push si
 mov si,di
 call pm_zero
 jz .bad_pop
 mov di,pc_n
 call pm_cmp
 jae .bad_pop
 pop si
 clc
 ret
.bad_pop:
 pop si
.bad:
 stc
 ret

; SI=digest (48-byte big endian), DI=DER, CX=length, BP=affine anchor.
p384_verify:
 cld
 cmp cx,8
 jb .bad
 cmp cx,104
 ja .bad
 mov [pv_digest],si
 mov [pv_sig],di
 add cx,di
 jc .bad
 mov [pv_sig_end],cx
 mov [pv_anchor],bp
 call pv_parse
 jc .bad
 mov si,[pv_digest]
 mov di,pv_z+PBYTES-1
 mov cx,PBYTES
.digest:
 lodsb
 mov [di],al
 dec di
 loop .digest
 mov word [pm_mod],pc_n
 mov word [pm_n0],PC_N0_N
 mov si,pv_z
 mov di,pc_n
 call pm_cmp
 jb .digest_ok
 mov bx,pv_z
 call pm_sub_mod
.digest_ok:
 mov si,pv_s
 mov di,pv_w
 call pm_inverse
 jc .bad
 call pp_program
%assign PMODE 1
 PMUL pt0,pv_z,pc_r2_n
 PMUL pv_u1,pt0,pv_w
 PMUL pt0,pv_r,pc_r2_n
 PMUL pv_u2,pt0,pv_w
 db 0
%assign PMODE 0
 mov word [pm_mod],pc_p
 mov word [pm_n0],1
 mov si,pc_g
 call pp_validate
 jc .bad
 call pp_program
%assign PMODE 1
 PCOPY pv_gx,pv_qx
 PCOPY pv_gy,pv_qy
 db 0
%assign PMODE 0
 mov si,[pv_anchor]
 call pp_validate
 jc .bad
 call pp_infinity
 mov si,pv_gx
 mov di,pv_gy
 call pp_add
 mov si,pv_qx
 mov di,pv_qy
 call pp_add
 mov word [pv_joint_inf],0
 call pp_normalize
 jnc .joint_ready
 inc word [pv_joint_inf]
.joint_ready:
 call pp_program
%assign PMODE 1
 PCOPY pv_gqx,pv_x
 PCOPY pv_gqy,pv_y
 db 0
%assign PMODE 0
 call pp_infinity
 mov word [pv_index],PBYTES-2
 mov word [pv_mask],0x8000
.bit:
 call pp_double
 xor ax,ax
 mov bx,[pv_index]
 mov dx,[pv_mask]
 test [pv_u1+bx],dx
 jz .no1
 inc ax
.no1:
 test [pv_u2+bx],dx
 jz .no2
 add ax,2
.no2:
 or ax,ax
 jz .next
 cmp ax,1
 je .g
 cmp ax,2
 je .q
 cmp word [pv_joint_inf],0
 jne .next
 mov si,pv_gqx
 jmp .add
.g:
 mov si,pv_gx
 jmp .add
.q:
 mov si,pv_qx
.add:
 mov di,si
 add di,PBYTES
 call pp_add
.next:
 shr word [pv_mask],1
 jnz .bit
 sub word [pv_index],2
 jc .finish
 mov word [pv_mask],0x8000
 jmp .bit
.finish:
 call pp_normalize
 jc .bad
 PMUL pt0,pv_x,pc_one
 mov si,pt0
 mov di,pc_n
 call pm_cmp
 jb .compare
 mov word [pm_mod],pc_n
 mov bx,pt0
 call pm_sub_mod
.compare:
 mov si,pt0
 mov di,pv_r
 call pm_cmp
 jne .bad
 clc
 ret
.bad:
 stc
 ret

; Execute only the fixed tuple stream immediately after the CALL. All input
; and output slots are selected by this immutable program, never TLS data.
pp_program:
 pop word [pp_pc]
.next:
 mov si,[pp_pc]
 lodsb
 or al,al
 jz .done
 xor ah,ah
 push ax
 and ax,3
 shl ax,1
 mov bx,ax
 mov ax,[cs:pp_functions+bx]
 mov [pp_op],ax
 pop ax
 shr ax,1
 shr ax,1
 call .lookup
 push ax
 call .slot
 push ax
 call .slot
 mov di,ax
 mov [pp_pc],si
 pop si
 pop bx
 call word [cs:pp_op]
 jmp .next
.done:
 jmp si
.slot:
 lodsb
 xor ah,ah
.lookup:
 shl ax,1
 mov bx,ax
 mov ax,[cs:pp_slots+bx]
 ret
pp_copy:
 mov di,bx
 jmp pm_copy
pp_functions dw pp_copy,pm_mul,pm_add,pm_sub
pp_slots:
 dw pc_b_mont,pc_one,pc_r2_n,pc_r2_p,pi_x,pi_y,pt0,pt1,pt2,pt3,pt4,pt5,pt6,pt7,pt8,pv_qx,pv_qy,pv_r,pv_u1,pv_u2,pv_w,pv_x,pv_y,pv_z,pv_zj,pc_one_p,pv_gx,pv_gy,pv_gqx,pv_gqy
