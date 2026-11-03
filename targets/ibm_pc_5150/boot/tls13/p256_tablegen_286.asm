; Callable S286MOD2 width-7 P-256 comb-table generator.
;
; Input is one validated-or-untrusted affine point in ordinary little-endian
; P-256 field representation.  This module validates it, builds all 127
; projective subset sums, and batch-normalizes them with one inversion.  The
; 15,? KiB far scratch is explicit in the operation descriptor; no table or
; private state is embedded by the host.  The operation boundary is deliberately
; narrower than a general P-256 service: it accepts only the two affine-point
; slots emitted by the fixed authentication controller and the corresponding
; high-reservation table destination.

bits 16
cpu 8086

%include "core/layout.inc"
%include "tls13/tls13_286_abi.inc"
org tls13_286_module_load

table_points equ 127
table_point_bytes equ 96
table_prefix_bytes equ 32
table_projective_bytes equ table_points * table_point_bytes
table_prefix_off equ table_projective_bytes
tablegen_scratch_bytes equ \
    table_projective_bytes + table_points * table_prefix_bytes
table_generator_phys equ 0x3220
table_leaf_phys equ 0x32ad
table_module_stack_bytes equ 512

module_header:
    db 'S286MOD2'
    dw tls13_286_abi_version
    dw tls13_286_mod_kind_p256_tablegen
    dw image_end - module_header
    dw module_entry - module_header
    dw tls13_286_state_bytes
    dw table_module_stack_bytes
    dw tls13_286_mod_flag_one_shot
    times tls13_286_mod_header_bytes - ($ - module_header) db 0

module_entry:
    ; Reject an unusable return stack before storing even the caller's BP.
    ; A valid call has enough room for the advertised stack plus that saved BP.
    mov dx, sp
    test dx, 1
    jnz module_error_stack
    cmp dx, tls13_286_module_limit + table_module_stack_bytes + 2
    jb module_error_stack
    cmp dx, 0x8000
    jae module_error_stack
    push bp
    cld
    or di, di
    jnz module_error_abi
    cmp ax, tls13_286_mod_op_p256_tablegen
    jne module_error_abi
    cmp si, tls13_286_controller_load
    jb module_error_bounds
    cmp si, tls13_286_controller_limit - tls13_286_desc_bytes
    ja module_error_bounds
    cmp word [si + tls13_286_desc_flags], 0
    jne module_error_abi
    cmp word [si + tls13_286_desc_op], ax
    jne module_error_abi
    cmp bx, tls13_286_root_state_loader
    jne module_error_bounds
    cmp word [bx + tls13_286_state_cache_capacity], \
        tls13_286_pack_cache_bytes
    jne module_error_bounds
    mov dx, [bx + tls13_286_state_cache_seg]
    cmp dx, 0x7000
    jb module_error_bounds
    cmp dx, 0x9000
    ja module_error_bounds
    test dx, 0x003f
    jnz module_error_bounds
    mov [module_crypto_seg], dx
    mov [table_desc], si

    mov bx, si
    add bx, tls13_286_desc_input2
    call module_validate_zero_span
    jc module_error_bounds
    add bx, tls13_286_span_bytes
    call module_validate_zero_span
    jc module_error_bounds
    mov bx, si
    add bx, tls13_286_desc_output1
    call module_validate_zero_span
    jc module_error_bounds

    mov bx, si
    add bx, tls13_286_desc_input0
    call module_select_point
    jc module_error_bounds
    call module_validate_desc_point_disjoint
    jc module_error_bounds
    mov dx, 64
    mov di, table_input_x
    call module_copy_span_to_near

    mov bx, [table_desc]
    add bx, tls13_286_desc_input1
    mov ax, tls13_286_record_plain_off
    mov dx, tablegen_scratch_bytes
    call module_validate_high_at
    jc module_error_bounds
    mov ax, [bx + tls13_286_span_seg]
    mov [table_scratch_seg], ax

    mov bx, [table_desc]
    add bx, tls13_286_desc_output0
    mov ax, [table_expected_output_off]
    mov dx, tls13_286_w7_table_bytes
    call module_validate_high_at
    jc module_error_bounds
    mov ax, [bx + tls13_286_span_off]
    mov [table_output_off], ax
    mov ax, [bx + tls13_286_span_seg]
    mov [table_output_seg], ax

    mov si, table_input_x
    mov di, table_input_y
    call table_validate_point
    jc module_error_crypto
    call table_build_teeth
    call table_build_projective
    call table_batch_prefix
    jc module_error_crypto
    call table_batch_normalize
    jc module_error_crypto
    call module_wipe
    xor dx, dx
    jmp module_finish_result

module_error_abi:
    mov dx, tls13_286_error_abi
    jmp short module_error
module_error_bounds:
    mov dx, tls13_286_error_bounds
    jmp short module_error
module_error_crypto:
    mov dx, tls13_286_error_crypto
module_error:
    call module_wipe
    jmp module_finish_result

; An invalid incoming SP cannot safely use the guarded-stack finalizer.  No
; module state or caller-controlled span has been touched at this point.
module_error_stack:
    mov ax, tls13_286_error_bounds
    stc
    ret

; BX=span.  Accept only an all-zero inactive encoding.
module_validate_zero_span:
    cmp word [bx + tls13_286_span_off], 0
    jne .bad
    cmp word [bx + tls13_286_span_seg], 0
    jne .bad
    cmp word [bx + tls13_286_span_len], 0
    jne .bad
    cmp word [bx + tls13_286_span_len + 2], 0
    jne .bad
    clc
    ret
.bad:
    stc
    ret

; BX=span, AX=offset from the validated high reservation, DX=exact length.
; Every product slot is paragraph aligned, making segment:0000 its unique
; canonical representation.
module_validate_high_at:
    cmp word [bx + tls13_286_span_len], dx
    jne .bad
    cmp word [bx + tls13_286_span_len + 2], 0
    jne .bad
    cmp word [bx + tls13_286_span_off], 0
    jne .bad
    mov cl, 4
    shr ax, cl
    add ax, [module_crypto_seg]
    cmp word [bx + tls13_286_span_seg], ax
    jne .bad
    clc
    ret
.bad:
    stc
    ret

; BX=input0 span.  Return the paired output offset and remember the exact low
; physical point for the descriptor non-alias check.
module_select_point:
    cmp word [bx + tls13_286_span_len], 64
    jne .bad
    cmp word [bx + tls13_286_span_len + 2], 0
    jne .bad
    cmp word [bx + tls13_286_span_off], table_generator_phys & 15
    jne .try_leaf
    cmp word [bx + tls13_286_span_seg], table_generator_phys >> 4
    jne .try_leaf
    mov word [table_input_phys], table_generator_phys
    mov word [table_expected_output_off], tls13_286_g_table_off
    clc
    ret
.try_leaf:
    cmp word [bx + tls13_286_span_off], table_leaf_phys & 15
    jne .bad
    cmp word [bx + tls13_286_span_seg], table_leaf_phys >> 4
    jne .bad
    mov word [table_input_phys], table_leaf_phys
    mov word [table_expected_output_off], tls13_286_leaf_table_off
    clc
    ret
.bad:
    stc
    ret

; Reject a descriptor which overlaps the selected low public point.  All high
; exact slots are disjoint by construction.
module_validate_desc_point_disjoint:
    mov ax, [table_desc]
    mov dx, ax
    add dx, tls13_286_desc_bytes
    cmp dx, [table_input_phys]
    jbe .good
    mov dx, [table_input_phys]
    add dx, 64
    cmp ax, dx
    jae .good
    stc
    ret
.good:
    clc
    ret

; BX=validated span, DI=near destination, DX=length.
module_copy_span_to_near:
    push ds
    push es
    mov ax, [bx + tls13_286_span_seg]
    mov si, [bx + tls13_286_span_off]
    mov ds, ax
    xor ax, ax
    mov es, ax
    mov cx, dx
    rep movsb
    pop es
    pop ds
    ret

; Retire every mutable near byte before returning.  This module is one-shot;
; constants which happen to lie inside the contiguous tail are harmlessly
; retired with the arithmetic state and point copies.
module_wipe:
    push ax
    push cx
    push di
    push es
    xor ax, ax
    mov es, ax
    mov di, module_mutable_start
    mov cx, image_end - module_mutable_start
    rep stosb
    pop es
    pop di
    pop cx
    pop ax
    ret

; DX is the final public status.  All nested calls have returned, so SP points
; at the saved caller BP.  Scrub the complete used part of the product stack,
; then use a same-CS IRET frame to restore IF and publish CF atomically.  The
; three public frame words are the only permitted guard residue.
module_finish_result:
    pushf
    pop bx
    cli
    and bx, 0xfffe
    or dx, dx
    jz .status_ready
    or bx, 1
.status_ready:
    mov cx, sp
    mov di, tls13_286_module_limit
    sub cx, di
    shr cx, 1
    xor ax, ax
    mov es, ax
    rep stosw
    mov ax, dx
    pop bp
    pop si
    push bx
    push cs
    push si
    xor bx, bx
    xor cx, cx
    xor dx, dx
    xor si, si
    xor di, di
    iret

; Validate canonical x/y and y^2 = x^3 - 3x + b.
table_validate_point:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    mov [table_point_x_ptr], si
    mov [table_point_y_ptr], di
    mov di, p256_prime
    call p256_cmp_words
    jnc .failed
    mov si, [table_point_y_ptr]
    mov di, p256_prime
    call p256_cmp_words
    jnc .failed
    mov si, [table_point_y_ptr]
    mov di, si
    mov bx, p256_s0
    call p256_mul_mod
    mov si, [table_point_x_ptr]
    mov di, si
    mov bx, p256_s1
    call p256_mul_mod
    mov si, p256_s1
    mov di, [table_point_x_ptr]
    mov bx, p256_s2
    call p256_mul_mod
    mov si, [table_point_x_ptr]
    mov bx, p256_s3
    call p256_double_mod
    mov si, p256_s3
    mov di, [table_point_x_ptr]
    mov bx, p256_s3
    call p256_add_mod
    mov si, p256_s2
    mov di, p256_s3
    mov bx, p256_s4
    call p256_sub_mod
    mov si, p256_s4
    mov di, table_curve_b
    mov bx, p256_s4
    call p256_add_mod
    mov si, p256_s0
    mov di, p256_s4
    call table_words_equal
    jc .failed
    clc
    jmp short .done
.failed:
    stc
.done:
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; teeth[j] = 2^(37*j) P, j=0..6, affine and near-resident.
table_build_teeth:
    push ax
    push bx
    push cx
    push si
    push di
    push es
    push ds
    pop es
    mov si, table_input_x
    mov di, table_teeth
    mov cx, 32
    rep movsw
    mov word [table_index], 1
.next:
    mov ax, [table_index]
    dec ax
    mov cl, 6
    shl ax, cl
    add ax, table_teeth
    mov [p256_affine_x_ptr], ax
    add ax, 32
    mov [p256_affine_y_ptr], ax
    call p256_point_set_from_affine
    mov cx, 37
.double:
    call p256_point_double_jacobian
    loop .double
    mov ax, [table_index]
    mov cl, 6
    shl ax, cl
    add ax, table_teeth
    mov di, ax
    add ax, 32
    mov bx, ax
    call p256_w_to_affine
    inc word [table_index]
    cmp word [table_index], 7
    jb .next
    pop es
    pop di
    pop si
    pop cx
    pop bx
    pop ax
    ret

; Build natural-index subset sums in projective far scratch:
; T[i] = T[i-lowbit(i)] + teeth[bit(lowbit(i))], i=1..127.
table_build_projective:
    mov word [table_index], 1
.next:
    mov ax, [table_index]
    mov dx, ax
    dec dx
    and dx, ax
    mov [table_rest], dx
    xor cx, cx
.bit:
    test ax, 1
    jnz .have_bit
    shr ax, 1
    inc cx
    jmp short .bit
.have_bit:
    mov ax, cx
    mov cl, 6
    shl ax, cl
    add ax, table_teeth
    mov [p256_affine_x_ptr], ax
    add ax, 32
    mov [p256_affine_y_ptr], ax
    cmp word [table_rest], 0
    jne .add
    call p256_point_set_from_affine
    jmp short .store
.add:
    mov ax, [table_rest]
    dec ax
    call table_load_projective
    call p256_point_add_mixed
.store:
    mov ax, [table_index]
    dec ax
    call table_store_projective
    inc word [table_index]
    cmp word [table_index], table_points + 1
    jb .next
    ret

; prefix[i] = product(Z[0..i]).
table_batch_prefix:
    xor ax, ax
    call table_load_projective
    mov si, p256_jac_z
    mov di, table_batch_prev
    call p256_copy_words
    xor ax, ax
    mov si, table_batch_prev
    call table_store_prefix
    mov word [table_index], 1
.next:
    mov ax, [table_index]
    call table_load_projective
    mov si, table_batch_prev
    mov di, p256_jac_z
    mov bx, table_batch_next
    call p256_mul_mod
    mov si, table_batch_next
    mov di, table_batch_prev
    call p256_copy_words
    mov ax, [table_index]
    mov si, table_batch_prev
    call table_store_prefix
    inc word [table_index]
    cmp word [table_index], table_points
    jb .next
    mov si, table_batch_prev
    mov di, table_batch_inverse
    call p256_inv_mod
    ret

; Walk backwards, derive each Z^-1 from the batch inverse/prefix, emit affine
; x/y, and update the running inverse by the current original Z.
table_batch_normalize:
    mov word [table_index], table_points - 1
.next:
    mov ax, [table_index]
    call table_load_projective
    cmp word [table_index], 0
    je .first
    mov ax, [table_index]
    dec ax
    mov di, table_batch_prev
    call table_load_prefix
    mov si, table_batch_inverse
    mov di, table_batch_prev
    mov bx, table_batch_zinv
    call p256_mul_mod
    jmp short .have_zinv
.first:
    mov si, table_batch_inverse
    mov di, table_batch_zinv
    call p256_copy_words
.have_zinv:
    mov si, table_batch_inverse
    mov di, p256_jac_z
    mov bx, table_batch_next
    call p256_mul_mod
    mov si, table_batch_next
    mov di, table_batch_inverse
    call p256_copy_words

    mov si, table_batch_zinv
    mov di, table_batch_zinv
    mov bx, table_batch_z2
    call p256_mul_mod
    mov si, table_batch_z2
    mov di, table_batch_zinv
    mov bx, table_batch_z3
    call p256_mul_mod
    mov si, p256_jac_x
    mov di, table_batch_z2
    mov bx, table_output_x
    call p256_mul_mod
    mov si, p256_jac_y
    mov di, table_batch_z3
    mov bx, table_output_y
    call p256_mul_mod
    mov ax, [table_index]
    mov si, table_output_x
    call table_store_output
    cmp word [table_index], 0
    je .complete
    dec word [table_index]
    jmp .next
.complete:
    mov si, table_batch_inverse
    call p256_is_one
    jnc .failed
    clc
    ret
.failed:
    stc
    ret

; AX=index, far scratch[index].XYZ <-> contiguous p256_jac_x/y/z.
table_load_projective:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push ds
    push es
    mov cx, table_point_bytes
    mul cx
    mov si, ax
    mov ax, [table_scratch_seg]
    mov ds, ax
    xor ax, ax
    mov es, ax
    mov di, p256_jac_x
    mov cx, table_point_bytes / 2
    rep movsw
    pop es
    pop ds
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

table_store_projective:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push es
    mov cx, table_point_bytes
    mul cx
    mov di, ax
    mov ax, [table_scratch_seg]
    mov es, ax
    mov si, p256_jac_x
    mov cx, table_point_bytes / 2
    rep movsw
    pop es
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; AX=index, SI/DI=near field for store/load.
table_store_prefix:
    push ax
    push bx
    push cx
    push dx
    push di
    push es
    mov cx, table_prefix_bytes
    mul cx
    add ax, table_prefix_off
    mov di, ax
    mov ax, [table_scratch_seg]
    mov es, ax
    mov cx, table_prefix_bytes / 2
    rep movsw
    pop es
    pop di
    pop dx
    pop cx
    pop bx
    pop ax
    ret

table_load_prefix:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push ds
    push es
    mov cx, table_prefix_bytes
    mul cx
    add ax, table_prefix_off
    mov si, ax
    mov ax, [table_scratch_seg]
    mov ds, ax
    xor ax, ax
    mov es, ax
    mov cx, table_prefix_bytes / 2
    rep movsw
    pop es
    pop ds
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; AX=index, SI=64-byte near affine point.
table_store_output:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push es
    mov cl, 6
    shl ax, cl
    add ax, [table_output_off]
    mov di, ax
    mov ax, [table_output_seg]
    mov es, ax
    mov cx, 32
    rep movsw
    pop es
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; CF=0 equal, CF=1 different.
table_words_equal:
    push ax
    push cx
    push si
    push di
    mov cx, p256_word_count
.word:
    mov ax, [si]
    cmp ax, [di]
    jne .different
    add si, 2
    add di, 2
    loop .word
    clc
    jmp short .done
.different:
    stc
.done:
    pop di
    pop si
    pop cx
    pop ax
    ret

; The checked-in 8086 P-256 point/field implementation is the arithmetic
; source of truth; its mutable window is emitted inside this module.
tls_premaster_secret equ p256_s4
%include "core/p256.inc"

align 2
p256_prime: dw 65535,65535,65535,65535,65535,65535,0,0,0,0,0,0,1,0,65535,65535
p256_three: dw 3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
module_mutable_start:
p256_jac_x: times 16 dw 0
p256_jac_y: times 16 dw 0
p256_jac_z: times 16 dw 0
p256_s0: times 16 dw 0
p256_s1: times 16 dw 0
p256_s2: times 16 dw 0
p256_s3: times 16 dw 0
p256_s4: times 16 dw 0
p256_s5: times 16 dw 0
p256_s6: times 16 dw 0
p256_s7: times 16 dw 0
p256_s8: times 16 dw 0
p256_product: times 36 dw 0
p256_carry: db 0
p256_left_ptr: dw 0
p256_right_ptr: dw 0
p256_result_ptr: dw 0
p256_inv_output_ptr: dw 0
p256_affine_x_ptr: dw 0
p256_affine_y_ptr: dw 0
p256_scalar_ptr: dw 0

p256_client_private equ p256_s0
tls_server_ec_x_words equ p256_s1
tls_server_ec_y_words equ p256_s2
tls_shared_x_words equ p256_s3

table_curve_b:
    dw 24651,10194,15422,15310,45302,52307,1712,25885
    dw 34492,30360,48469,46059,37863,43578,13784,23238

table_desc: dw 0
module_crypto_seg: dw 0
table_scratch_seg: dw 0
table_output_off: dw 0
table_output_seg: dw 0
table_input_phys: dw 0
table_expected_output_off: dw 0
table_point_x_ptr: dw 0
table_point_y_ptr: dw 0
table_index: dw 0
table_rest: dw 0

align 2
table_input_x: times 16 dw 0
table_input_y: times 16 dw 0
table_teeth: times 7 * 32 dw 0
table_batch_prev: times 16 dw 0
table_batch_next: times 16 dw 0
table_batch_inverse: times 16 dw 0
table_batch_zinv: times 16 dw 0
table_batch_z2: times 16 dw 0
table_batch_z3: times 16 dw 0
table_output_x: times 16 dw 0
table_output_y: times 16 dw 0

image_end:

%if image_end - module_header > tls13_286_module_max_bytes
%error "P-256 tablegen module exceeds the TLS 1.3 286 overlay"
%endif
