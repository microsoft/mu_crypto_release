default rel
%define XMMWORD
%define YMMWORD
%define ZMMWORD
section .data data align=8

ALIGN   16
SHUFF_MASK:
DB      3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12

section .text code align=64









global  ossl_hwsm3_block_data_order

ALIGN   32
ossl_hwsm3_block_data_order:
        mov     QWORD[8+rsp],rdi        ;WIN64 prologue
        mov     QWORD[16+rsp],rsi
        mov     rax,rsp
$L$SEH_begin_ossl_hwsm3_block_data_order:
        mov     rdi,rcx
        mov     rsi,rdx
        mov     rdx,r8



DB      243,15,30,250

        push    rbp


$L$ossl_hwsm3_block_data_order_seh_setfp:

        sub     rsp,112

        vmovdqu XMMWORD[rsp],xmm6
        vmovdqu XMMWORD[16+rsp],xmm7
        vmovdqu XMMWORD[32+rsp],xmm8
        vmovdqu XMMWORD[48+rsp],xmm9
        vmovdqu XMMWORD[64+rsp],xmm10
        vmovdqu XMMWORD[80+rsp],xmm11
        vmovdqu XMMWORD[96+rsp],xmm12

$L$ossl_hwsm3_block_data_order_seh_prolog_end:
        or      rdx,rdx
        je      NEAR .done_hash




        vmovdqu xmm6,XMMWORD[rdi]
        vmovdqu xmm7,XMMWORD[16+rdi]

        vpshufd xmm0,xmm6,0x1B
        vpshufd xmm1,xmm7,0x1B
        vpunpckhqdq     xmm6,xmm1,xmm0
        vpunpcklqdq     xmm7,xmm1,xmm0
        vpsrld  xmm2,xmm7,9
        vpslld  xmm3,xmm7,23
        vpxor   xmm1,xmm2,xmm3
        vpsrld  xmm4,xmm7,19
        vpslld  xmm5,xmm7,13
        vpxor   xmm0,xmm4,xmm5

        vpblendd        xmm7,xmm1,xmm0,0x3

        vmovdqa xmm12,XMMWORD[SHUFF_MASK]

ALIGN   32
.block_loop:
        vmovdqa xmm10,xmm6
        vmovdqa xmm11,xmm7


        vmovdqu xmm2,XMMWORD[rsi]
        vmovdqu xmm3,XMMWORD[16+rsi]
        vmovdqu xmm4,XMMWORD[32+rsi]
        vmovdqu xmm5,XMMWORD[48+rsi]
        vpshufb xmm2,xmm2,xmm12
        vpshufb xmm3,xmm3,xmm12
        vpshufb xmm4,xmm4,xmm12
        vpshufb xmm5,xmm5,xmm12

        vpalignr        xmm8,xmm4,xmm3,12
        vpsrldq xmm9,xmm5,4
        vsm3msg1        xmm8,xmm9,xmm2
        vpalignr        xmm9,xmm3,xmm2,12
        vpalignr        xmm1,xmm5,xmm4,8
        vsm3msg2        xmm8,xmm9,xmm1
        vpunpcklqdq     xmm1,xmm2,xmm3
        vsm3rnds2       xmm7,xmm6,xmm1,0
        vpunpckhqdq     xmm1,xmm2,xmm3
        vsm3rnds2       xmm6,xmm7,xmm1,2
        vmovdqa xmm2,xmm8
        vpalignr        xmm8,xmm5,xmm4,12
        vpsrldq xmm9,xmm2,4
        vsm3msg1        xmm8,xmm9,xmm3
        vpalignr        xmm9,xmm4,xmm3,12
        vpalignr        xmm1,xmm2,xmm5,8
        vsm3msg2        xmm8,xmm9,xmm1
        vpunpcklqdq     xmm1,xmm3,xmm4
        vsm3rnds2       xmm7,xmm6,xmm1,4
        vpunpckhqdq     xmm1,xmm3,xmm4
        vsm3rnds2       xmm6,xmm7,xmm1,6
        vmovdqa xmm3,xmm8
        vpalignr        xmm8,xmm2,xmm5,12
        vpsrldq xmm9,xmm3,4
        vsm3msg1        xmm8,xmm9,xmm4
        vpalignr        xmm9,xmm5,xmm4,12
        vpalignr        xmm1,xmm3,xmm2,8
        vsm3msg2        xmm8,xmm9,xmm1
        vpunpcklqdq     xmm1,xmm4,xmm5
        vsm3rnds2       xmm7,xmm6,xmm1,8
        vpunpckhqdq     xmm1,xmm4,xmm5
        vsm3rnds2       xmm6,xmm7,xmm1,10
        vmovdqa xmm4,xmm8
        vpalignr        xmm8,xmm3,xmm2,12
        vpsrldq xmm9,xmm4,4
        vsm3msg1        xmm8,xmm9,xmm5
        vpalignr        xmm9,xmm2,xmm5,12
        vpalignr        xmm1,xmm4,xmm3,8
        vsm3msg2        xmm8,xmm9,xmm1
        vpunpcklqdq     xmm1,xmm5,xmm2
        vsm3rnds2       xmm7,xmm6,xmm1,12
        vpunpckhqdq     xmm1,xmm5,xmm2
        vsm3rnds2       xmm6,xmm7,xmm1,14
        vmovdqa xmm5,xmm8
        vpalignr        xmm8,xmm4,xmm3,12
        vpsrldq xmm9,xmm5,4
        vsm3msg1        xmm8,xmm9,xmm2
        vpalignr        xmm9,xmm3,xmm2,12
        vpalignr        xmm1,xmm5,xmm4,8
        vsm3msg2        xmm8,xmm9,xmm1
        vpunpcklqdq     xmm1,xmm2,xmm3
        vsm3rnds2       xmm7,xmm6,xmm1,16
        vpunpckhqdq     xmm1,xmm2,xmm3
        vsm3rnds2       xmm6,xmm7,xmm1,18
        vmovdqa xmm2,xmm8
        vpalignr        xmm8,xmm5,xmm4,12
        vpsrldq xmm9,xmm2,4
        vsm3msg1        xmm8,xmm9,xmm3
        vpalignr        xmm9,xmm4,xmm3,12
        vpalignr        xmm1,xmm2,xmm5,8
        vsm3msg2        xmm8,xmm9,xmm1
        vpunpcklqdq     xmm1,xmm3,xmm4
        vsm3rnds2       xmm7,xmm6,xmm1,20
        vpunpckhqdq     xmm1,xmm3,xmm4
        vsm3rnds2       xmm6,xmm7,xmm1,22
        vmovdqa xmm3,xmm8
        vpalignr        xmm8,xmm2,xmm5,12
        vpsrldq xmm9,xmm3,4
        vsm3msg1        xmm8,xmm9,xmm4
        vpalignr        xmm9,xmm5,xmm4,12
        vpalignr        xmm1,xmm3,xmm2,8
        vsm3msg2        xmm8,xmm9,xmm1
        vpunpcklqdq     xmm1,xmm4,xmm5
        vsm3rnds2       xmm7,xmm6,xmm1,24
        vpunpckhqdq     xmm1,xmm4,xmm5
        vsm3rnds2       xmm6,xmm7,xmm1,26
        vmovdqa xmm4,xmm8
        vpalignr        xmm8,xmm3,xmm2,12
        vpsrldq xmm9,xmm4,4
        vsm3msg1        xmm8,xmm9,xmm5
        vpalignr        xmm9,xmm2,xmm5,12
        vpalignr        xmm1,xmm4,xmm3,8
        vsm3msg2        xmm8,xmm9,xmm1
        vpunpcklqdq     xmm1,xmm5,xmm2
        vsm3rnds2       xmm7,xmm6,xmm1,28
        vpunpckhqdq     xmm1,xmm5,xmm2
        vsm3rnds2       xmm6,xmm7,xmm1,30
        vmovdqa xmm5,xmm8
        vpalignr        xmm8,xmm4,xmm3,12
        vpsrldq xmm9,xmm5,4
        vsm3msg1        xmm8,xmm9,xmm2
        vpalignr        xmm9,xmm3,xmm2,12
        vpalignr        xmm1,xmm5,xmm4,8
        vsm3msg2        xmm8,xmm9,xmm1
        vpunpcklqdq     xmm1,xmm2,xmm3
        vsm3rnds2       xmm7,xmm6,xmm1,32
        vpunpckhqdq     xmm1,xmm2,xmm3
        vsm3rnds2       xmm6,xmm7,xmm1,34
        vmovdqa xmm2,xmm8
        vpalignr        xmm8,xmm5,xmm4,12
        vpsrldq xmm9,xmm2,4
        vsm3msg1        xmm8,xmm9,xmm3
        vpalignr        xmm9,xmm4,xmm3,12
        vpalignr        xmm1,xmm2,xmm5,8
        vsm3msg2        xmm8,xmm9,xmm1
        vpunpcklqdq     xmm1,xmm3,xmm4
        vsm3rnds2       xmm7,xmm6,xmm1,36
        vpunpckhqdq     xmm1,xmm3,xmm4
        vsm3rnds2       xmm6,xmm7,xmm1,38
        vmovdqa xmm3,xmm8
        vpalignr        xmm8,xmm2,xmm5,12
        vpsrldq xmm9,xmm3,4
        vsm3msg1        xmm8,xmm9,xmm4
        vpalignr        xmm9,xmm5,xmm4,12
        vpalignr        xmm1,xmm3,xmm2,8
        vsm3msg2        xmm8,xmm9,xmm1
        vpunpcklqdq     xmm1,xmm4,xmm5
        vsm3rnds2       xmm7,xmm6,xmm1,40
        vpunpckhqdq     xmm1,xmm4,xmm5
        vsm3rnds2       xmm6,xmm7,xmm1,42
        vmovdqa xmm4,xmm8
        vpalignr        xmm8,xmm3,xmm2,12
        vpsrldq xmm9,xmm4,4
        vsm3msg1        xmm8,xmm9,xmm5
        vpalignr        xmm9,xmm2,xmm5,12
        vpalignr        xmm1,xmm4,xmm3,8
        vsm3msg2        xmm8,xmm9,xmm1
        vpunpcklqdq     xmm1,xmm5,xmm2
        vsm3rnds2       xmm7,xmm6,xmm1,44
        vpunpckhqdq     xmm1,xmm5,xmm2
        vsm3rnds2       xmm6,xmm7,xmm1,46
        vmovdqa xmm5,xmm8
        vpalignr        xmm8,xmm4,xmm3,12
        vpsrldq xmm9,xmm5,4
        vsm3msg1        xmm8,xmm9,xmm2
        vpalignr        xmm9,xmm3,xmm2,12
        vpalignr        xmm1,xmm5,xmm4,8
        vsm3msg2        xmm8,xmm9,xmm1
        vpunpcklqdq     xmm1,xmm2,xmm3
        vsm3rnds2       xmm7,xmm6,xmm1,48
        vpunpckhqdq     xmm1,xmm2,xmm3
        vsm3rnds2       xmm6,xmm7,xmm1,50
        vmovdqa xmm2,xmm8
        vpunpcklqdq     xmm1,xmm3,xmm4
        vsm3rnds2       xmm7,xmm6,xmm1,52
        vpunpckhqdq     xmm1,xmm3,xmm4
        vsm3rnds2       xmm6,xmm7,xmm1,54
        vpunpcklqdq     xmm1,xmm4,xmm5
        vsm3rnds2       xmm7,xmm6,xmm1,56
        vpunpckhqdq     xmm1,xmm4,xmm5
        vsm3rnds2       xmm6,xmm7,xmm1,58
        vpunpcklqdq     xmm1,xmm5,xmm2
        vsm3rnds2       xmm7,xmm6,xmm1,60
        vpunpckhqdq     xmm1,xmm5,xmm2
        vsm3rnds2       xmm6,xmm7,xmm1,62

        vpxor   xmm6,xmm6,xmm10
        vpxor   xmm7,xmm7,xmm11
        add     rsi,64
        dec     rdx
        jnz     NEAR .block_loop


        vpslld  xmm2,xmm7,9
        vpsrld  xmm3,xmm7,23
        vpxor   xmm1,xmm2,xmm3
        vpslld  xmm4,xmm7,19
        vpsrld  xmm5,xmm7,13
        vpxor   xmm0,xmm4,xmm5
        vpblendd        xmm7,xmm1,xmm0,0x3
        vpshufd xmm0,xmm6,0x1B
        vpshufd xmm1,xmm7,0x1B

        vpunpcklqdq     xmm6,xmm0,xmm1
        vpunpckhqdq     xmm7,xmm0,xmm1

        vmovdqu XMMWORD[rdi],xmm6
        vmovdqu XMMWORD[16+rdi],xmm7
.done_hash:


        vmovdqu xmm6,XMMWORD[rsp]
        vmovdqu xmm7,XMMWORD[16+rsp]
        vmovdqu xmm8,XMMWORD[32+rsp]
        vmovdqu xmm9,XMMWORD[48+rsp]
        vmovdqu xmm10,XMMWORD[64+rsp]
        vmovdqu xmm11,XMMWORD[80+rsp]
        vmovdqu xmm12,XMMWORD[96+rsp]
        add     rsp,112

        pop     rbp

        mov     rdi,QWORD[8+rsp]        ;WIN64 epilogue
        mov     rsi,QWORD[16+rsp]
        DB      0F3h,0C3h               ;repret

