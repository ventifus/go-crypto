// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.10,amd64,!gccgo,!appengine

#include "textflag.h"

DATA ·AVX2_c40<>+0x00(SB)/8, $0x0201000706050403
DATA ·AVX2_c40<>+0x08(SB)/8, $0x0a09080f0e0d0c0b
DATA ·AVX2_c40<>+0x10(SB)/8, $0x0201000706050403
DATA ·AVX2_c40<>+0x18(SB)/8, $0x0a09080f0e0d0c0b
GLOBL ·AVX2_c40<>(SB), (NOPTR+RODATA), $32

DATA ·AVX2_c48<>+0x00(SB)/8, $0x0100070605040302
DATA ·AVX2_c48<>+0x08(SB)/8, $0x09080f0e0d0c0b0a
DATA ·AVX2_c48<>+0x10(SB)/8, $0x0100070605040302
DATA ·AVX2_c48<>+0x18(SB)/8, $0x09080f0e0d0c0b0a
GLOBL ·AVX2_c48<>(SB), (NOPTR+RODATA), $32

#define SHUFFLE(v1, v2, v3) \
	VPERMQ $0x39, v1, v1; \
	VPERMQ $0x4E, v2, v2; \
	VPERMQ $-109, v3, v3

#define HALF_ROUND(v0, v1, v2, v3, t0, c40, c48) \
	VPMULUDQ v0, v1, t0;   \
	VPADDQ   t0, v0, v0;   \
	VPADDQ   t0, v0, v0;   \
	VPADDQ   v1, v0, v0;   \
	VPXOR    v0, v3, v3;   \
	VPSHUFD  $-79, v3, v3; \
	VPMULUDQ v2, v3, t0;   \
	VPADDQ   t0, v2, v2;   \
	VPADDQ   t0, v2, v2;   \
	VPADDQ   v3, v2, v2;   \
	VPXOR    v2, v1, v1;   \
	VPSHUFB  c40, v1, v1;  \
	VPMULUDQ v0, v1, t0;   \
	VPADDQ   t0, v0, v0;   \
	VPADDQ   t0, v0, v0;   \
	VPADDQ   v1, v0, v0;   \
	VPXOR    v0, v3, v3;   \
	VPSHUFB  c48, v3, v3;  \
	VPMULUDQ v2, v3, t0;   \
	VPADDQ   t0, v2, v2;   \
	VPADDQ   t0, v2, v2;   \
	VPADDQ   v3, v2, v2;   \
	VPXOR    v2, v1, v1;   \
	VPSLLQ   $1, v1, t0;   \
	VPSRLQ   $63, v1, v1;  \
	VPXOR    t0, v1, v1

#define LOAD_MSG_0(block, off) \
	VMOVDQU 8*(off+0)(block), Y0; \
	VMOVDQU 8*(off+4)(block), Y1; \
	VMOVDQU 8*(off+8)(block), Y2; \
	VMOVDQU 8*(off+12)(block), Y3

#define STORE_MSG_0(block, off) \
	VMOVDQU Y0, 8*(off+0)(block); \
	VMOVDQU Y1, 8*(off+4)(block); \
	VMOVDQU Y2, 8*(off+8)(block); \
	VMOVDQU Y3, 8*(off+12)(block)

#define LOAD_MSG_1(block, off) \
	VINSERTI128 $0, 8*off+0*8(block), Y0, Y0;  \
	VINSERTI128 $1, 8*off+16*8(block), Y0, Y0; \
	VINSERTI128 $0, 8*off+32*8(block), Y1, Y1; \
	VINSERTI128 $1, 8*off+48*8(block), Y1, Y1; \
	VINSERTI128 $0, 8*off+64*8(block), Y2, Y2; \
	VINSERTI128 $1, 8*off+80*8(block), Y2, Y2; \
	VINSERTI128 $0, 8*off+96*8(block), Y3, Y3; \
	VINSERTI128 $1, 8*off+112*8(block), Y3, Y3

#define STORE_MSG_1(block, off) \
	VEXTRACTI128 $0, Y0, 8*off+0*8(block);  \
	VEXTRACTI128 $1, Y0, 8*off+16*8(block); \
	VEXTRACTI128 $0, Y1, 8*off+32*8(block); \
	VEXTRACTI128 $1, Y1, 8*off+48*8(block); \
	VEXTRACTI128 $0, Y2, 8*off+64*8(block); \
	VEXTRACTI128 $1, Y2, 8*off+80*8(block); \
	VEXTRACTI128 $0, Y3, 8*off+96*8(block); \
	VEXTRACTI128 $1, Y3, 8*off+112*8(block)

#define BLAMKA_ROUND_0(block, off, v0, v1, v2, v3, t0, c40, c48) \
	LOAD_MSG_0(block, off);                   \
	HALF_ROUND(v0, v1, v2, v3, t0, c40, c48); \
	SHUFFLE(Y1, Y2, Y3);                      \
	HALF_ROUND(v0, v1, v2, v3, t0, c40, c48); \
	SHUFFLE(Y3, Y2, Y1);                      \
	STORE_MSG_0(block, off)

#define BLAMKA_ROUND_1(block, off, v0, v1, v2, v3, t0, c40, c48) \
	LOAD_MSG_1(block, off);                   \
	HALF_ROUND(v0, v1, v2, v3, t0, c40, c48); \
	SHUFFLE(Y1, Y2, Y3);                      \
	HALF_ROUND(v0, v1, v2, v3, t0, c40, c48); \
	SHUFFLE(Y3, Y2, Y1);                      \
	STORE_MSG_1(block, off)

// func blamkaAVX2(b *block)
TEXT ·blamkaAVX2(SB), 4, $0-8
	MOVQ b+0(FP), AX

	VMOVDQU ·AVX2_c40<>(SB), Y5
	VMOVDQU ·AVX2_c48<>(SB), Y6

	BLAMKA_ROUND_0(AX, 0, Y0, Y1, Y2, Y3, Y4, Y5, Y6)
	BLAMKA_ROUND_0(AX, 16, Y0, Y1, Y2, Y3, Y4, Y5, Y6)
	BLAMKA_ROUND_0(AX, 32, Y0, Y1, Y2, Y3, Y4, Y5, Y6)
	BLAMKA_ROUND_0(AX, 48, Y0, Y1, Y2, Y3, Y4, Y5, Y6)
	BLAMKA_ROUND_0(AX, 64, Y0, Y1, Y2, Y3, Y4, Y5, Y6)
	BLAMKA_ROUND_0(AX, 80, Y0, Y1, Y2, Y3, Y4, Y5, Y6)
	BLAMKA_ROUND_0(AX, 96, Y0, Y1, Y2, Y3, Y4, Y5, Y6)
	BLAMKA_ROUND_0(AX, 112, Y0, Y1, Y2, Y3, Y4, Y5, Y6)

	BLAMKA_ROUND_1(AX, 0, Y0, Y1, Y2, Y3, Y4, Y5, Y6)
	BLAMKA_ROUND_1(AX, 2, Y0, Y1, Y2, Y3, Y4, Y5, Y6)
	BLAMKA_ROUND_1(AX, 4, Y0, Y1, Y2, Y3, Y4, Y5, Y6)
	BLAMKA_ROUND_1(AX, 6, Y0, Y1, Y2, Y3, Y4, Y5, Y6)
	BLAMKA_ROUND_1(AX, 8, Y0, Y1, Y2, Y3, Y4, Y5, Y6)
	BLAMKA_ROUND_1(AX, 10, Y0, Y1, Y2, Y3, Y4, Y5, Y6)
	BLAMKA_ROUND_1(AX, 12, Y0, Y1, Y2, Y3, Y4, Y5, Y6)
	BLAMKA_ROUND_1(AX, 14, Y0, Y1, Y2, Y3, Y4, Y5, Y6)
	RET

// func mixBlocksAVX2(out, a, b, c *block)
TEXT ·mixBlocksAVX2(SB), 4, $0-32
	MOVQ out+0(FP), DX
	MOVQ a+8(FP), AX
	MOVQ b+16(FP), BX
	MOVQ a+24(FP), CX
	MOVQ $128, BP

loop:
	VMOVDQU 0(AX), Y0
	VMOVDQU 0(BX), Y1
	VMOVDQU 0(CX), Y2
	VPXOR   Y1, Y0, Y0
	VPXOR   Y2, Y0, Y0
	VMOVDQU Y0, 0(DX)
	ADDQ    $32, AX
	ADDQ    $32, BX
	ADDQ    $32, CX
	ADDQ    $32, DX
	SUBQ    $4, BP
	JA      loop
	VZEROUPPER
	RET

// func xorBlocksAVX2(out, a, b, c *block)
TEXT ·xorBlocksAVX2(SB), 4, $0-32
	MOVQ out+0(FP), DX
	MOVQ a+8(FP), AX
	MOVQ b+16(FP), BX
	MOVQ a+24(FP), CX
	MOVQ $128, BP

loop:
	VMOVDQU 0(AX), Y0
	VMOVDQU 0(BX), Y1
	VMOVDQU 0(CX), Y2
	VMOVDQU 0(DX), Y3
	VPXOR   Y0, Y1, Y4
	VPXOR   Y2, Y3, Y5
	VPXOR   Y4, Y5, Y0
	VMOVDQU Y0, 0(DX)
	ADDQ    $32, AX
	ADDQ    $32, BX
	ADDQ    $32, CX
	ADDQ    $32, DX
	SUBQ    $4, BP
	JA      loop
	RET

// func supportsAVX2() bool
TEXT ·supportsAVX2(SB), 4, $0-1
	MOVQ runtime·support_avx2(SB), AX
	MOVB AX, ret+0(FP)
	RET
