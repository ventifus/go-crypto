// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build s390x,!gccgo,!appengine

#include "textflag.h"

// This is an implementation of the ChaCha20 encryption algorithm as
// specified in RFC 7539. It uses vector instructions to compute
// 4 keystream blocks in parallel (256 bytes) which are then XORed
// with the bytes in the input slice.

GLOBL ·constants<>(SB), RODATA, $80
// BSWAP: swap bytes in each 4-byte element
DATA ·constants<>+0(SB)/4, $0x03020100
DATA ·constants<>+4(SB)/4, $0x07060504
DATA ·constants<>+8(SB)/4, $0x0b0a0908
DATA ·constants<>+12(SB)/4, $0x0f0e0d0c
// ROL1: rotate left by 1 element
DATA ·constants<>+16(SB)/4, $0x04050607
DATA ·constants<>+20(SB)/4, $0x08090a0b
DATA ·constants<>+24(SB)/4, $0x0c0d0e0f
DATA ·constants<>+28(SB)/4, $0x00010203
// ROL2: rotate left by 2 elements
DATA ·constants<>+32(SB)/4, $0x08090a0b
DATA ·constants<>+36(SB)/4, $0x0c0d0e0f
DATA ·constants<>+40(SB)/4, $0x00010203
DATA ·constants<>+44(SB)/4, $0x04050607
// ROL3: rotate left by 3 elements
DATA ·constants<>+48(SB)/4, $0x0c0d0e0f
DATA ·constants<>+52(SB)/4, $0x00010203
DATA ·constants<>+56(SB)/4, $0x04050607
DATA ·constants<>+60(SB)/4, $0x08090a0b
// J0: [j0, j1, j2, j3]
DATA ·constants<>+64(SB)/4, $0x61707865
DATA ·constants<>+68(SB)/4, $0x3320646e
DATA ·constants<>+72(SB)/4, $0x79622d32
DATA ·constants<>+76(SB)/4, $0x6b206574

#define BSWAP V0
#define ROL1  V1
#define ROL2  V2
#define ROL3  V3

#define J0    V4
#define J1    V5
#define J2    V6
#define CTR0  V7
#define CTR1  V8
#define CTR2  V9
#define CTR3  V10

#define M0    V11
#define M1    V12
#define M2    V13
#define M3    V14
#define INC   V15

#define X0    V16
#define X1    V17
#define X2    V18
#define X3    V19
#define X4    V20
#define X5    V21
#define X6    V22
#define X7    V23
#define X8    V24
#define X9    V25
#define X10   V26
#define X11   V27
#define X12   V28
#define X13   V29
#define X14   V30
#define X15   V31

#define NUM_ROUNDS 20

#define ROUND(a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3) \
	VAF    a0, a1, a0  \
	VAF    b0, b1, b0  \
	VAF    c0, c1, c0  \
	VAF    d0, d1, d0  \
	VX     a3, a0, a3  \
	VX     b3, b0, b3  \
	VX     c3, c0, c3  \
	VX     d3, d0, d3  \
	VERLLF $16, a3, a3 \
	VERLLF $16, b3, b3 \
	VERLLF $16, c3, c3 \
	VERLLF $16, d3, d3 \
	VAF    a2, a3, a2  \
	VAF    b2, b3, b2  \
	VAF    c2, c3, c2  \
	VAF    d2, d3, d2  \
	VX     a1, a2, a1  \
	VX     b1, b2, b1  \
	VX     c1, c2, c1  \
	VX     d1, d2, d1  \
	VERLLF $12, a1, a1 \
	VERLLF $12, b1, b1 \
	VERLLF $12, c1, c1 \
	VERLLF $12, d1, d1 \
	VAF    a0, a1, a0  \
	VAF    b0, b1, b0  \
	VAF    c0, c1, c0  \
	VAF    d0, d1, d0  \
	VX     a3, a0, a3  \
	VX     b3, b0, b3  \
	VX     c3, c0, c3  \
	VX     d3, d0, d3  \
	VERLLF $8, a3, a3  \
	VERLLF $8, b3, b3  \
	VERLLF $8, c3, c3  \
	VERLLF $8, d3, d3  \
	VAF    a2, a3, a2  \
	VAF    b2, b3, b2  \
	VAF    c2, c3, c2  \
	VAF    d2, d3, d2  \
	VX     a1, a2, a1  \
	VX     b1, b2, b1  \
	VX     c1, c2, c1  \
	VX     d1, d2, d1  \
	VERLLF $7, a1, a1  \
	VERLLF $7, b1, b1  \
	VERLLF $7, c1, c1  \
	VERLLF $7, d1, d1

#define PERMUTE(mask, v0, v1, v2, v3) \
	VPERM v0, v0, mask, v0 \
	VPERM v1, v1, mask, v1 \
	VPERM v2, v2, mask, v2 \
	VPERM v3, v3, mask, v3

#define ADDV(x, v0, v1, v2, v3) \
	VAF x, v0, v0 \
	VAF x, v1, v1 \
	VAF x, v2, v2 \
	VAF x, v3, v3

#define XORV(off, dst, src, v0, v1, v2, v3) \
	VLM  off(src), M0, M3          \
	PERMUTE(BSWAP, v0, v1, v2, v3) \
	VX   v0, M0, M0                \
	VX   v1, M1, M1                \
	VX   v2, M2, M2                \
	VX   v3, M3, M3                \
	VSTM M0, M3, off(dst)

// func xorKeyStreamVX(out, in []byte, counter *[16]byte, key *[32]byte)
TEXT ·xorKeyStreamVX(SB), NOSPLIT, $256-64
	LMG    out+0(FP), R5, R6 // R5=&out[0] R6=len(out)
	LMG    in+24(FP), R7, R8 // R7=&in[0]  R8=len(in)
	CMPBLT R6, R8, fault     // assert len(out) >= len(in)
	CMPBEQ R8, $0, return    // nothing to do

	// load J0, ROL1, ROL2, ROL3 and BSWAP
	MOVD $·constants<>(SB), R1
	VLM  (R1), BSWAP, J0

	// setup J1 and J2
	MOVD  key+56(FP), R4
	VLM   (R4), J1, J2
	VPERM J1, J1, BSWAP, J1
	VPERM J2, J2, BSWAP, J2

	// initialize counter values
	MOVD  counter+48(FP), R3
	VL    (R3), CTR0
	VPERM CTR0, CTR0, BSWAP, CTR0
	VZERO INC
	VLEIF $0, $1, INC
	VAF   INC, CTR0, CTR1
	VAF   INC, CTR1, CTR2
	VAF   INC, CTR2, CTR3
	VLEIF $0, $4, INC

chacha:
	VLR J0, X0; VLR J0, X4; VLR J0, X8; VLR J0, X12
	VLR J1, X1; VLR J1, X5; VLR J1, X9; VLR J1, X13
	VLR J2, X2; VLR J2, X6; VLR J2, X10; VLR J2, X14
	VLR CTR0, X3; VLR CTR1, X7; VLR CTR2, X11; VLR CTR3, X15

	MOVD $(NUM_ROUNDS/2), R1

loop:
	ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15)
	PERMUTE(ROL1, X1, X5,  X9, X13)
	PERMUTE(ROL3, X3, X7, X11, X15)
	PERMUTE(ROL2, X2, X6, X10, X14)

	ROUND(X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15)
	PERMUTE(ROL3, X1, X5,  X9, X13)
	PERMUTE(ROL1, X3, X7, X11, X15)
	PERMUTE(ROL2, X2, X6, X10, X14)

	ADD $-1, R1
	BNE loop

	ADDV(J0, X0, X4,  X8, X12)
	ADDV(J1, X1, X5,  X9, X13)
	ADDV(J2, X2, X6, X10, X14)
	VAF X3, CTR0, X3
	VAF X7, CTR1, X7
	VAF X11, CTR2, X11
	VAF X15, CTR3, X15

	CMP R8, $256
	BLT tail

	// decrement length
	MOVD $-256(R8), R8

	// xor keystream with plaintext
	XORV(0*64, R5, R7,  X0,  X1,  X2,  X3)
	XORV(1*64, R5, R7,  X4,  X5,  X6,  X7)
	XORV(2*64, R5, R7,  X8,  X9, X10, X11)
	XORV(3*64, R5, R7, X12, X13, X14, X15)

	// increment counters
	VAF INC, CTR0, CTR0
	VAF INC, CTR1, CTR1
	VAF INC, CTR2, CTR2
	VAF INC, CTR3, CTR3

	// increment pointers
	MOVD $256(R5), R5
	MOVD $256(R7), R7

	CMPBNE R8, $0, chacha

tail:
	CMPBEQ R8, $0, return

	// xor the keystream with the last blocks of plaintext
#define XORV1(off, k, tmp) \
	VPERM k, k, BSWAP, k   \
	VLL   R8, off(R7), tmp \
	VX    k, tmp, tmp      \
	VSTL  R8, tmp, off(R5) \
	ADD   $-16, R8         \
	BLT   return

	ADD $-1, R8 // the index to read/write up to
	XORV1( 0*16,  X0, M0)
	XORV1( 1*16,  X1, M1)
	XORV1( 2*16,  X2, M2)
	XORV1( 3*16,  X3, M3)
	XORV1( 4*16,  X4, M0)
	XORV1( 5*16,  X5, M1)
	XORV1( 6*16,  X6, M2)
	XORV1( 7*16,  X7, M3)
	XORV1( 8*16,  X8, M0)
	XORV1( 9*16,  X9, M1)
	XORV1(10*16, X10, M2)
	XORV1(11*16, X11, M3)
	XORV1(12*16, X12, M0)
	XORV1(13*16, X13, M1)
	XORV1(14*16, X14, M2)
	XORV1(15*16, X15, M3)

#undef XORV1

return:
	RET

fault:
	MOVD $0, (R0)
	RET

// func hasVectorFacility() bool
TEXT ·hasVectorFacility(SB), NOSPLIT, $24-1
	MOVD  $x-24(SP), R1
	XC    $24, 0(R1), 0(R1) // clear the storage
	MOVD  $2, R0            // R0 is the number of double words stored -1
	WORD  $0xB2B01000       // STFLE 0(R1)
	XOR   R0, R0            // reset the value of R0
	MOVBZ z-8(SP), R1
	AND   $0x40, R1
	BEQ   novector

vectorinstalled:
	// check if the vector instruction has been enabled
	VLEIB  $0, $0xF, V16
	VLGVB  $0, V16, R1
	CMPBNE R1, $0xF, novector
	MOVB   $1, ret+0(FP)      // have vx
	RET

novector:
	MOVB $0, ret+0(FP) // no vx
	RET
