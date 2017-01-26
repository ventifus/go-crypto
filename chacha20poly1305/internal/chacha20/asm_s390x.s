// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build s390x,!gccgo,!appengine

#include "textflag.h"

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
#define J3    V7
#define X0    V8
#define X1    V9
#define X2    V10
#define X3    V11
#define M0    V12
#define M1    V13
#define M2    V14
#define M3    V15
#define INC   V16

#define NUM_ROUNDS 20

#define ROUND(a, b, c, d) \
	VAF    a, b, a   \
	VX     d, a, d   \
	VERLLF $16, d, d \
	VAF    c, d, c   \
	VX     b, c, b   \
	VERLLF $12, b, b \
	VAF    a, b, a   \
	VX     d, a, d   \
	VERLLF $8, d, d  \
	VAF    c, d, c   \
	VX     b, c, b   \
	VERLLF $7, b, b

// func xorKeyStreamVX(out, in []byte, counter *[16]byte, key *[32]byte)
TEXT ·xorKeyStreamVX(SB), NOSPLIT, $0-64
	MOVD $·constants<>(SB), R1
	VLM  (R1), BSWAP, J0       // also loads ROL1, ROL2 and ROL3

	MOVD counter+48(FP), R3
	VL   (R3), J3

	MOVD key+56(FP), R4
	VLM  (R4), J1, J2

	VPERM J1, J1, BSWAP, J1
	VPERM J2, J2, BSWAP, J2
	VPERM J3, J3, BSWAP, J3

	VZERO INC
	VLEIF $0, $1, INC

	LMG    out+0(FP), R5, R6
	LMG    in+24(FP), R7, R8
	CMPBLT R6, R8, fault
	CMPBEQ R8, $0, return

chacha:
	VLR J0, X0
	VLR J1, X1
	VLR J2, X2
	VLR J3, X3

	MOVD $(NUM_ROUNDS/2), R1

loop:
	ROUND(X0, X1, X2, X3)
	VPERM X1, X1, ROL1, X1
	VPERM X2, X2, ROL2, X2
	VPERM X3, X3, ROL3, X3
	ROUND(X0, X1, X2, X3)
	VPERM X1, X1, ROL3, X1
	VPERM X2, X2, ROL2, X2
	VPERM X3, X3, ROL1, X3
	ADD   $-1, R1
	BNE   loop

	VAF X0, J0, X0
	VAF X1, J1, X1
	VAF X2, J2, X2
	VAF X3, J3, X3

	CMPBLT R8, $64, tail
	MOVD   $-64(R8), R8

	VLM (R7), M0, M3

	VPERM M0, M0, BSWAP, M0
	VPERM M1, M1, BSWAP, M1
	VPERM M2, M2, BSWAP, M2
	VPERM M3, M3, BSWAP, M3
	VX    X0, M0, M0
	VX    X1, M1, M1
	VX    X2, M2, M2
	VX    X3, M3, M3
	VPERM M0, M0, BSWAP, M0
	VPERM M1, M1, BSWAP, M1
	VPERM M2, M2, BSWAP, M2
	VPERM M3, M3, BSWAP, M3

	VAF INC, J3, J3

	VSTM M0, M3, (R5)
	MOVD $64(R5), R5
	MOVD $64(R7), R7

	CMPBNE R8, $0, chacha

tail:
	CMPBEQ R8, $0, return

	VPERM X0, X0, BSWAP, X0
	VPERM X1, X1, BSWAP, X1
	VPERM X2, X2, BSWAP, X2
	VPERM X3, X3, BSWAP, X3

	ADD  $-1, R8
	VLL  R8, 0(R7), M0
	VX   X0, M0, M0
	VSTL R8, M0, 0(R5)
	ADD  $-16, R8
	BLT  return
	VLL  R8, 16(R7), M1
	VX   X1, M1, M1
	VSTL R8, M1, 16(R5)
	ADD  $-16, R8
	BLT  return
	VLL  R8, 32(R7), M2
	VX   X2, M2, M2
	VSTL R8, M2, 32(R5)
	ADD  $-16, R8
	BLT  return
	VLL  R8, 48(R7), M3
	VX   X3, M3, M3
	VSTL R8, M3, 48(R5)

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
