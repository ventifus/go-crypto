// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build ppc64le,!gccgo,!appengine

#include "textflag.h"

// This was ported from the amd64 implementation.

#define POLY1305_ADD(msg, h0, h1, h2) \
	MOVD (msg), R20;  \
	MOVD 8(msg), R21; \
	MOVD $1, R22;     \
	ADDC R20, h0, h0; \
	ADDE R21, h1, h1; \
	ADDE R22, h2;     \
	ADD  $16, msg

#define POLY1305_MUL(h0, h1, h2, r0, r1, t0, t1, t2, t3) \
	MULLD  r0, h0, t0;   \
	MULLD  r0, h1, R20;  \
	MULHDU r0, h0, t1;   \
	MULHDU r0, h1, R21;  \
	ADDC   R20, t1, t1;  \
	MULLD  r0, h2, t2;   \
	ADDZE  R21;          \
	MULHDU r1, h0, R20;  \
	MULLD  r1, h0, h0;   \
	ADD    R21, t2, t2;  \
	ADDC   h0, t1, t1;   \
	MULLD  h2, r1, t3;   \
	ADDZE  R20, h0;      \
	MULHDU r1, h1, R21;  \
	MULLD  r1, h1, R20;  \
	ADDC   R20, t2, t2;  \
	ADDE   R21, t3, t3;  \
	ADDC   h0, t2, t2;   \
	MOVD   $-4, R20;     \
	MOVD   t0, h0;       \
	MOVD   t1, h1;       \
	ADDZE  t3;           \
	ANDCC  $3, t2, h2;   \
	AND    t2, R20, t0;  \
	ADDC   t0, h0, h0;   \
	ADDE   t3, h1, h1;   \
	SLD    $62, t3, R20; \
	SRD    $2, t2;       \
	ADDZE  h2;           \
	OR     R20, t2, t2;  \
	SRD    $2, t3;       \
	ADDC   t2, h0, h0;   \
	ADDE   t3, h1, h1;   \
	ADDZE  h2

DATA ·poly1305Mask<>+0x00(SB)/8, $0x0FFFFFFC0FFFFFFF
DATA ·poly1305Mask<>+0x08(SB)/8, $0x0FFFFFFC0FFFFFFC
GLOBL ·poly1305Mask<>(SB), RODATA, $16

// func update(state *[7]uint64, msg []byte)

TEXT ·update(SB), $0-32
	MOVD state+0(FP), R3
	MOVD msg_base+8(FP), R4
	MOVD msg_len+16(FP), R5

	MOVD 0(R3), R8   // h0
	MOVD 8(R3), R9   // h1
	MOVD 16(R3), R10 // h2
	MOVD 24(R3), R11 // r0
	MOVD 32(R3), R12 // r1

	CMP R5, $16
	BLT bytes_between_0_and_15

loop:
	POLY1305_ADD(R4, R8, R9, R10)

multiply:
	POLY1305_MUL(R8, R9, R10, R11, R12, R16, R17, R18, R14)
	ADD $-16, R5
	CMP R5, $16
	BGE loop

bytes_between_0_and_15:
	CMP  $0, R5
	BEQ  done
	MOVD $0, R16 // h0
	MOVD $0, R17 // h1

flush_buffer:
	CMP R5, $8
	BLE just1

	// Greater than 8 -- load 2nd double word from msg
	MOVD 8(R4), R17

	// Find bytes to clear
	MOVD $16, R21
	SUB  R5, R21, R21

	// Find location for 1
	MOVD $8, R22
	SUB  R21, R22, R22

	// SUB $8,R5,R21
	SLD $3, R21

	// Clear unused bytes
	SLD R21, R17, R17
	SRD R21, R17, R17

	// Put 1 at high end
	MOVD $1, R23
	SLD  $3, R22
	SLD  R22, R23, R23
	OR   R23, R17, R17

	// Remainder is 8
	MOVD $8, R5

just1:
	MOVD (R4), R16
	CMP  R5, $8
	BLT  less8

	// If R5 is 8 at this point, R17 was not loaded
	// and should just have 1 in high byte.
	CMP $0, R17

	// Check if we've already set R17
	BNE  carry
	MOVD $1, R17
	BR   carry

	// Determine bytes to shift
less8:
	// Put 1 at end of bytes
	SLD  $3, R5, R21
	MOVD $1, R20
	SLD  R21, R20, R20

	// Find bytes to clear
	MOVD $8, R21
	SUB  R5, R21, R21
	SLD  $3, R21
	SLD  R21, R16, R16
	SRD  R21, R16, R16
	OR   R16, R20, R16

carry:
	// Add new values to h0, h1, h2
	ADDC R16, R8
	ADDE R17, R9
	ADDE $0, R10
	MOVD $16, R5
	ADD  R5, R4
	BR   multiply

done:
	// Save h0, h1, h2 in state
	MOVD R8, 0(R3)
	MOVD R9, 8(R3)
	MOVD R10, 16(R3)
	RET

// func initialize(state *[7]uint64, key *[32]byte)
TEXT ·initialize(SB), $0-16
	MOVD state+0(FP), R3
	MOVD key+8(FP), R4

	// state[0...7] is initialized with zero
	// Load key
	MOVD 0(R4), R5
	MOVD 8(R4), R6
	MOVD 16(R4), R7
	MOVD 24(R4), R8

	// Address of key mask
	MOVD $·poly1305Mask<>(SB), R9

	// Save original key in state
	MOVD R7, 40(R3)
	MOVD R8, 48(R3)

	// Get mask
	MOVD (R9), R7
	MOVD 8(R9), R8

	// And with key
	AND R5, R7, R5
	AND R6, R8, R6

	// Save masked key in state
	MOVD R5, 24(R3)
	MOVD R6, 32(R3)
	RET

// func finalize(tag *[TagSize]byte, state *[7]uint64)
TEXT ·finalize(SB), $0-16
	MOVD tag+0(FP), R3
	MOVD state+8(FP), R4

	// Get h0, h1, h2 from state
	MOVD 0(R4), R5
	MOVD 8(R4), R6
	MOVD 16(R4), R7

	// Save h0, h1
	MOVD  R5, R8
	MOVD  R6, R9
	MOVD  $3, R20
	MOVD  $-1, R21
	SUBC  $-5, R5
	SUBE  R21, R6
	SUBE  R20, R7
	MOVD  $0, R21
	SUBZE R21
	CMP   $0, R21
	BEQ   nocarry1
	MOVD  R8, R5
	MOVD  R9, R6

nocarry1:
	MOVD 40(R4), R8
	MOVD 48(R4), R9

done:
	ADDC R8, R5
	ADDE R9, R6
	MOVD R5, 0(R3)
	MOVD R6, 8(R3)
	RET
