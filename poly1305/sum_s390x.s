// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build s390x,!gccgo,!appengine,go1.8

#include "textflag.h"

#define POLY1305_ADD(msg, h0, h1, h2) \
	MOVDBR 0(msg), R0;   \
	ADDC   R0, h0;       \
	MOVDBR 8(msg), R0;   \
	ADDE   R0, h1;       \
	MOVD   $1, R0;       \
	ADDE   R0, h2;       \
	MOVD   $16(msg), msg

#define POLY1305_MUL(h0, h1, h2, t0, t1, t2, t3) \
	MOVD  r0-16(SP), R1;                       \
	WORD  $0xB9860008; /* MLGR R8(h0),R0:R1 */ \
	MOVD  R1, t0;                              \
	MOVD  R0, t1;                              \
	MOVD  r0-16(SP), R1;                       \
	WORD  $0xB9860009; /* MLGR R9(h1),R0:R1 */ \
	ADDC  R1, t1;                              \
	MOVD  $0, R1;                              \
	ADDE  R1, R0;                              \
	MOVD  r0-16(SP), t2;                       \
	MULLD h2, t2;                              \
	ADD   R0, t2;                              \
	                                           \
	MOVD  r1-8(SP), R1;                        \
	WORD  $0xB9860008; /* MLGR R8(h0),R0:R1 */ \
	ADDC  R1, t1;                              \
	MOVD  $0, R1;                              \
	ADDE  R1, R0;                              \
	MOVD  R0, h0;                              \
	MOVD  r1-8(SP), t3;                        \
	MULLD h2, t3;                              \
	MOVD  r1-8(SP), R1;                        \
	WORD  $0xB9860009; /* MLGR R9(h1),R0:R1 */ \
	ADDC  R1, t2;                              \
	ADDE  R0, t3;                              \
	ADDC  h0, t2;                              \
	MOVD  $0, R1;                              \
	ADDE  R1, t3;                              \
	                                           \
	MOVD  $0, R0;                              \
	MOVD  t0, h0;                              \
	MOVD  t1, h1;                              \
	MOVD  t2, h2;                              \
	ANDW  $3, h2;                              \
	MOVWZ h2, h2;                              \
	MOVD  t2, t0;                              \
	AND   $0xFFFFFFFFFFFFFFFC, t0;             \
	ADDC  t0, h0;                              \
	ADDE  t3, h1;                              \
	ADDE  R0, h2;                              \
	SRD   $2, t2;                              \
	SLD   $62, t3, R1;                         \
	OR    R1, t2;                              \
	SRD   $2, t3;                              \
	ADDC  t2, h0;                              \
	ADDE  t3, h1;                              \
	ADDE  R0, h2

// func poly1305(out *[16]byte, m *byte, mlen uint64, key *[32]key)
TEXT ·poly1305(SB), $16-32
	MOVD m+8(FP), R5
	MOVD mlen+16(FP), R7
	MOVD key+24(FP), R3

	// load the first 16 bytes of the key in little endian order
	MOVDBR 0(R3), R1
	MOVDBR 8(R3), R2

	// load 0x0ffffffc0fffffff into R8
	WORD $0xc0880fff; BYTE $0xff; BYTE $0xfc // iihf r8,0x0ffffffc
	WORD $0xc0890fff; BYTE $0xff; BYTE $0xff // iilf r8,0x0fffffff

	// load 0x0ffffffc0ffffffc into R9
	WORD $0xc0980fff; BYTE $0xff; BYTE $0xfc // iihf r9,0x0ffffffc
	WORD $0xc0990fff; BYTE $0xff; BYTE $0xfc // iilf r9,0x0ffffffc

	AND    R8, R1
	AND    R9, R2
	MOVD   R1, r0-16(SP)
	MOVD   R2, r1-8(SP)

	MOVD $0, R8 // h0
	MOVD $0, R9 // h1
	MOVD $0, R6 // h2

	CMPBLT R7, $16, bytes_between_0_and_15

loop:
	POLY1305_ADD(R5, R8, R9, R6)

multiply:
	POLY1305_MUL(R8, R9, R6, R3, R2, R4, R12)
	MOVD   $-16(R7), R7
	CMPBGE R7, $16, loop

bytes_between_0_and_15:
	CMPBEQ R7, $0, done
	MOVD   $1, R3
	MOVD   $0, R2
	MOVD   $0, R4
	ADD    R7, R5

flush_buffer:
	SLD   $8, R2
	SRD   $56, R3, R0
	OR    R0, R2
	SLD   $8, R3
	MOVBZ -1(R5), R4
	XOR   R4, R3
	ADD   $-1, R5
	ADD   $-1, R7
	BNE   flush_buffer

	MOVD $0, R0
	ADDC R3, R8
	ADDE R2, R9
	ADDE R0, R6
	MOVD $16, R7
	BR   multiply

done:
	MOVD   $0xFFFFFFFFFFFFFFFF, R4
	MOVD   $3, R5
	MOVD   R8, R0
	MOVD   R9, R3
	SUBC   $0xFFFFFFFFFFFFFFFB, R0
	SUBE   R4, R3
	SUBE   R5, R6
	MOVDLE R8, R0
	MOVDLE R9, R3
	MOVD   key+24(FP), R8
	MOVDBR 16(R8), R4
	MOVDBR 24(R8), R2
	ADDC   R4, R0
	ADDE   R2, R3

	MOVD   out+0(FP), R2
	MOVDBR R0, 0(R2)
	MOVDBR R3, 8(R2)

	RET
