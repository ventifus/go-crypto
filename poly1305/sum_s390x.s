// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.8,s390x,!gccgo,!appengine

#include "textflag.h"

// Implementation of Poly1305 using z196 instructions.

#define MSG R9
#define REM R12

#define H_0 R6 // fixed
#define H_1 R7 // fixed
#define H_2 R8

#define T_0 R0 // fixed
#define T_1 R1 // fixed
#define T_2 R2
#define T_3 R3
#define T_4 R4
#define T_5 R5

#define MULTIPLY(h0, h1, h2, t0, t1, t2, t3) \
	MOVD  r0-16(SP), T_1 \
	WORD  $0xB9860006    \ // T_0:T_1 = h0 * T_1 (mlgr)
	MOVD  T_1, t0        \
	MOVD  T_0, t1        \
	MOVD  r0-16(SP), T_1 \
	WORD  $0xB9860007    \ // T_0:T_1 = h1 * T_1 (mlgr)
	ADDC  T_1, t1        \
	MOVD  $0, T_1        \
	ADDE  T_1, T_0       \
	MOVD  r0-16(SP), t2  \
	MULLD h2, t2         \
	ADD   T_0, t2        \
	                     \
	MOVD  r1-8(SP), T_1  \
	WORD  $0xB9860006    \ // T_0:T_1 = h0 * T_1 (mlgr)
	ADDC  T_1, t1        \
	MOVD  $0, T_1        \
	ADDE  T_1, T_0       \
	MOVD  T_0, h0        \
	MOVD  r1-8(SP), T_1  \
	MOVD  T_1, t3        \
	MULLD h2, t3         \
	WORD  $0xB9860007    \ // T_0:T_1 = h1 * T_1 (mlgr)
	ADDC  T_1, t2        \
	ADDE  T_0, t3        \
	ADDC  h0, t2         \
	MOVD  $0, T_0        \
	ADDE  T_0, t3        \
	                     \
	MOVD  t0, h0         \
	MOVD  t1, h1         \
	MOVD  t2, h2         \
	ANDW  $3, h2         \
	MOVWZ h2, h2         \
	MOVD  t2, t0         \
	AND   $~0x3, t0      \
	ADDC  t0, h0         \
	ADDE  t3, h1         \
	ADDE  T_0, h2        \
	SRD   $2, t2         \
	SLD   $62, t3, T_1   \
	OR    T_1, t2        \
	SRD   $2, t3         \
	ADDC  t2, h0         \
	ADDE  t3, h1         \
	ADDE  T_0, h2

#define LOAD64(hi, lo, reg) \
	BYTE $0xc0; BYTE $(0x8 + (reg<<4)); WORD $hi \ // iihf
	BYTE $0xc0; BYTE $(0x9 + (reg<<4)); WORD $lo // iilf

// Target for execute instruction, should not be called.
TEXT ·mvc(SB), NOFRAME|NOSPLIT, $0-0
	MVC $1, (MSG), (T_1)
	RET                  // not reached

// func poly1305z196(out *[16]byte, m *byte, mlen uint64, key *[32]key)
TEXT ·poly1305z196(SB), NOSPLIT, $32-48
	MOVD m+8(FP), MSG
	MOVD mlen+16(FP), REM
	MOVD key+24(FP), T_1

	// clear storage for the last block
	XC $16, tmp-32(SP), tmp-32(SP)

	// load the first 16 bytes of the key into T_2:T_3
	MOVDBR 0(T_1), T_2
	MOVDBR 8(T_1), T_3

	// load clamp mask into R1:R0 (T_1:T_0)
	LOAD64(0x0ffffffc, 0x0fffffff, 0)
	LOAD64(0x0ffffffc, 0x0ffffffc, 1)

	AND  T_0, T_2
	AND  T_1, T_3
	MOVD T_2, r0-16(SP)
	MOVD T_3, r1-8(SP)

	MOVD $0, H_0 // h0
	MOVD $0, H_1 // h1
	MOVD $0, H_2 // h2

	CMPBLT REM, $16, tail

loop:
	// load next block
	MOVDBR 0(MSG), T_0
	MOVDBR 8(MSG), T_1
	MOVD   $16(MSG), MSG
	MOVD   $1, T_2

	// accumulate
	ADDC T_0, H_0
	ADDE T_1, H_1
	ADDE T_2, H_2

	MOVD $-16(REM), REM

multiply:
	MULTIPLY(H_0, H_1, H_2, T_2, T_3, T_4, T_5)
	CMPBGE REM, $16, loop

tail:
	CMPBEQ REM, $0, finish
	SUB    $1, REM
	MOVD   $tmp-32(SP), T_1
	EXRL   $·mvc(SB), REM
	MOVB   $1, 1(REM)(T_1*1)
	MOVD   $0, REM
	MOVDBR 0(T_1), T_2
	MOVDBR 8(T_1), T_3
	ADDC   T_2, H_0
	ADDE   T_3, H_1
	ADDE   REM, H_2
	BR     multiply

finish:
	ADDC   $5, H_0, T_0
	MOVD   H_1, T_1
	ADDE   REM, T_1        // REM==0
	MOVD   $-4, T_2
	ADDE   H_2, T_2
	MOVD   $-1, T_3
	ADDE   T_3, REM        // REM==mask
	AND    REM, H_0
	AND    REM, H_1
	XOR    T_3, REM        // ~REM
	AND    REM, T_0
	AND    REM, T_1
	OR     T_0, H_0
	OR     T_1, H_1
	MOVD   key+24(FP), T_4
	MOVDBR 16(T_4), T_0
	MOVDBR 24(T_4), T_1
	ADDC   T_0, H_0
	ADDE   T_1, H_1
	MOVD   out+0(FP), T_2
	MOVDBR H_0, 0(T_2)
	MOVDBR H_1, 8(T_2)

	RET

