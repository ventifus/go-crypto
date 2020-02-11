// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build s390x,go1.11,!gccgo,!appengine

#include "textflag.h"

// Implementation of Poly1305 using the vector facility (vx).

// constants
#define MOD24 V0
#define MOD26 V1
#define EX0   V2
#define EX1   V3
#define EX2   V4

// temporaries
#define T_0 V5
#define T_1 V6
#define T_2 V7
#define T_3 V8
#define T_4 V9

// key (r)
#define R_0  V10
#define R_1  V11
#define R_2  V12
#define R_3  V13
#define R_4  V14
#define R5_1 V15
#define R5_2 V16
#define R5_3 V17
#define R5_4 V18

// message block
#define F_0 V22
#define F_1 V23
#define F_2 V24
#define F_3 V25
#define F_4 V26

// accumulator
#define H_0 V27
#define H_1 V28
#define H_2 V29
#define H_3 V30
#define H_4 V31

GLOBL ·constants<>(SB), RODATA, $0x30
// EX0
DATA ·constants<>+0x00(SB)/8, $0x0006050403020100
DATA ·constants<>+0x08(SB)/8, $0x1016151413121110
// EX1
DATA ·constants<>+0x10(SB)/8, $0x060c0b0a09080706
DATA ·constants<>+0x18(SB)/8, $0x161c1b1a19181716
// EX2
DATA ·constants<>+0x20(SB)/8, $0x0d0d0d0d0d0f0e0d
DATA ·constants<>+0x28(SB)/8, $0x1d1d1d1d1d1f1e1d

// h = (f*g) % (2**130-5) [partial reduction]
#define MULTIPLY(f0, f1, f2, f3, f4, g0, g1, g2, g3, g4, g51, g52, g53, g54, h0, h1, h2, h3, h4) \
	VMLOF  f0, g0, h0        \
	VMLOF  f0, g3, h3        \
	VMLOF  f0, g1, h1        \
	VMLOF  f0, g4, h4        \
	VMLOF  f0, g2, h2        \
	VMLOF  f1, g54, T_0      \
	VMLOF  f1, g2, T_3       \
	VMLOF  f1, g0, T_1       \
	VMLOF  f1, g3, T_4       \
	VMLOF  f1, g1, T_2       \
	VMALOF f2, g53, h0, h0   \
	VMALOF f2, g1, h3, h3    \
	VMALOF f2, g54, h1, h1   \
	VMALOF f2, g2, h4, h4    \
	VMALOF f2, g0, h2, h2    \
	VMALOF f3, g52, T_0, T_0 \
	VMALOF f3, g0, T_3, T_3  \
	VMALOF f3, g53, T_1, T_1 \
	VMALOF f3, g1, T_4, T_4  \
	VMALOF f3, g54, T_2, T_2 \
	VMALOF f4, g51, h0, h0   \
	VMALOF f4, g54, h3, h3   \
	VMALOF f4, g52, h1, h1   \
	VMALOF f4, g0, h4, h4    \
	VMALOF f4, g53, h2, h2   \
	VAG    T_0, h0, h0       \
	VAG    T_3, h3, h3       \
	VAG    T_1, h1, h1       \
	VAG    T_4, h4, h4       \
	VAG    T_2, h2, h2

// carry h0->h1 h3->h4, h1->h2 h4->h0, h0->h1 h2->h3, h3->h4
#define REDUCE(h0, h1, h2, h3, h4) \
	VESRLG $26, h0, T_0  \
	VESRLG $26, h3, T_1  \
	VN     MOD26, h0, h0 \
	VN     MOD26, h3, h3 \
	VAG    T_0, h1, h1   \
	VAG    T_1, h4, h4   \
	VESRLG $26, h1, T_2  \
	VESRLG $26, h4, T_3  \
	VN     MOD26, h1, h1 \
	VN     MOD26, h4, h4 \
	VESLG  $2, T_3, T_4  \
	VAG    T_3, T_4, T_4 \
	VAG    T_2, h2, h2   \
	VAG    T_4, h0, h0   \
	VESRLG $26, h2, T_0  \
	VESRLG $26, h0, T_1  \
	VN     MOD26, h2, h2 \
	VN     MOD26, h0, h0 \
	VAG    T_0, h3, h3   \
	VAG    T_1, h1, h1   \
	VESRLG $26, h3, T_2  \
	VN     MOD26, h3, h3 \
	VAG    T_2, h4, h4

// expand in0 into d[0] and in1 into d[1]
#define EXPAND(in0, in1, d0, d1, d2, d3, d4) \
	VPERM  in0, in1, EX0, d0 \
	VPERM  in0, in1, EX1, d2 \
	VPERM  in0, in1, EX2, d4 \
	VESRLG $26, d0, d1       \
	VESRLG $30, d2, d3       \
	VESRLG $4, d2, d2        \
	VN     MOD26, d0, d0     \
	VN     MOD26, d3, d3     \
	VN     MOD26, d1, d1     \
	VN     MOD24, d4, d4     \ // high limb is only 24 bits
	VN     MOD26, d2, d2

// pack h4:h0 into h1:h0 (no carry)
#define PACK(h0, h1, h2, h3, h4) \
	VESLG $26, h1, h1  \
	VESLG $26, h3, h3  \
	VO    h0, h1, h0   \
	VO    h2, h3, h2   \
	VESLG $4, h2, h2   \
	VLEIB $7, $48, h1  \
	VSLB  h1, h2, h2   \
	VO    h0, h2, h0   \
	VLEIB $7, $104, h1 \
	VSLB  h1, h4, h3   \
	VO    h3, h0, h0   \
	VLEIB $7, $24, h1  \
	VSRLB h1, h4, h1

// func updateVX(state *macState, msg []byte)
TEXT ·updateVX(SB), NOSPLIT, $0
	// This code processes up to 2 blocks (32 bytes) per iteration
	// using the algorithm described in:
	// NEON crypto, Daniel J. Bernstein & Peter Schwabe
	// https://cryptojedi.org/papers/neoncrypto-20120320.pdf
	MOVD state+0(FP), R1
	LMG  msg+8(FP), R2, R3

	// load EX0, EX1 and EX2
	MOVD $·constants<>(SB), R5
	VLM  (R5), EX0, EX2

	// generate masks
	VGMG $(64-24), $63, MOD24 // [0x00ffffff, 0x00ffffff]
	VGMG $(64-26), $63, MOD26 // [0x03ffffff, 0x03ffffff]

	// load h & r
	MOVD    $7, R0
	VL      0(R1), T_0        // [h₆₄[0], h₆₄[1]]
	VL      16(R1), T_1       // [h₆₄[2], r₆₄[0]]
	VLL     R0, 32(R1), T_2   // [r₆₄[1], 0]
	VPDI    $1, T_0, T_1, T_3 // [h₆₄[0], r₆₄[0]]
	VPDI    $4, T_0, T_2, T_4 // [h₆₄[1], r₆₄[1]]

	// split h & r into 26 bit limbs
	VN      MOD26, T_3, H_0
	VZERO   H_1
	VZERO   H_3
	VZERO   H_4
	VGMG    $(64-12-14), $(63-12), T_0
	VERIMG  $-26&63, T_3, MOD26, H_1
	VESRLG  $+52&63, T_3, H_2
	VERIMG  $-14&63, T_4, MOD26, H_3
	VERIMG  $-40&63, T_4, MOD24, H_4
	VERIMG  $+12&63, T_4, T_0, H_2

	// replicate r across all 4 words
	VREPF $3, H_0, R_0 // [r₂₆[0], r₂₆[0], r₂₆[0], r₂₆[0]]
	VREPF $3, H_1, R_1 // [r₂₆[1], r₂₆[1], r₂₆[1], r₂₆[1]]
	VREPF $3, H_2, R_2 // [r₂₆[2], r₂₆[2], r₂₆[2], r₂₆[2]]
	VREPF $3, H_3, R_3 // [r₂₆[3], r₂₆[3], r₂₆[3], r₂₆[3]]
	VREPF $3, H_4, R_4 // [r₂₆[4], r₂₆[4], r₂₆[4], r₂₆[4]]

	// set the highest 2 bits in h₂₆[4] (the lowest 2 bits in h₆₄[2])
	VGMG   $(64-24-2), $(63-24), T_0
	VERIMG $+24&63, T_1, T_0, H_4

	// zero out index 1 of h
	VLEIG $1, $0, H_0 // [h₂₆[0], 0]
	VLEIG $1, $0, H_1 // [h₂₆[1], 0]
	VLEIG $1, $0, H_2 // [h₂₆[2], 0]
	VLEIG $1, $0, H_3 // [h₂₆[3], 0]
	VLEIG $1, $0, H_4 // [h₂₆[4], 0]

	// calculate 5r (ignore least significant limb)
	VREPIF $5, T_0
	VMLF   T_0, R_1, R5_1
	VMLF   T_0, R_2, R5_2
	VMLF   T_0, R_3, R5_3
	VMLF   T_0, R_4, R5_4

	// skip r² calculation
	CMPBLE R3, $16, skip

	// calculate r²
	MULTIPLY(R_0, R_1, R_2, R_3, R_4, R_0, R_1, R_2, R_3, R_4, R5_1, R5_2, R5_3, R5_4, F_0, F_1, F_2, F_3, F_4)
	REDUCE(F_0, F_1, F_2, F_3, F_4)
	VGBM   $0x0f0f, T_0
	VERIMG $0, F_0, T_0, R_0 // [r₂₆[0], r²₂₆[0], r₂₆[0], r²₂₆[0]]
	VERIMG $0, F_1, T_0, R_1 // [r₂₆[1], r²₂₆[1], r₂₆[1], r²₂₆[1]]
	VERIMG $0, F_2, T_0, R_2 // [r₂₆[2], r²₂₆[2], r₂₆[2], r²₂₆[2]]
	VERIMG $0, F_3, T_0, R_3 // [r₂₆[3], r²₂₆[3], r₂₆[3], r²₂₆[3]]
	VERIMG $0, F_4, T_0, R_4 // [r₂₆[4], r²₂₆[4], r₂₆[4], r²₂₆[4]]

	// calculate 5r² (ignore least significant limb)
	VREPIF $5, T_0
	VMLF   T_0, R_1, R5_1
	VMLF   T_0, R_2, R5_2
	VMLF   T_0, R_3, R5_3
	VMLF   T_0, R_4, R5_4

loop:
	CMPBLE R3, $32, b2
	VLM    (R2), T_0, T_1
	SUB    $32, R3
	MOVD   $32(R2), R2
	EXPAND(T_0, T_1, F_0, F_1, F_2, F_3, F_4)
	VLEIB  $4, $1, F_4
	VLEIB  $12, $1, F_4

multiply:
	VAG    H_0, F_0, F_0
	VAG    H_3, F_3, F_3
	VAG    H_1, F_1, F_1
	VAG    H_4, F_4, F_4
	VAG    H_2, F_2, F_2
	MULTIPLY(F_0, F_1, F_2, F_3, F_4, R_0, R_1, R_2, R_3, R_4, R5_1, R5_2, R5_3, R5_4, H_0, H_1, H_2, H_3, H_4)
	REDUCE(H_0, H_1, H_2, H_3, H_4)
	CMPBNE R3, $0, loop

finish:
	// sum vectors
	VZERO  T_0
	VSUMQG H_0, T_0, H_0
	VSUMQG H_3, T_0, H_3
	VSUMQG H_1, T_0, H_1
	VSUMQG H_4, T_0, H_4
	VSUMQG H_2, T_0, H_2

	// h may be >= 2*(2**130-5) so we need to reduce it again
	REDUCE(H_0, H_1, H_2, H_3, H_4)

	// h is now < 2*(2**130-5)
	// pack h into h1 (hi) and h0 (lo)
	PACK(H_0, H_1, H_2, H_3, H_4)

	// update state
	VSTEG $1, H_0, 0(R1)
	VSTEG $0, H_0, 8(R1)
	VSTEG $1, H_1, 16(R1)
	RET

b2:
	CMPBLE R3, $16, b1

	// 2 blocks remaining
	SUB    $17, R3
	VL     (R2), T_0
	VLL    R3, 16(R2), T_1
	ADD    $1, R3
	MOVBZ  $1, R0
	CMPBEQ R3, $16, 2(PC)
	VLVGB  R3, R0, T_1
	EXPAND(T_0, T_1, F_0, F_1, F_2, F_3, F_4)
	CMPBNE R3, $16, 2(PC)
	VLEIB  $12, $1, F_4
	VLEIB  $4, $1, F_4

	// setup [r²,r]
	VGBM   $0x00ff, T_0
	VERIMG $32, R_0, T_0, R_0
	VERIMG $32, R_1, T_0, R_1
	VERIMG $32, R_2, T_0, R_2
	VERIMG $32, R_3, T_0, R_3
	VERIMG $32, R_4, T_0, R_4
	VERIMG $32, R5_1, T_0, R5_1
	VERIMG $32, R5_2, T_0, R5_2
	VERIMG $32, R5_3, T_0, R5_3
	VERIMG $32, R5_4, T_0, R5_4

	MOVD $0, R3
	BR   multiply

skip:
	CMPBEQ R3, $0, finish

b1:
	// 1 block remaining
	SUB    $1, R3
	VLL    R3, (R2), T_0
	ADD    $1, R3
	MOVBZ  $1, R0
	CMPBEQ R3, $16, 2(PC)
	VLVGB  R3, R0, T_0
	VZERO  T_1
	EXPAND(T_0, T_1, F_0, F_1, F_2, F_3, F_4)
	CMPBNE R3, $16, 2(PC)
	VLEIB  $4, $1, F_4

	// setup [r, 1]
	VZERO T_0
	MOVD  $0, R0
	MOVD  $0x10111213, R12
	VLVGP R12, R0, T_1
	VPERM T_0, R_0, T_1, R_0
	VPERM T_0, R_1, T_1, R_1
	VPERM T_0, R_2, T_1, R_2
	VPERM T_0, R_3, T_1, R_3
	VPERM T_0, R_4, T_1, R_4
	VPERM T_0, R5_1, T_1, R5_1
	VPERM T_0, R5_2, T_1, R5_2
	VPERM T_0, R5_3, T_1, R5_3
	VPERM T_0, R5_4, T_1, R5_4
	VLEIF $3, $1, R_0

	MOVD $0, R3
	BR   multiply
