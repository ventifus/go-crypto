// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !gccgo,!purego

#include "textflag.h"

// This implementation of Poly1305 uses the vector facility (vx)
// to process up to 2 blocks (32 bytes) per iteration using an
// algorithm based on the one described in:
//
// NEON crypto, Daniel J. Bernstein & Peter Schwabe
// https://cryptojedi.org/papers/neoncrypto-20120320.pdf
//
// This algorithm uses 5 26-bit limbs to represent a 130-bit
// value. These limbs are, for the most part, zero extended and
// placed into 64-bit vector register elements. Each vector
// register is 128-bits wide and so holds 2 of these elements.
// Using 26-bit limbs allows us plenty of headroom to accomodate
// accumulations before and after multiplication without
// overflowing either 32-bits (before multiplication) or 64-bits
// (after multiplication).
//
// In order to parallelise the operations required to calculate
// the sum we use two separate accumulators and then sum those
// in an extra final step. For compatibility with the generic
// implementation we perform this summation at the end of every
// updateVX call.
//
// To use two accumulators we must multiply the message blocks
// by r² rather than r. Only the final message block should be
// multiplied by r.
//
// Example:
//
// We want to calculate the sum (h) for a 64 byte message (m):
//
//   h = m[0:16]r⁴ + m[16:32]r³ + m[32:48]r² + m[48:64]r
//
// To do this we split the calculation into the even indices
// and odd indices of the message. These form our SIMD 'lanes':
//
//   h = m[ 0:16]r⁴ + m[32:48]r² +   <- lane 0
//       m[16:32]r³ + m[48:64]r      <- lane 1
//
// To calculate this iteratively we refactor so that both lanes
// are written in terms of r² and r:
//
//   h = (m[ 0:16]r² + m[32:48])r² + <- lane 0
//       (m[16:32]r² + m[48:64])r    <- lane 1
//                ^             ^
//                |             coefficients for second iteration
//                coefficients for first iteration
//
// So in this case we would have two iterations. In the first
// both lanes are multiplied by r². In the second only the
// first lane is multiplied by r² and the second lane is
// instead multiplied by r. This gives use the odd and even
// powers of r that we need from the original equation.
//
// Notation:
//
//   h - accumulator
//   r - key
//   m - message
//
//   [a, b]       - SIMD register holding two 64-bit values
//   [a, b, c, d] - SIMD register holding four 32-bit values
//   xᵢ[n]        - limb n of variable x with bit width i
//
// Limbs are expressed in little endian order, so for 26-bit
// limbs x₂₆[4] will be the most significant limb and x₂₆[0]
// will be the least significant limb.

// masking constants
#define MOD24 V0 // [0x0000000000ffffff, 0x0000000000ffffff] - mask low 24-bits
#define MOD26 V1 // [0x0000000003ffffff, 0x0000000003ffffff] - mask low 26-bits

// expansion constants (see EXPAND macro)
#define EX0 V2
#define EX1 V3
#define EX2 V4

// key (r², r or 1 depending on context)
#define R_0 V5
#define R_1 V6
#define R_2 V7
#define R_3 V8
#define R_4 V9

// precalculated coefficients (5r², 5r or 0 depending on context)
#define R5_1 V10
#define R5_2 V11
#define R5_3 V12
#define R5_4 V13

// message block (m)
#define M_0 V14
#define M_1 V15
#define M_2 V16
#define M_3 V17
#define M_4 V18

// accumulator (h)
#define H_0 V19
#define H_1 V20
#define H_2 V21
#define H_3 V22
#define H_4 V23

// temporary registers (for short-lived values)
#define T_0 V24
#define T_1 V25
#define T_2 V26
#define T_3 V27
#define T_4 V28

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

// MULTIPLY multiplies each lane of f and g, partially reduced
// modulo 2¹³⁰-5. The result, h, consists of partial products
// in each lane that need to be reduced further to produce the
// final result.
//
//   h₁₃₀ = (f₁₃₀g₁₃₀) % 2¹³⁰ + (5f₁₃₀g₁₃₀) / 2¹³⁰
//
// Note that the multiplication by 5 of the high bits is
// acheived by precalculating the multiplication of four of the
// g coefficients by 5. These are g51-g54.
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

// REDUCE performs the following carry operations in four
// stages, as specified in Bernstein & Schwabe:
//
//   1: h₂₆[0]->h₂₆[1] h₂₆[3]->h₂₆[4]
//   2: h₂₆[1]->h₂₆[2] h₂₆[4]->h₂₆[0]
//   3: h₂₆[0]->h₂₆[1] h₂₆[2]->h₂₆[3]
//   4: h₂₆[3]->h₂₆[4]
//
// The result is that all of the limbs are limited to 26-bits
// except for h₂₆[1] and h₂₆[4] which are limited to 27-bits.
//
// Note that although each limb is aligned at 26-bit intervals
// they may contain values that exceed 2²⁶-1, hence the need
// to carry the excess bits in each limb.
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

// EXPAND splits the 128-bit little-endian values in0 and in1
// into 26-bit big-endian limbs and places the results into
// the first and second lane of d₂₆[0:4] respectively.
//
// The EX0, EX1 and EX2 constants are arrays of byte indices
// for permutation. The permutation both reverses the bytes
// in the input and ensures the bytes are copied into the
// destination limb ready to be shifted into their final
// position.
#define EXPAND(in0, in1, d0, d1, d2, d3, d4) \
	VPERM  in0, in1, EX0, d0 \
	VPERM  in0, in1, EX1, d2 \
	VPERM  in0, in1, EX2, d4 \
	VESRLG $26, d0, d1       \
	VESRLG $30, d2, d3       \
	VESRLG $4, d2, d2        \
	VN     MOD26, d0, d0     \ // [in0₂₆[0], in1₂₆[0]]
	VN     MOD26, d3, d3     \ // [in0₂₆[3], in1₂₆[3]]
	VN     MOD26, d1, d1     \ // [in0₂₆[1], in1₂₆[1]]
	VN     MOD24, d4, d4     \ // [in0₂₆[4], in1₂₆[4]]
	VN     MOD26, d2, d2     // [in0₂₆[2], in1₂₆[2]]

// func updateVX(state *macState, msg []byte)
TEXT ·updateVX(SB), NOSPLIT, $0
	MOVD state+0(FP), R1
	LMG  msg+8(FP), R2, R3 // R2=msg_base, R3=msg_len

	// load EX0, EX1 and EX2
	MOVD $·constants<>(SB), R5
	VLM  (R5), EX0, EX2

	// generate masks
	VGMG $(64-24), $63, MOD24 // [0x00ffffff, 0x00ffffff]
	VGMG $(64-26), $63, MOD26 // [0x03ffffff, 0x03ffffff]

	// load h (accumulator) and r (key) from state
	MOVD $7, R0
	VL   0(R1), T_0        // [h₆₄[0], h₆₄[1]]
	VL   16(R1), T_1       // [h₆₄[2], r₆₄[0]]
	VLL  R0, 32(R1), T_2   // [r₆₄[1], 0]
	VPDI $1, T_0, T_1, T_3 // [h₆₄[0], r₆₄[0]]
	VPDI $4, T_0, T_2, T_4 // [h₆₄[1], r₆₄[1]]

	// split h and r into 26-bit limbs
	VN     MOD26, T_3, H_0
	VZERO  H_1
	VZERO  H_3
	VZERO  H_4
	VGMG   $(64-12-14), $(63-12), T_0
	VERIMG $-26&63, T_3, MOD26, H_1
	VESRLG $+52&63, T_3, H_2
	VERIMG $-14&63, T_4, MOD26, H_3
	VERIMG $-40&63, T_4, MOD24, H_4
	VERIMG $+12&63, T_4, T_0, H_2

	// replicate r across all 4 vector elements
	VREPF $3, H_0, R_0 // [r₂₆[0], r₂₆[0], r₂₆[0], r₂₆[0]]
	VREPF $3, H_1, R_1 // [r₂₆[1], r₂₆[1], r₂₆[1], r₂₆[1]]
	VREPF $3, H_2, R_2 // [r₂₆[2], r₂₆[2], r₂₆[2], r₂₆[2]]
	VREPF $3, H_3, R_3 // [r₂₆[3], r₂₆[3], r₂₆[3], r₂₆[3]]
	VREPF $3, H_4, R_4 // [r₂₆[4], r₂₆[4], r₂₆[4], r₂₆[4]]

	// set the highest 2 bits in h₂₆[4] (the lowest 2 bits in h₆₄[2])
	VGMG   $(64-24-2), $(63-24), T_0
	VERIMG $+24&63, T_1, T_0, H_4

	// zero out lane 1 of h
	VLEIG $1, $0, H_0 // [h₂₆[0], 0]
	VLEIG $1, $0, H_1 // [h₂₆[1], 0]
	VLEIG $1, $0, H_2 // [h₂₆[2], 0]
	VLEIG $1, $0, H_3 // [h₂₆[3], 0]
	VLEIG $1, $0, H_4 // [h₂₆[4], 0]

	// calculate 5r (ignore least significant limb)
	VREPIF $5, T_0
	VMLF   T_0, R_1, R5_1 // [5r₂₆[1], 5r₂₆[1], 5r₂₆[1], 5r₂₆[1]]
	VMLF   T_0, R_2, R5_2 // [5r₂₆[2], 5r₂₆[2], 5r₂₆[2], 5r₂₆[2]]
	VMLF   T_0, R_3, R5_3 // [5r₂₆[3], 5r₂₆[3], 5r₂₆[3], 5r₂₆[3]]
	VMLF   T_0, R_4, R5_4 // [5r₂₆[4], 5r₂₆[4], 5r₂₆[4], 5r₂₆[4]]

	// skip r² calculation if we are only calculating one block
	CMPBLE R3, $16, skip

	// calculate r²
	MULTIPLY(R_0, R_1, R_2, R_3, R_4, R_0, R_1, R_2, R_3, R_4, R5_1, R5_2, R5_3, R5_4, M_0, M_1, M_2, M_3, M_4)
	REDUCE(M_0, M_1, M_2, M_3, M_4)
	VGBM   $0x0f0f, T_0
	VERIMG $0, M_0, T_0, R_0 // [r₂₆[0], r²₂₆[0], r₂₆[0], r²₂₆[0]]
	VERIMG $0, M_1, T_0, R_1 // [r₂₆[1], r²₂₆[1], r₂₆[1], r²₂₆[1]]
	VERIMG $0, M_2, T_0, R_2 // [r₂₆[2], r²₂₆[2], r₂₆[2], r²₂₆[2]]
	VERIMG $0, M_3, T_0, R_3 // [r₂₆[3], r²₂₆[3], r₂₆[3], r²₂₆[3]]
	VERIMG $0, M_4, T_0, R_4 // [r₂₆[4], r²₂₆[4], r₂₆[4], r²₂₆[4]]

	// calculate 5r² (ignore least significant limb)
	VREPIF $5, T_0
	VMLF   T_0, R_1, R5_1 // [5r₂₆[1], 5r²₂₆[1], 5r₂₆[1], 5r²₂₆[1]]
	VMLF   T_0, R_2, R5_2 // [5r₂₆[2], 5r²₂₆[2], 5r₂₆[2], 5r²₂₆[2]]
	VMLF   T_0, R_3, R5_3 // [5r₂₆[3], 5r²₂₆[3], 5r₂₆[3], 5r²₂₆[3]]
	VMLF   T_0, R_4, R5_4 // [5r₂₆[4], 5r²₂₆[4], 5r₂₆[4], 5r²₂₆[4]]

loop:
	CMPBLE R3, $32, b2 // 2 or fewer blocks remaining, need to change key coefficients

	// load next 2 blocks from message
	VLM (R2), T_0, T_1

	// update message slice
	SUB  $32, R3
	MOVD $32(R2), R2

	// unpack message blocks into 26-bit big-endian limbs
	EXPAND(T_0, T_1, M_0, M_1, M_2, M_3, M_4)

	// add 2¹²⁸ to each message block value
	VLEIB $4, $1, M_4
	VLEIB $12, $1, M_4

multiply:
	// accumulate the incoming message
	VAG H_0, M_0, M_0
	VAG H_3, M_3, M_3
	VAG H_1, M_1, M_1
	VAG H_4, M_4, M_4
	VAG H_2, M_2, M_2

	// multiply the accumulator by the key coefficient
	MULTIPLY(M_0, M_1, M_2, M_3, M_4, R_0, R_1, R_2, R_3, R_4, R5_1, R5_2, R5_3, R5_4, H_0, H_1, H_2, H_3, H_4)

	// carry and partially reduce the partial products
	REDUCE(H_0, H_1, H_2, H_3, H_4)

	CMPBNE R3, $0, loop

finish:
	// sum lane 0 and lane 1 and put the result in lane 1
	VZERO  T_0
	VSUMQG H_0, T_0, H_0
	VSUMQG H_3, T_0, H_3
	VSUMQG H_1, T_0, H_1
	VSUMQG H_4, T_0, H_4
	VSUMQG H_2, T_0, H_2

	// reduce again after summation
	// TODO(mundaym): there might be a more efficient way to do this
	// now that we only have 1 active lane. For example, we could
	// simultaneously pack the values as we reduce them.
	REDUCE(H_0, H_1, H_2, H_3, H_4)

	// carry h[1] through to h[4] so that only h[4] can exceed 2²⁶-1
	// TODO(mundaym): in testing this final carry was unnecessary.
	// Needs a proof before it can be removed though.
	VESRLG $26, H_1, T_1
	VN     MOD26, H_1, H_1
	VAQ    T_1, H_2, H_2
	VESRLG $26, H_2, T_2
	VN     MOD26, H_2, H_2
	VAQ    T_2, H_3, H_3
	VESRLG $26, H_3, T_3
	VN     MOD26, H_3, H_3
	VAQ    T_3, H_4, H_4

	// h is now < 2(2¹³⁰-5)
	// Pack each lane in h₂₆[0:4] into h₁₂₈[0:1].
	VESLG $26, H_1, H_1
	VESLG $26, H_3, H_3
	VO    H_0, H_1, H_0
	VO    H_2, H_3, H_2
	VESLG $4, H_2, H_2
	VLEIB $7, $48, H_1
	VSLB  H_1, H_2, H_2
	VO    H_0, H_2, H_0
	VLEIB $7, $104, H_1
	VSLB  H_1, H_4, H_3
	VO    H_3, H_0, H_0
	VLEIB $7, $24, H_1
	VSRLB H_1, H_4, H_1

	// update state
	VSTEG $1, H_0, 0(R1)
	VSTEG $0, H_0, 8(R1)
	VSTEG $1, H_1, 16(R1)
	RET

b2:  // 2 or fewer blocks remaining
	CMPBLE R3, $16, b1

	// 2 blocks remaining
	MOVD   $-17(R3), R0
	VL     (R2), T_0
	VLL    R0, 16(R2), T_1
	MOVBZ  $1, R0
	MOVD   $-16(R3), R3
	CMPBEQ R3, $16, 2(PC)
	VLVGB  R3, R0, T_1
	EXPAND(T_0, T_1, M_0, M_1, M_2, M_3, M_4)
	CMPBNE R3, $16, 2(PC)
	VLEIB  $12, $1, M_4
	VLEIB  $4, $1, M_4

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

b1:  // 1 block remaining
	MOVD   $-1(R3), R0
	VLL    R0, (R2), T_0
	MOVBZ  $1, R0
	CMPBEQ R3, $16, 2(PC)
	VLVGB  R3, R0, T_0
	VZERO  T_1
	EXPAND(T_0, T_1, M_0, M_1, M_2, M_3, M_4)
	CMPBNE R3, $16, 2(PC)
	VLEIB  $4, $1, M_4

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
