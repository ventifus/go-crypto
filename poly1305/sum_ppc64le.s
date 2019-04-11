// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// Implementation of Poly1305 using the vector facility
// based on the s390x asm implementation.

// Differences:
// - To do the equivalent of VLL (vector load length), a vector load
//   is done followed by VPERM and shift.
// - Since ppc64le does not have a multiply-add instruction, that is done
//   in separate steps using an intermediate result.
// - s390x has many more vector shift instructions with immediate shift
// values, on ppc64le it is necessary to put the count in vector register
// using a constant.
// - The sum across on s390x had to be done using multiple instructions.

// Registers for constants
#define MOD26 V0
#define MOD26_ VS32
#define EX0   V1
#define EX0_ VS33
#define EX1   V2
#define EX1_ VS34
#define EX2   V3
#define EX2_ VS35

// Temp registers
#define TMP0 V0 // overloaded with MOD26 -- reload when necessary
#define TMP0_ VS32
#define TMP1 V1 // overloaded with EX0
#define TMP1_ VS33
#define TMP2 V2 // overloaded with EX1
#define TMP2_ VS24
#define T_0 V4
#define T_0_ VS36
#define T_1 V5
#define T_1_ VS37
#define T_2 V6
#define T_2_ VS38
#define T_3 V7
#define T_3_ VS39
#define T_4 V8
#define T_4_ VS40

// Temp register used for VPERM string
#define SWAP V8
#define SWAP_ VS40

// key (r)
#define R_0  V9
#define R_1  V10
#define R_1_ VS42
#define R_2  V11
#define R_3  V12
#define R_4  V13
#define R5_1 V14
#define R5_1_ VS46
#define R5_2 V15
#define R5_2_ VS47
#define R5_3 V16
#define R5_3_ VS48
#define R5_4 V17
#define R5_4_ VS49
// Save registers
#define RSAVE_0 R15
#define RSAVE_1 R16
#define RSAVE_2 R17
#define RSAVE_3 R18
#define RSAVE_4 R19
#define R5SAVE_1 V28
#define R5SAVE_1_ VS60
#define R5SAVE_2 V29
#define R5SAVE_2_ VS61
#define R5SAVE_3 V30
#define R5SAVE_3_ VS62
#define R5SAVE_4 V31
#define R5SAVE_4_ VS63

// Holds the base of constants
#define CONSTBASE R7

// message block
#define F_0 V18
#define F_1 V19
#define F_1_ VS51
#define F_2 V20
#define F_3 V21
#define F_4 V22

// accumulator
#define H_0 V23
#define H_0_ VS55
#define H_1 V24
#define H_1_ VS56
#define H_2 V25
#define H_2_ VS57
#define H_3 V26
#define H_3_ VS58
#define H_4 V27
#define H_4_ VS59

// All constants are ordered for use with
// LXVD2X/STXVD2X

GLOBL ·keyMask<>(SB), RODATA, $16
DATA ·keyMask<>+0(SB)/8, $0x0ffffffc0ffffffc
DATA ·keyMask<>+8(SB)/8, $0x0ffffffc0fffffff

GLOBL ·constants<>(SB), RODATA, $112
// MOD26
DATA ·constants<>+0(SB)/8, $0x0000000003ffffff
DATA ·constants<>+8(SB)/8, $0x0000000003ffffff

// The following are used by EXPAND to put bytes
// in the proper order
// EX0
#define OFFEX0 $16
DATA ·constants<>+16(SB)/8, $0x0f090a0b0c0d0e0f
DATA ·constants<>+24(SB)/8, $0x1f191a1b1c1d1e1f
// EX1
#define OFFEX1 $32
DATA ·constants<>+32(SB)/8, $0x0903040506070809
DATA ·constants<>+40(SB)/8, $0x1913141516171819

// EX2
#define OFFEX2 $48
DATA ·constants<>+48(SB)/8, $0x0202020202000102
DATA ·constants<>+56(SB)/8, $0x1212121212101112

// ONEFIVE
#define ONEFIVE $64
DATA ·constants<>+64(SB)/8, $0x0000000000000000
DATA ·constants<>+72(SB)/8, $0x0000000000000005
// MINUS4
#define MINUS4 $80
DATA ·constants<>+80(SB)/8, $0xffffffffffffffff
DATA ·constants<>+88(SB)/8, $0xfffffffffffffffc
// TWOFIVES
#define TWOFIVES $96
DATA ·constants<>+96(SB)/8, $0x0000000000000005
DATA ·constants<>+104(SB)/8, $0x0000000000000005
// VPERM constants
// High double word
#define HIGHDW $112
DATA ·constants<>+112(SB)/8, $0x08090a0b0c0d0e0f
DATA ·constants<>+120(SB)/8, $0x1011121314151617
// Low double word
#define LOWDW $128
DATA ·constants<>+128(SB)/8, $0x0001020304050607
DATA ·constants<>+136(SB)/8, $0x18191a1b1c1d1e1f
#define BYTES412 $144
// Insert '1' at bytes 4 and 12
DATA ·constants<>+144(SB)/8, $0x000102031f050607
DATA ·constants<>+152(SB)/8, $0x08090a0b1f0d0e0f
// Reorder bytes from LXVXD2/STXVD2X to LE order
#define SWAPBASE $160
DATA ·constants<>+160(SB)/8, $0x08090a0b0c0d0e0f
DATA ·constants<>+168(SB)/8, $0x0001020304050607
#define BYTE4 $176
// Insert '1' at byte 4
DATA ·constants<>+176(SB)/8, $0x000102031f050607
DATA ·constants<>+184(SB)/8, $0x08090a0b0c0d0e0f
#define DOUBLE1 $192
// Insert '1' in high double word
DATA ·constants<>+192(SB)/8, $0x0001020304050607
DATA ·constants<>+200(SB)/8, $0x101010101010101f
#define DOUBLE0 $208
// Insert '1' at load double word
DATA ·constants<>+208(SB)/8, $0x1011121314151617
DATA ·constants<>+216(SB)/8, $0x08090a0b0c0d0e0f
// D1 value in EXPAND
#define D1VALUE $224
DATA ·constants<>+224(SB)/8, $0x0000000000ffffff
DATA ·constants<>+232(SB)/8, $0x0000000000ffffff
#define SHIFT26 $240
// Used for shift of 26
DATA ·constants<>+240(SB)/8, $0x000000000000001a
DATA ·constants<>+248(SB)/8, $0x000000000000001a
#define SHIFT30 $256
// Used for shift of 30
DATA ·constants<>+256(SB)/8, $0x000000000000001e
DATA ·constants<>+264(SB)/8, $0x000000000000001e
#define SHIFT24 $272
// Used for shift of 24
DATA ·constants<>+272(SB)/8, $0x0000000000000018
DATA ·constants<>+280(SB)/8, $0x0000000000000018

// h = (f*g) % (2**130-5) [partial reduction]
#define MULTIPLY(f0, f1, f2, f3, f4, g0, g1, g2, g3, g4, g51, g52, g53, g54, h0, h1, h2, h3, h4) \
	VMULOUW f0, g0, h0     \
	VMULOUW f0, g1, h1     \
	VMULOUW f0, g2, h2     \
	VMULOUW f0, g3, h3     \
	VMULOUW f0, g4, h4     \
	VMULOUW f2, g53, T_0   \
	VADDUDM T_0, h0, h0    \
	VMULOUW f2, g54, T_1   \
	VADDUDM T_1, h1, h1    \
	VMULOUW f2, g0, T_2    \
	VADDUDM T_2, h2, h2    \
	VMULOUW f2, g1, T_3    \
	VADDUDM T_3, h3, h3    \
	VMULOUW f2, g2, T_4    \
	VADDUDM T_4, h4, h4    \
	VMULOUW f4, g51, T_0   \
	VADDUDM T_0, h0, h0    \
	VMULOUW f4, g52, T_1   \
	VADDUDM T_1, h1, h1    \
	VMULOUW f4, g53, T_2   \
	VADDUDM T_2, h2, h2    \
	VMULOUW f4, g54, T_3   \
	VADDUDM T_3, h3, h3    \
	VMULOUW f4, g0, T_4    \
	VADDUDM T_4, h4, h4    \
	VMULOUW f1, g54, T_0   \
	VMULOUW f3, g52, T_1   \
	VADDUDM T_0, T_1, T_0  \
	VMULOUW f1, g0, T_1    \
	VMULOUW f3, g53, T_2   \
	VADDUDM T_1, T_2, T_1  \
	VMULOUW f1, g1, T_2    \
	VMULOUW f3, g54, T_3   \
	VADDUDM T_2, T_3, T_2  \
	VMULOUW f1, g2, T_3    \
	VMULOUW f3, g0, T_4    \
	VADDUDM T_3, T_4, T_3  \
	VMULOUW f1, g3, T_4    \
	VMULOUW f3, g1, TMP0   \
	VADDUDM T_4, TMP0, T_4 \
	VADDUDM T_0, h0, h0    \
	VADDUDM T_1, h1, h1    \
	VADDUDM T_2, h2, h2    \
	VADDUDM T_3, h3, h3    \
	VADDUDM T_4, h4, h4

// carry h0->h1 h3->h4, h1->h2 h4->h0, h0->h1 h2->h3, h3->h4
#define REDUCE(h0, h1, h2, h3, h4) \
	MOVD     SHIFT26, R20            \
	LXVD2X   (CONSTBASE)(R20), TMP1_ \
	VSRD     h0, TMP1, T_0           \
	VSRD     h3, TMP1, T_1           \
	VAND     MOD26, h0, h0           \
	VAND     MOD26, h3, h3           \
	VADDUDM  T_0, h1, h1             \
	VADDUDM  T_1, h4, h4             \
	VSRD     h1, TMP1, T_2           \
	VSRD     h4, TMP1, T_3           \
	VAND     MOD26, h1, h1           \
	VAND     MOD26, h4, h4           \
	VSPLTISW $2, TMP2                \
	VSLD     T_3, TMP2, T_4          \
	VADDUDM  T_3, T_4, T_4           \
	VADDUDM  T_2, h2, h2             \
	VADDUDM  T_4, h0, h0             \
	VSRD     h2, TMP1, T_0           \
	VSRD     h0, TMP1, T_1           \
	VAND     MOD26, h2, h2           \
	VAND     MOD26, h0, h0           \
	VADDUDM  T_0, h3, h3             \
	VADDUDM  T_1, h1, h1             \
	VSRD     h3, TMP1, T_2           \
	VAND     MOD26, h3, h3           \
	VADDUDM  T_2, h4, h4

// expand in0 into d[0] and in1 into d[1]
#define EXPAND(in0, in1, d0, d1, d2, d3, d4, d1_) \
	MOVD     OFFEX0, R20            \
	MOVD     OFFEX1, R21            \
	MOVD     OFFEX2, R22            \
	LXVD2X   (CONSTBASE)(R20), EX0_ \
	LXVD2X   (CONSTBASE)(R21), EX1_ \
	LXVD2X   (CONSTBASE)(R22), EX2_ \
	MOVD     D1VALUE, R20           \
	LXVD2X   (CONSTBASE)(R20), d1_  \
	VPERM    in0, in1, EX2, d4      \
	VPERM    in0, in1, EX0, d0      \
	VPERM    in0, in1, EX1, d2      \
	VAND     d1, d4, d4             \
	MOVD     SHIFT26, R20           \
	LXVD2X   (R20)(CONSTBASE), T_3_ \
	MOVD     SHIFT30, R20           \
	LXVD2X   (R20)(CONSTBASE), T_4_ \
	VSPLTISW $4, T_2                \
	VSRD     d0, T_3, d1            \
	VSRD     d2, T_4, d3            \
	VSRD     d2, T_2, d2            \
	VAND     MOD26, d0, d0          \
	VAND     MOD26, d1, d1          \
	VAND     MOD26, d2, d2          \
	VAND     MOD26, d3, d3

// pack h4:h0 into h1:h0 (no carry)
#define PACK(h0, h1, h2, h3, h4, h1_, h2_, h3_) \
	MOVD     SHIFT26, R20           \
	LXVD2X   (CONSTBASE)(R20), T_0_ \
	VSLD     h1, T_0, h1            \
	VSLD     h3, T_0, h3            \
	VOR      h0, h1, h0             \
	VOR      h2, h3, h2             \
	VSPLTISW $4, T_0                \
	VSLD     h2, T_0, h2            \
	VSLDOI   $6, h2, h2, h2         \
	VOR      h0, h2, h0             \
	VSPLTISW $0, T_0                \
	VSLDOI   $13, h4, T_0, h3       \
	VOR      h3, h0, h0             \
	MOVD     SHIFT24, R20           \
	LXVD2X   (CONSTBASE)(R20), T_0_ \
	VSRO     h4, T_0, h1

// if h > 2**130-5 then h -= 2**130-5
#define MOD(h0, h1, t0, t1, t2, t0_, t2_) \
	MOVD     ONEFIVE, R20          \
	LXVD2X   (CONSTBASE)(R20), t0_ \
	VADDCUQ  h0, t0, t1            \
	VADDUQM  h0, t0, t0            \
	MOVD     MINUS4, R20           \
	LXVD2X   (CONSTBASE)(R20), t2_ \
	VADDUQM  t2, t1, t1            \
	VADDCUQ  h1, t1, t1            \
	VSPLTISB $0xff, t2             \
	VADDUQM  t2, t1, t1            \
	VAND     h0, t1, t2            \
	VANDC    t0, t1, t1            \
	VOR      t1, t2, h0

// func poly1305vx(out *[16]byte, m *byte, mlen uint64, key *[32]key)
TEXT ·poly1305vx(SB), $40-32
	// This code processes up to 2 blocks (32 bytes) per iteration
	// using the algorithm described in:
	// NEON crypto, Daniel J. Bernstein & Peter Schwabe
	// https://cryptojedi.org/papers/neoncrypto-20120320.pdf
	// Do I want to continue to use these registers?
	MOVD out+0(FP), R3
	MOVD m+8(FP), R4
	MOVD mlen+16(FP), R5
	MOVD key+24(FP), R6

	// load MOD26, EX0, EX1 and EX2
	// Constants declared in correct order
	// for use with LXVD2X
	MOVD   $·constants<>(SB), CONSTBASE
	LXVD2X (CONSTBASE), MOD26_

	// setup r
	ANDCC $15, R6, R20
	BNE   unaligned
	LVX   (R6), T_0
	BR    loadkey

unaligned:
	MOVD   SWAPBASE, R20
	LXVD2X (CONSTBASE)(R20), SWAP_
	LXVD2X (R6), T_0_
	VPERM  T_0, T_0, SWAP, T_0

	// Constants are declared in order for use with LXVD2X
loadkey:
	MOVD   $·keyMask<>(SB), R8
	LXVD2X (R8), T_1_
	VAND   T_0, T_1, T_0
	EXPAND(T_0, T_0, R_0, R_1, R_2, R_3, R_4, R_1_)

	// setup r*5
	MOVD   TWOFIVES, R9
	LXVD2X (R7)(R9), T_0_

	// store r (for final block)
	VMULOUW T_0, R_1, R5SAVE_1
	VMULOUW T_0, R_2, R5SAVE_2
	VMULOUW T_0, R_3, R5SAVE_3
	VMULOUW T_0, R_4, R5SAVE_4

	MFVSRD R_0, RSAVE_0
	MFVSRD R_1, RSAVE_1
	MFVSRD R_2, RSAVE_2
	MFVSRD R_3, RSAVE_3
	MFVSRD R_4, RSAVE_4

	// skip r**2 calculation
	CMP R5, $16
	BLE skip

	// calculate r**2
	MULTIPLY(R_0, R_1, R_2, R_3, R_4, R_0, R_1, R_2, R_3, R_4, R5SAVE_1, R5SAVE_2, R5SAVE_3, R5SAVE_4, H_0, H_1, H_2, H_3, H_4)

	// Reload MOD26
	LXVD2X (CONSTBASE), MOD26_
	REDUCE(H_0, H_1, H_2, H_3, H_4)

	// Double fives
	MOVD    TWOFIVES, R8
	LXVD2X  (R8)(CONSTBASE), T_0_
	VMULOUW T_0, H_1, R5_1
	VMULOUW T_0, H_2, R5_2
	VMULOUW T_0, H_3, R5_3
	VMULOUW T_0, H_4, R5_4
	VOR     H_0, H_0, R_0
	VOR     H_1, H_1, R_1
	VOR     H_2, H_2, R_2
	VOR     H_3, H_3, R_3
	VOR     H_4, H_4, R_4

	// initialize h
	VSPLTISW $0, H_0
	VSPLTISW $0, H_1
	VSPLTISW $0, H_2
	VSPLTISW $0, H_3
	VSPLTISW $0, H_4

loop:
	CMP    R5, $32
	BLE    b2
	MOVD   $16, R9
	LXVD2X (R4)(R0), T_0_
	LXVD2X (R4)(R9), T_1_
	MOVD   SWAPBASE, R20
	LXVD2X (CONSTBASE)(R20), T_4_
	VPERM  T_0, T_0, T_4, T_0
	VPERM  T_1, T_1, T_4, T_1
	SUB    $32, R5
	ADD    $32, R4
	MOVD   $32, R20
	EXPAND(T_0, T_1, F_0, F_1, F_2, F_3, F_4, F_1_)

	// Insert 1s at byte 4 and 12
	// As done by VLEIB $4, $1, F_4
	//            VLEIB $12, $1, F_4
	VSPLTISB $1, T_0
	MOVD     BYTES412, R20
	LXVD2X   (CONSTBASE)(R20), T_4_
	VPERM    F_4, T_0, T_4, F_4

multiply:
	VADDUDM H_0, F_0, F_0
	VADDUDM H_1, F_1, F_1
	VADDUDM H_2, F_2, F_2
	VADDUDM H_3, F_3, F_3
	VADDUDM H_4, F_4, F_4
	MULTIPLY(F_0, F_1, F_2, F_3, F_4, R_0, R_1, R_2, R_3, R_4, R5_1, R5_2, R5_3, R5_4, H_0, H_1, H_2, H_3, H_4)
	LXVD2X  (CONSTBASE), MOD26_
	REDUCE(H_0, H_1, H_2, H_3, H_4)
	CMP     $0, R5
	BNE     loop

finish:
	// sum vectors
	VSPLTISB $0, T_0
	VSPLTISB $0xff, T_1
	VSLDOI   $8, T_0, T_1, T_1
	XXPERMDI H_0_, H_0_, $2, T_0_
	VADDUDM  H_0, T_0, H_0
	VAND     H_0, T_1, H_0

	XXPERMDI H_1_, H_1_, $2, T_0_
	VADDUDM  H_1, T_0, H_1
	VAND     H_1, T_1, H_1

	XXPERMDI H_2_, H_2_, $2, T_0_
	VADDUDM  H_2, T_0, H_2
	VAND     H_2, T_1, H_2

	XXPERMDI H_3_, H_3_, $2, T_0_
	VADDUDM  H_3, T_0, H_3
	VAND     H_3, T_1, H_3

	XXPERMDI H_4_, H_4_, $2, T_0_
	VADDUDM  H_4, T_0, H_4
	VAND     H_4, T_1, H_4

	// h may be >= 2*(2**130-5) so we need to reduce it again
	REDUCE(H_0, H_1, H_2, H_3, H_4)

	// carry h1->h4
	MOVD   SHIFT26, R20
	LXVD2X (CONSTBASE)(R20), TMP1_
	VSRD   H_1, TMP1, T_1
	VAND   MOD26, H_1, H_1

	VADDUQM T_1, H_2, H_2
	VSRD    H_2, TMP1, T_2
	VAND    MOD26, H_2, H_2
	VADDUQM T_2, H_3, H_3
	VSRD    H_3, TMP1, T_3
	VAND    MOD26, H_3, H_3
	VADDUQM T_3, H_4, H_4

	// h is now < 2*(2**130-5)
	// pack h into h1 (hi) and h0 (lo)
	PACK(H_0, H_1, H_2, H_3, H_4, H_1_, H_2_, H_3_)

	// if h > 2**130-5 then h -= 2**130-5
	MOD(H_0, H_1, T_0, T_1, T_2, T_0_, T_2_)

	// h += s
	MOVD  out+0(FP), R3
	MOVD  $16, R20
	ANDCC $15, R6, R23
	BNE   unalignedload
	LVX   (R6)(R20), T_0
	BR    next

unalignedload:
	MOVD   SWAPBASE, R21
	LXVD2X (CONSTBASE)(R21), SWAP_
	LXVD2X (R6)(R20), T_0_
	VPERM  T_0, T_0, SWAP, T_0

next:
	VADDUQM T_0, H_0, H_0
	ANDCC   $15, R3, R23
	BNE     unalignedstore
	STVX    H_0, (R3)
	RET

unalignedstore:
	MOVD    SWAPBASE, R21
	LXVD2X  (CONSTBASE)(R21), SWAP_
	VPERM   H_0, H_0, SWAP, H_0
	STXVD2X H_0_, (R3)
	RET

b2:

	// s390x has a vector load with length, but
	// ppc64le does not. This is done by using a load
	// with shifts to get only the bytes to be loaded.
	CMP R5, $16
	BLE b1

	// 2 blocks remaining

	MOVD $16, R21

	// Keep it simple, use LXVD2X to avoid checking
	// alignment then VPERM to put bytes in the
	// right order.
	MOVD   SWAPBASE, R22
	LXVD2X (CONSTBASE)(R22), SWAP_
	LXVD2X (R4)(R0), T_0_
	LXVD2X (R4)(R21), T_1_
	VPERM  T_0, T_0, SWAP, T_0
	VPERM  T_1, T_1, SWAP, T_1

	CMP R5, $32
	BEQ expand

	// At this point, less than 32, more than 16 bytes.
	// Put '1' at end of bytes
	MOVD   $1, R21
	MTVSRD R21, T_2
	VSLDOI $8, T_2, T_2, T_2

	// Determine how many bytes to shift out
	MOVD $32, R21
	SUB  R5, R21

	// Shift uses bytes, convert from bits to bytes
	SLD    $3, R21
	MTVSRD R21, T_3_
	VSLDOI $8, T_3, T_3, T_3
	VSLO   T_1, T_3, T_1
	VSLDOI $15, T_2, T_1, T_1
	ADD    $-8, R21
	MTVSRD R21, T_3_
	VSLDOI $8, T_3, T_3, T_3
	VSRO   T_1, T_3, T_1

expand:
	ADD      $-16, R5
	EXPAND(T_0, T_1, F_0, F_1, F_2, F_3, F_4, F_1_)
	VSPLTISB $1, T_0
	MOVD     BYTE4, R21
	CMP      R5, $16
	BNE      2(PC)

	// VPERM string to put '1' into bytes 4 and 12
	MOVD   BYTES412, R21          // vperm string
	LXVD2X (CONSTBASE)(R21), T_1_

	VPERM F_4, T_0, T_1, F_4

	// Constant used to get high doubleword
	MOVD   HIGHDW, R25
	LXVD2X (CONSTBASE)(R25), TMP0_

	MTVSRD   RSAVE_0, T_0
	VPERM    R_0, T_0, TMP0, R_0
	MTVSRD   RSAVE_1, T_1
	VPERM    R_1, T_1, TMP0, R_1
	MTVSRD   RSAVE_2, T_2
	VPERM    R_2, T_2, TMP0, R_2
	MTVSRD   RSAVE_3, T_3
	VPERM    R_3, T_3, TMP0, R_3
	MTVSRD   RSAVE_4, T_4
	VPERM    R_4, T_4, TMP0, R_4
	XXPERMDI R5_1_, R5SAVE_1_, $0, R5_1_
	XXPERMDI R5_2_, R5SAVE_2_, $0, R5_2_
	XXPERMDI R5_3_, R5SAVE_3_, $0, R5_3_
	XXPERMDI R5_4_, R5SAVE_4_, $0, R5_4_

	MOVD $0, R5
	BR   multiply

skip:
	VSPLTISW $0, H_0
	VSPLTISW $0, H_1
	VSPLTISW $0, H_2
	VSPLTISW $0, H_3
	VSPLTISW $0, H_4

	CMP $0, R5
	BEQ finish

b1:
	// 1 block remaining: <= 16
	CMP R5, $16

	// Implementation for s390x VLL (vector load length)
	MOVD   SWAPBASE, R20
	LXVD2X (CONSTBASE)(R20), SWAP_
	LXVD2X (R4), T_0_
	VPERM  T_0, T_0, SWAP, T_0

	BEQ next1

	// load if < 16 bytes remaining
	// Determine bytes to shift
	MOVD     $16, R21
	SUB      R5, R21
	SLD      $3, R21
	VSPLTISW $1, T_2
	MTVSRD   R21, T_1

	// Set up shift count
	VSLDOI $8, T_1, T_1, T_1
	VSLO   T_0, T_1, T_0
	VSLDOI $15, T_2, T_0, T_0
	ADD    $-8, R21
	MTVSRD R21, T_3
	VSLDOI $8, T_3, T_3, T_3
	VSRO   T_0, T_3, T_0

next1:
	VSPLTISW $0, T_1
	EXPAND(T_0, T_1, F_0, F_1, F_2, F_3, F_4, F_1_)
	CMP      R5, $16
	VSPLTISW $1, T_1
	MOVD     BYTE4, R20
	LXVD2X   (CONSTBASE)(R20), T_4_
	BNE      2(PC)
	VPERM    F_4, T_1, T_4, F_4
	MOVD     DOUBLE1, R20
	LXVD2X   (CONSTBASE)(R20), T_4_
	VPERM    R_0, T_1, T_4, R_0
	VSPLTISW $0, R_1
	VSPLTISW $0, R_2
	VSPLTISW $0, R_3
	VSPLTISW $0, R_4
	VSPLTISW $0, R5_1
	VSPLTISW $0, R5_2
	VSPLTISW $0, R5_3
	VSPLTISW $0, R5_4

	// setup [r, 1]
	MTVSRD RSAVE_0, T_0
	MTVSRD RSAVE_1, T_1
	MTVSRD RSAVE_2, T_2
	MTVSRD RSAVE_3, T_3
	MTVSRD RSAVE_4, T_4

	// Using VPERM to get the lower doubleword from the T_* regs
	// and put them into the upper doubleword for R_* regs.
	MOVD   DOUBLE0, R20
	LXVD2X (CONSTBASE)(R20), TMP0_
	VPERM  R_0, T_0, TMP0, R_0
	VPERM  R_1, T_1, TMP0, R_1
	VPERM  R_2, T_2, TMP0, R_2
	VPERM  R_3, T_3, TMP0, R_3
	VPERM  R_4, T_4, TMP0, R_4

	XXPERMDI R5SAVE_1_, R5_1_, $0, R5_1_
	XXPERMDI R5SAVE_2_, R5_2_, $0, R5_2_
	XXPERMDI R5SAVE_3_, R5_3_, $0, R5_3_
	XXPERMDI R5SAVE_4_, R5_4_, $0, R5_4_

	MOVD $0, R5
	BR   multiply
