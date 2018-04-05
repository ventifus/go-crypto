// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Based on CRYPTOGAMS code with the following comment:
// # ====================================================================
// # Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
// # project. The module is, however, dual licensed under OpenSSL and
// # CRYPTOGAMS licenses depending on where you obtain it. For further
// # details see http://www.openssl.org/~appro/cryptogams/.
// # ====================================================================

// Original code can be found at the link below:
// git://git.openssl.org/openssl.git/crypto/chacha/asm/chacha-ppc.pl

// There are some differences between OpenSSL code and this one. The round
// loop for "_int" isn't the same as the original. Some adjustments were
// necessary because there are less vectors available.  For example, some
// X variables (r12, r13, r14, and r15) share the same register used by the
// counter. The original code uses ctr to name the counter. Here we use CNT
// because golang uses CTR as the counter register name.

// +build ppc64le,!gccgo,!appengine

#include "textflag.h"

#define OUT  R3
#define INP  R4
#define LEN  R5
#define KEY  R6
#define CNT  R7

#define TEMP R8

#define X0   R11
#define X1   R12
#define X2   R14
#define X3   R15
#define X4   R16
#define X5   R17
#define X6   R18
#define X7   R19
#define X8   R20
#define X9   R21
#define X10  R22
#define X11  R23
#define X12  R24
#define X13  R25
#define X14  R26
#define X15  R27

#define CON0 X0
#define CON1 X1
#define CON2 X2
#define CON3 X3

#define KEY0 X4
#define KEY1 X5
#define KEY2 X6
#define KEY3 X7
#define KEY4 X8
#define KEY5 X9
#define KEY6 X10
#define KEY7 X11

#define CNT0 X12
#define CNT1 X13
#define CNT2 X14
#define CNT3 X15

#define TMP0 R9
#define TMP1 R10
#define TMP2 R28
#define TMP3 R29

#define CONSTS  R8

#define A0      V0
#define B0      V1
#define C0      V2
#define D0      V3
#define A1      V4
#define B1      V5
#define C1      V6
#define D1      V7
#define A2      V8
#define B2      V9
#define C2      V10
#define D2      V11
#define T0      V12
#define T1      V13
#define T2      V14

#define K0      V15
#define K1      V16
#define K2      V17
#define K3      V18
#define K4      V19
#define K5      V20

#define FOUR    V21
#define SIXTEEN V22
#define TWENTY4 V23
#define TWENTY  V24
#define TWELVE  V25
#define TWENTY5 V26
#define SEVEN   V27

#define INPPERM V28
#define OUTPERM V29
#define OUTMASK V30

#define DD0     V31
#define DD1     SEVEN
#define DD2     T0
#define DD3     T1
#define DD4     T2

DATA  ·consts+0x00(SB)/8, $0x3320646e61707865
DATA  ·consts+0x08(SB)/8, $0x6b20657479622d32
DATA  ·consts+0x10(SB)/8, $0x0000000000000001
DATA  ·consts+0x18(SB)/8, $0x0000000000000000
DATA  ·consts+0x20(SB)/8, $0x0000000000000004
DATA  ·consts+0x28(SB)/8, $0x0000000000000000
DATA  ·consts+0x30(SB)/8, $0x0a0b08090e0f0c0d
DATA  ·consts+0x38(SB)/8, $0x0203000106070405
DATA  ·consts+0x40(SB)/8, $0x090a0b080d0e0f0c
DATA  ·consts+0x48(SB)/8, $0x0102030005060704
GLOBL ·consts(SB), RODATA, $80

//func ChaCha20_ctr32_vmx(out, inp []byte, len int, key *[32]byte, counter *[16]byte)
TEXT ·ChaCha20_ctr32_vmx(SB),NOSPLIT|NOFRAME,$0
	// Load the arguments inside the registers
	MOVD out+0(FP), OUT
	MOVD inp+8(FP), INP
	MOVD len+16(FP), LEN
	MOVD key+24(FP), KEY
	MOVD cnt+32(FP), CNT

	MOVD $·consts(SB), CONSTS // point to consts addr

	MOVD $16, X0
	MOVD $32, X1
	MOVD $48, X2
	MOVD $64, X3
	MOVD $31, X4
	MOVD $15, X5

	// Load key
	LVX  (KEY)(R0), K1
	LVSR (KEY)(R0), T0
	LVX  (KEY)(X0), K2
	LVX  (KEY)(X4), DD0

	// Load counter
	LVX  (CNT)(R0), K3
	LVSR (CNT)(R0), T1
	LVX  (CNT)(X5), DD1

	// Load constants
	LVX (CONSTS)(R0), K0
	LVX (CONSTS)(X0), K5
	LVX (CONSTS)(X1), FOUR
	LVX (CONSTS)(X2), SIXTEEN
	LVX (CONSTS)(X3), TWENTY4

	// Align key and counter
	VPERM K2,  K1, T0, K1
	VPERM DD0, K2, T0, K2
	VPERM DD1, K3, T1, K3

	// Load counter to GPR
	MOVWZ 0(CNT), CNT0
	MOVWZ 4(CNT), CNT1
	VADDUWM K3, K5, K3
	MOVWZ 8(CNT), CNT2
	VADDUWM K3, K5, K4
	MOVWZ 12(CNT), CNT3
	VADDUWM K4, K5, K5

	// Synthesized constants
	VSPLTISW $-12, TWENTY
	VSPLTISW $12, TWELVE
	VSPLTISW $-7, TWENTY5

	VXOR T0, T0, T0
	VSPLTISW $-1, OUTMASK
	LVSR (INP)(R0), INPPERM
	LVSL (OUT)(R0), OUTPERM
	VPERM OUTMASK, T0, OUTPERM, OUTMASK

loop_outer_vmx:
	// Load constant
	MOVD $0x61707865, CON0
	MOVD $0x3320646e, CON1
	MOVD $0x79622d32, CON2
	MOVD $0x6b206574, CON3

	VOR K0, K0, A0
	VOR K0, K0, A1
	VOR K0, K0, A2
	VOR K1, K1, B0

	MOVD $10, TEMP

	// Load key to GPR
	MOVWZ 0(KEY), X4
	VOR K1, K1, B1
	MOVWZ 4(KEY), X5
	VOR K1, K1, B2
	MOVWZ 8(KEY), X6
	VOR K2, K2, C0
	MOVWZ 12(KEY), X7
	VOR K2, K2, C1
	MOVWZ 16(KEY), X8
	VOR K2, K2, C2
	MOVWZ  0(CNT), X12
	MOVWZ 20(KEY), X9
	VOR K3, K3, D0
	MOVWZ  4(CNT), TMP1
	MOVD TMP1, X13
	MOVWZ 24(KEY), X10
	VOR K4, K4, D1
	MOVWZ  8(CNT), TMP1
	MOVD TMP1, X14
	MOVWZ 28(KEY), X11
	VOR K5, K5, D2
	MOVWZ 12(CNT), TMP1
	MOVD TMP1, X15

	MOVD X4, TMP0
	MOVD X5, TMP1
	MOVD X6, TMP2
	MOVD X7, TMP3
	VSPLTISW $7, SEVEN

	MOVD TEMP, CTR

loop_vmx:
	// OpenSSL uses a macro to create a loop using perl. This isn't possible
	// using assembly macros.  Therefore, the macro expansion result was used
	// in order to maintain the algorithm efficiency.
	VADDUWM A0, B0, A0
	ADD X4, X0, X0
	VADDUWM A1, B1, A1
	ADD X5, X1, X1
	VADDUWM A2, B2, A2
	ADD X6, X2, X2
	VXOR D0, A0, D0
	ADD X7, X3, X3
	VXOR D1, A1, D1
	XOR X0, X12, X12
	VXOR D2, A2, D2
	XOR X1, X13, X13
	VPERM D0, D0, SIXTEEN, D0
	XOR X2, X14, X14
	VPERM D1, D1, SIXTEEN, D1
	XOR X3, X15, X15
	VPERM D2, D2, SIXTEEN, D2
	ROTLW $16, X12, X12
	VADDUWM C0, D0, C0
	ROTLW $16, X13, X13
	VADDUWM C1, D1, C1
	ROTLW $16, X14, X14
	VADDUWM C2, D2, C2
	ROTLW $16, X15, X15
	VXOR B0, C0, T0
	ADD X12, X8, X8
	VXOR B1, C1, T1
	ADD X13, X9, X9
	VXOR B2, C2, T2
	ADD X14, X10, X10
	ADD X15, X11, X11
	XOR X8, X4, X4
	XOR X9, X5, X5
	XOR X10, X6, X6
	XOR X11, X7, X7
	ROTLW $12, X4, X4
	VRLW T0, TWELVE, B0
	ROTLW $12, X5, X5
	VRLW T1, TWELVE, B1
	ROTLW $12, X6, X6
	VRLW T2, TWELVE, B2
	ROTLW $12, X7, X7
	VADDUWM A0, B0, A0
	ADD X4, X0, X0
	VADDUWM A1, B1, A1
	ADD X5, X1, X1
	VADDUWM A2, B2, A2
	ADD X6, X2, X2
	VXOR D0, A0, D0
	ADD X7, X3, X3
	VXOR D1, A1, D1
	XOR X0, X12, X12
	VXOR D2, A2, D2
	XOR X1, X13, X13
	VPERM D0, D0, TWENTY4, D0
	XOR X2, X14, X14
	VPERM D1, D1, TWENTY4, D1
	XOR X3, X15, X15
	VPERM D2, D2, TWENTY4, D2
	ROTLW $8, X12, X12
	VADDUWM C0, D0, C0
	ROTLW $8, X13, X13
	VADDUWM C1, D1, C1
	ROTLW $8, X14, X14
	VADDUWM C2, D2, C2
	ROTLW $8, X15, X15
	VXOR B0, C0, T0
	ADD X12, X8, X8
	VXOR B1, C1, T1
	ADD X13, X9, X9
	VXOR B2, C2, T2
	ADD X14, X10, X10
	ADD X15, X11, X11
	XOR X8, X4, X4
	XOR X9, X5, X5
	XOR X10, X6, X6
	XOR X11, X7, X7
	ROTLW $7, X4, X4
	VRLW T0, SEVEN, B0
	ROTLW $7, X5, X5
	VRLW T1, SEVEN, B1
	ROTLW $7, X6, X6
	VRLW T2, SEVEN, B2
	ROTLW $7, X7, X7
	VSLDOI $8, C0, C0, C0
	VSLDOI $8, C1, C1, C1
	VSLDOI $8, C2, C2, C2
	VSLDOI $12, B0, B0, B0
	VSLDOI $12, B1, B1, B1
	VSLDOI $12, B2, B2, B2
	VSLDOI $4, D0, D0, D0
	VSLDOI $4, D1, D1, D1
	VSLDOI $4, D2, D2, D2
	VADDUWM A0, B0, A0
	ADD X5, X0, X0
	VADDUWM A1, B1, A1
	ADD X6, X1, X1
	VADDUWM A2, B2, A2
	ADD X7, X2, X2
	VXOR D0, A0, D0
	ADD X4, X3, X3
	VXOR D1, A1, D1
	XOR X0, X15, X15
	VXOR D2, A2, D2
	XOR X1, X12, X12
	VPERM D0, D0, SIXTEEN, D0
	XOR X2, X13, X13
	VPERM D1, D1, SIXTEEN, D1
	XOR X3, X14, X14
	VPERM D2, D2, SIXTEEN, D2
	ROTLW $16, X15, X15
	VADDUWM C0, D0, C0
	ROTLW $16, X12, X12
	VADDUWM C1, D1, C1
	ROTLW $16, X13, X13
	VADDUWM C2, D2, C2
	ROTLW $16, X14, X14
	VXOR B0, C0, T0
	ADD X15, X10, X10
	VXOR B1, C1, T1
	ADD X12, X11, X11
	VXOR B2, C2, T2
	ADD X13, X8, X8
	ADD X14, X9, X9
	XOR X10, X5, X5
	XOR X11, X6, X6
	XOR X8, X7, X7
	XOR X9, X4, X4
	ROTLW $12, X5, X5
	VRLW T0, TWELVE, B0
	ROTLW $12, X6, X6
	VRLW T1, TWELVE, B1
	ROTLW $12, X7, X7
	VRLW T2, TWELVE, B2
	ROTLW $12, X4, X4
	VADDUWM A0, B0, A0
	ADD X5, X0, X0
	VADDUWM A1, B1, A1
	ADD X6, X1, X1
	VADDUWM A2, B2, A2
	ADD X7, X2, X2
	VXOR D0, A0, D0
	ADD X4, X3, X3
	VXOR D1, A1, D1
	XOR X0, X15, X15
	VXOR D2, A2, D2
	XOR X1, X12, X12
	VPERM D0, D0, TWENTY4, D0
	XOR X2, X13, X13
	VPERM D1, D1, TWENTY4, D1
	XOR X3, X14, X14
	VPERM D2, D2, TWENTY4, D2
	ROTLW $8, X15, X15
	VADDUWM C0, D0, C0
	ROTLW $8, X12, X12
	VADDUWM C1, D1, C1
	ROTLW $8, X13, X13
	VADDUWM C2, D2, C2
	ROTLW $8, X14, X14
	VXOR B0, C0, T0
	ADD X15, X10, X10
	VXOR B1, C1, T1
	ADD X12, X11, X11
	VXOR B2, C2, T2
	ADD X13, X8, X8
	ADD X14, X9, X9
	XOR X10, X5, X5
	XOR X11, X6, X6
	XOR X8, X7, X7
	XOR X9, X4, X4
	ROTLW $7, X5, X5
	VRLW T0, SEVEN, B0
	ROTLW $7, X6, X6
	VRLW T1, SEVEN, B1
	ROTLW $7, X7, X7
	VRLW T2, SEVEN, B2
	ROTLW $7, X4, X4
	VSLDOI $8, C0, C0, C0
	VSLDOI $8, C1, C1, C1
	VSLDOI $8, C2, C2, C2
	VSLDOI $4, B0, B0, B0
	VSLDOI $4, B1, B1, B1
	VSLDOI $4, B2, B2, B2
	VSLDOI $12, D0, D0, D0
	VSLDOI $12, D1, D1, D1
	VSLDOI $12, D2, D2, D2
	BC 0x10, 0, loop_vmx

	SUB $256, LEN, LEN

	// Accumulate
	ADD $0x61707865, X0, X0
	ADD $0x3320646e, X1, X1
	ADD $0x79622d32, X2, X2
	ADD $0x6b206574, X3, X3
	ADD TMP0, X4, X4
	MOVWZ 16(KEY), TMP0
	ADD TMP1, X5, X5
	MOVWZ 20(KEY), TMP1
	ADD TMP2, X6, X6
	MOVWZ 24(KEY), TMP2
	ADD TMP3, X7, X7
	MOVWZ 28(KEY), TMP3
	ADD TMP0, X8, X8
	ADD TMP1, X9, X9
	ADD TMP2, X10, X10
	ADD TMP3, X11, X11

	MOVWZ 12(CNT), TEMP
	ADD TEMP, X15, X15
	MOVWZ 8(CNT), TEMP
	ADD TEMP, X14, X14
	MOVWZ 4(CNT), TEMP
	ADD TEMP, X13, X13
	MOVWZ 0(CNT), TEMP
	ADD TEMP, X12, X12

	// Accumulate key block
	VADDUWM A0, K0, A0
	VADDUWM A1, K0, A1
	VADDUWM A2, K0, A2
	VADDUWM B0, K1, B0
	VADDUWM B1, K1, B1
	VADDUWM B2, K1, B2
	VADDUWM C0, K2, C0
	VADDUWM C1, K2, C1
	VADDUWM C2, K2, C2
	VADDUWM D0, K3, D0
	VADDUWM D1, K4, D1
	VADDUWM D2, K5, D2

	// Increment counter
	ADD $4, TEMP, TEMP
	MOVW TEMP, 0(CNT)

	VADDUWM K3, FOUR, K3
	VADDUWM K4, FOUR, K4
	VADDUWM K5, FOUR, K5

	// Load input (aligned or not)
	MOVWZ 0(INP), TMP0
	MOVWZ 4(INP), TMP1
	MOVWZ 8(INP), TMP2
	MOVWZ 12(INP), TMP3 // XOR with input
	XOR TMP0, X0, X0
	XOR TMP1, X1, X1
	XOR TMP2, X2, X2
	XOR TMP3, X3, X3
	MOVWZ 16(INP), TMP0
	MOVWZ 20(INP), TMP1
	MOVWZ 24(INP), TMP2
	MOVWZ 28(INP), TMP3
	XOR TMP0, X4, X4
	XOR TMP1, X5, X5
	XOR TMP2, X6, X6
	XOR TMP3, X7, X7
	MOVWZ 32(INP), TMP0
	MOVWZ 36(INP), TMP1
	MOVWZ 40(INP), TMP2
	MOVWZ 44(INP), TMP3
	XOR TMP0, X8, X8
	XOR TMP1, X9, X9
	XOR TMP2, X10, X10
	XOR TMP3, X11, X11
	MOVWZ 48(INP), TMP0
	MOVWZ 52(INP), TMP1
	MOVWZ 56(INP), TMP2
	MOVWZ 60(INP), TMP3
	XOR TMP0, X12, X12
	XOR TMP1, X13, X13
	XOR TMP2, X14, X14
	XOR TMP3, X15, X15
	MOVW X0, 0(OUT) // Store output (aligned or not)
	MOVW X1, 4(OUT)
	MOVW X2, 8(OUT)
	MOVW X3, 12(OUT)
	ADD $64, INP, INP
	MOVW X4, 16(OUT)
	MOVD $16, TMP0
	MOVW X5, 20(OUT)
	MOVD $32, TMP1
	MOVW X6, 24(OUT)
	MOVD $48, TMP2
	MOVW X7, 28(OUT)
	MOVD $64, TMP3
	MOVW X8, 32(OUT)
	MOVW X9, 36(OUT)
	MOVW X10, 40(OUT)
	MOVW X11, 44(OUT)
	MOVW X12, 48(OUT)
	MOVW X13, 52(OUT)
	MOVW X14, 56(OUT)
	MOVW X15, 60(OUT)
	ADD $64, OUT, OUT

	// Load input
	LVX (INP)(R0), DD0
	LVX (INP)(TMP0), DD1
	LVX (INP)(TMP1), DD2
	LVX (INP)(TMP2), DD3
	LVX (INP)(TMP3), DD4
	ADD $64, INP, INP

	VPERM DD1, DD0, INPPERM, DD0 // Align input
	VPERM DD2, DD1, INPPERM, DD1
	VPERM DD3, DD2, INPPERM, DD2
	VPERM DD4, DD3, INPPERM, DD3
	VXOR A0, DD0, A0 // XOR with input
	VXOR B0, DD1, B0
	LVX (INP)(TMP0), DD1 // Keep loading input
	VXOR C0, DD2, C0
	LVX (INP)(TMP1), DD2
	VXOR D0, DD3, D0
	LVX (INP)(TMP2), DD3
	LVX (INP)(TMP3), DD0
	ADD $64, INP, INP
	MOVD $63, TMP3 // 63 is not a typo
	VPERM A0, A0, OUTPERM, A0
	VPERM B0, B0, OUTPERM, B0
	VPERM C0, C0, OUTPERM, C0
	VPERM D0, D0, OUTPERM, D0

	VPERM DD1, DD4, INPPERM, DD4 // Align input
	VPERM DD2, DD1, INPPERM, DD1
	VPERM DD3, DD2, INPPERM, DD2
	VPERM DD0, DD3, INPPERM, DD3
	VXOR A1, DD4, A1
	VXOR B1, DD1, B1
	LVX (INP)(TMP0), DD1 // Keep loading
	VXOR C1, DD2, C1
	LVX (INP)(TMP1), DD2
	VXOR D1, DD3, D1
	LVX (INP)(TMP2), DD3
	LVX (INP)(TMP3), DD4 // Redundant in aligned case
	ADD $64, INP, INP
	VPERM A1, A1, OUTPERM, A1 // Pre-misalign output
	VPERM B1, B1, OUTPERM, B1
	VPERM C1, C1, OUTPERM, C1
	VPERM D1, D1, OUTPERM, D1

	VPERM DD1, DD0, INPPERM, DD0 // Align Input
	VPERM DD2, DD1, INPPERM, DD1
	VPERM DD3, DD2, INPPERM, DD2
	VPERM DD4, DD3, INPPERM, DD3
	VXOR A2, DD0, A2
	VXOR B2, DD1, B2
	VXOR C2, DD2, C2
	VXOR D2, DD3, D2
	VPERM A2, A2, OUTPERM, A2
	VPERM B2, B2, OUTPERM, B2
	VPERM C2, C2, OUTPERM, C2
	VPERM D2, D2, OUTPERM, D2

	ANDCC $15, OUT, X1 // Is out aligned?
	MOVD OUT, X0

	VSEL A0, B0, OUTMASK, DD0 // Collect pre-misaligned output
	VSEL B0, C0, OUTMASK, DD1
	VSEL C0, D0, OUTMASK, DD2
	VSEL D0, A1, OUTMASK, DD3
	VSEL A1, B1, OUTMASK, B0
	VSEL B1, C1, OUTMASK, C0
	VSEL C1, D1, OUTMASK, D0
	VSEL D1, A2, OUTMASK, A1
	VSEL A2, B2, OUTMASK, B1
	VSEL B2, C2, OUTMASK, C1
	VSEL C2, D2, OUTMASK, D1

	STVX DD0, (OUT+TMP0)
	STVX DD1, (OUT+TMP1)
	STVX DD2, (OUT+TMP2)
	ADD $64, OUT, OUT
	STVX DD3, (OUT+R0)
	STVX B0, (OUT+TMP0)
	STVX C0, (OUT+TMP1)
	STVX D0, (OUT+TMP2)
	ADD $64, OUT, OUT
	STVX A1, (OUT+R0)
	STVX B1, (OUT+TMP0)
	STVX C1, (OUT+TMP1)
	STVX D1, (OUT+TMP2)
	ADD $64, OUT, OUT

	BEQ aligned_vmx

	SUB X1, OUT, X2 // in misaligned case edges
	MOVD $0, X3 // are written byte-by-byte

unaligned_tail_vmx:
	STVEBX D2, (X2+X3)
	ADD $1, X3, X3
	CMPW X3, X1
	BNE unaligned_tail_vmx
	SUB X1, X0, X2

unaligned_head_vmx:
	STVEBX A0, (X2+X1)
	CMPW X1, $15
	ADD $1, X1, X1
	BNE unaligned_head_vmx

	CMPU LEN, $255 // done with 256-byte block yet?
	BGT loop_outer_vmx

	JMP done_vmx

aligned_vmx:
	STVX A0, (X0+R0)
	CMPU LEN, $255 // done with 256-byte block yet?
	BGT loop_outer_vmx

done_vmx:
	RET
