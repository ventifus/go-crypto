// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build arm64,!gccgo,!appengine,!nacl

#include "textflag.h"

// This code was based on the 64bit implementation from the MIT or public
// domain source by Andrew Moon: github.com/floodyberry/poly1305-donna.

// func Sum(out *[16]byte, msg []byte, key *[32]byte)
TEXT ·Sum(SB), NOSPLIT, $0
	// the hash accumulators, initialized to zero.
	MOVD	ZR, R22
	MOVD	ZR, R23
	MOVD	ZR, R24
	MOVD	key+32(FP), R0
	MOVD	(R0), R1
	// initialize the r part of the key.
	AND	$0xffc0fffffff, R1, R19
	MOVD	8(R0), R3
	EXTR	$44, R1, R3, R1
	AND	$0xfffffc0ffff, R1, R20
	LSR	$24, R3, R1
	AND	$0x00ffffffc0f, R1, R21
	ADD	R20<<2, R20, R2
	LSL	$2, R2, R2
	ADD	R21<<2, R21, R1
	LSL	$2, R1, R1
	MOVD	msg+8(FP), R3
	MOVD	msg+16(FP), R4
	MOVD	msg+24(FP), R5
	JMP	main_loop_entry
process_blocks:
	// h += msg
	LSL	$20, R7, R8
	ADD	R8>>20, R22, R22
	MOVD	8(R3), R8
	EXTR	$44, R7, R8, R7
	LSL	$20, R7, R7
	ADD	R7>>20, R23, R23
	LSR	$24, R8, R7
	ORR	$0x10000000000, R7, R7
	ADD	R24, R7, R24
	// h *= r
	UMULH	R22, R19, R16
	MUL	R22, R19, R17
	UMULH	R1, R23, R9
	MUL	R1, R23, R8
	ADDS	R8, R17, R17
	ADC	R9, R16, R16
	UMULH	R2, R24, R9
	MUL	R2, R24, R8
	ADDS	R8, R17, R17
	ADC	R9, R16, R16
	UMULH	R22, R20, R14
	MUL	R22, R20, R15
	UMULH	R23, R19, R8
	MUL	R23, R19, R9
	ADDS	R9, R15, R15
	ADC	R8, R14, R14
	UMULH	R1, R24, R9
	MUL	R1, R24, R8
	ADDS	R8, R15, R15
	ADC	R9, R14, R14
	UMULH	R22, R21, R12
	MUL	R22, R21, R13
	UMULH	R20, R23, R8
	MUL	R20, R23, R9
	ADDS	R9, R13, R13
	ADC	R8, R12, R12
	UMULH	R24, R19, R8
	MUL	R24, R19, R9
	ADDS	R9, R13, R13
	ADC	R8, R12, R12
	// h %= p
	AND	$0xfffffffffff, R17, R22
	EXTR	$44, R17, R16, R8
	ADDS	R15, R8, R15
	CINC	HS, R14, R14
	AND	$0xfffffffffff, R15, R23
	EXTR	$44, R15, R14, R14
	ADDS	R13, R14, R13
	CINC	HS, R12, R12
	AND	$0x3ffffffffff, R13, R24
	EXTR	$42, R13, R12, R7
	ADD	R7<<2, R7, R7
	ADD	R7, R22, R22
	ADD	R22>>44, R23, R23
	AND	$0xfffffffffff, R22, R22
	SUB	$16, R5, R5
	NEG	R5, R6
	ASR	$63, R6, R6
	AND	$16, R6, R6
	ADD	R6, R3, R3
	SUB	$16, R4, R4
main_loop_entry:
	CMP	$16, R4
	BLT	leftover_blocks
	SUB	$8, R4, R6
	MOVD	(R3), R7
	CMP	$7, R6
	BHI	process_blocks
leftover_blocks:
	CBZ	R4, finish
	MOVD	R2, s1-144(SP)
	MOVD	R1, s2-152(SP)
	STP	(ZR, ZR), block-128(SP)
	MOVD	R4, off-136(SP)
	MOVD	R5, 8(RSP)
	MOVD	R3, 16(RSP)
	MOVD	R4, 24(RSP)
	CALL	runtime·memmove(SB)
	MOVD	off-136(SP), R0
	// process the remaining block.
	MOVD	$block-128(SP), R1
	ADD	R0, R1, R0
	MOVD	$1, R1
	MOVB	R1, (R0)
	MOVD	block-128(SP), R1
	LSL	$20, R1, R2
	ADD	R2>>20, R22, R22
	MOVD	block-120(SP), R2
	EXTR	$44, R1, R2, R1
	LSL	$20, R1, R1
	ADD	R1>>20, R23, R23
	ADD	R2>>24, R24, R24
	// h *= r
	UMULH	R22, R19, R16
	MUL	R22, R19, R17
	MOVD	s2-152(SP), R1
	UMULH	R1, R23, R4
	MUL	R1, R23, R3
	ADDS	R3, R17, R17
	ADC	R4, R16, R16
	MOVD	s1-144(SP), R2
	UMULH	R2, R24, R3
	MUL	R2, R24, R4
	ADDS	R4, R17, R17
	ADC	R3, R16, R16
	UMULH	R22, R20, R14
	MUL	R22, R20, R15
	UMULH	R23, R19, R3
	MUL	R23, R19, R4
	ADDS	R4, R15, R15
	ADC	R3, R14, R14
	UMULH	R1, R24, R2
	MUL	R1, R24, R3
	ADDS	R3, R15, R15
	ADC	R2, R14, R14
	UMULH	R22, R21, R12
	MUL	R22, R21, R13
	UMULH	R23, R20, R2
	MUL	R23, R20, R3
	ADDS	R3, R13, R13
	ADC	R2, R12, R12
	UMULH	R24, R19, R2
	MUL	R24, R19, R3
	ADDS	R3, R13, R13
	ADC	R2, R12, R12
	// h %= p
	AND	$0xfffffffffff, R17, R22
	EXTR	$44, R17, R16, R2
	ADDS	R15, R2, R15
	CINC	HS, R14, R14
	AND	$0xfffffffffff, R15, R23
	EXTR	$44, R15, R14, R14
	ADDS	R13, R14, R13
	CINC	HS, R12, R12
	AND	$0x3ffffffffff, R13, R24
	EXTR	$42, R13, R12, R1
	ADD	R1<<2, R1, R1
	ADD	R1, R22, R22
	ADD	R22>>44, R23, R23
	AND	$0xfffffffffff, R22, R22
finish:
	// h %= p reduction
	ADD	R23>>44, R24, R24
	AND	$0xfffffffffff, R23, R23
	LSR	$42, R24, R1
	ADD	R1<<2, R1, R1
	ADD	R22, R1, R22
	AND	$0x3ffffffffff, R24, R24
	ADD	R22>>44, R23, R23
	AND	$0xfffffffffff, R22, R22
	// h - p
	ADD	$5, R22, R1
	ADD	R1>>44, R23, R2
	ADD	R2>>44, R24, R3
	SUB	$0x3ffffffffff, R3, R3
	// select h if h < p else h - p
	LSL	$20, R1, R1
	LSR	$63, R3, R4
	SUB	$1, R4, R4
	BIC	R4, R22, R0
	AND	R1>>20, R4, R1
	ORR	R1, R0, R22
	LSL	$20, R2, R0
	BIC	R4, R23, R1
	AND	R0>>20, R4, R0
	ORR	R0, R1, R23
	BIC	R4, R24, R0
	AND	R3, R4, R1
	ORR	R0, R1, R24
	// pad: the pad part of the key
	// tag = (h + pad)
	MOVD	key+32(FP), R1
	MOVD	16(R1), R2
	LSL	$20, R2, R3
	ADD	R3>>20, R22, R22
	MOVD	24(R1), R1
	EXTR	$44, R2, R1, R2
	LSL	$20, R2, R2
	LSR	$44, R22, R0
	ADD	R2>>20, R0, R0
	ADD	R23, R0, R23
	LSR	$44, R23, R0
	ADD	R1>>24, R0, R0
	ADD	R24, R0, R24
	AND	$0xfffffffffff, R22, R22
	AND	$0xfffffffffff, R23, R23
	AND	$0x3ffffffffff, R24, R24
	// h %= 2^128
	ORR	R23<<44, R22, R22
	LSR	$20, R23, R0
	ORR	R24<<24, R0, R23
	MOVD	out(FP), R1
	MOVD	R22, (R1)
	MOVD	R23, 8(R1)
	RET
