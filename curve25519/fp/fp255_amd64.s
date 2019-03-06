// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!gccgo,!appengine

#include "textflag.h"
#include "fp255_amd64.h"

// func (field) Modp(z *Elt)
TEXT ·field·Modp(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI

    MOVQ   (DI),  R8
    MOVQ  8(DI),  R9
    MOVQ 16(DI), R10
    MOVQ 24(DI), R11

    MOVL $19, AX
    MOVL $38, CX

    BTRQ $63, R11 // PUT BIT 255 IN CARRY FLAG AND CLEAR
    CMOVLCC AX, CX // C[255] ? 38 : 19

    // ADD EITHER 19 OR 38 TO C
    ADDQ CX,  R8
    ADCQ $0,  R9
    ADCQ $0, R10
    ADCQ $0, R11

    // TEST FOR BIT 255 AGAIN; ONLY TRIGGERED ON OVERFLOW MODULO 2^255-19
    MOVL     $0,  CX
    CMOVLPL  AX,  CX // C[255] ? 0 : 19
    BTRQ    $63, R11 // CLEAR BIT 255

    // SUBTRACT 19 IF NECESSARY
    SUBQ CX,  R8
    MOVQ  R8,   (DI)
    SBBQ $0,  R9
    MOVQ  R9,  8(DI)
    SBBQ $0, R10
    MOVQ R10, 16(DI)
    SBBQ $0, R11
    MOVQ R11, 24(DI)
    RET

// func (field) Add(z, x, y *Elt)
TEXT ·field·Add(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    additionLeg(0(DI),0(SI),0(BX))
    RET

// func (field) Sub(z, x, y *Elt)
TEXT ·field·Sub(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    subtraction(0(DI),0(SI),0(BX))
    RET

// func (field) Mul(z, x, y *Elt)
TEXT ·field·Mul(SB),NOSPLIT,$64
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    integerMulLeg(0(SP),0(SI),0(BX))
    reduceFromDoubleLeg(0(DI),0(SP))
    RET

// func (field) Sqr(z, x *Elt)
TEXT ·field·Sqr(SB),NOSPLIT,$64
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    integerSqrLeg(0(SP),0(SI))
    reduceFromDoubleLeg(0(DI),0(SP))
    RET

// func (field) sqrn(z *Elt, n uint)
TEXT ·field·sqrn(SB),NOSPLIT,$64
    MOVQ z+0(FP), DI
    MOVL n+8(FP), SI
    L0:
        CMPQ SI, $0
        JZ L1
        integerSqrLeg(0(SP),0(DI))
        reduceFromDoubleLeg(0(DI),0(SP))
        DECQ SI
        JMP L0
    L1:
    RET

// func (fieldBmi2Adx) Add(z, x, y *Elt)
TEXT ·fieldBmi2Adx·Add(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    additionAdx(0(DI),0(SI),0(BX))
    RET

// func (fieldBmi2Adx) Mul(z, x, y *Elt)
TEXT ·fieldBmi2Adx·Mul(SB),NOSPLIT,$64
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    integerMulAdx(0(SP),0(SI),0(BX))
    reduceFromDoubleAdx(0(DI),0(SP))
    RET

// func (fieldBmi2Adx) Sqr(z, x *Elt)
TEXT ·fieldBmi2Adx·Sqr(SB),NOSPLIT,$64
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    integerSqrAdx(0(SP),0(SI))
    reduceFromDoubleAdx(0(DI),0(SP))
    RET

// func (fieldBmi2Adx) sqrn(z *Elt, n uint)
TEXT ·fieldBmi2Adx·sqrn(SB),NOSPLIT,$64
    MOVQ z+0(FP), DI
    MOVL n+8(FP), SI
    L0:
        CMPQ SI, $0
        JZ L1
        integerSqrAdx(0(SP),0(DI))
        reduceFromDoubleAdx(0(DI),0(SP))
        DECQ SI
        JMP L0
    L1:
    RET
