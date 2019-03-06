// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!gccgo,!appengine

#include "textflag.h"
#include "fp_amd64.h"

// func Cmov(x, y *Elt, n uint)
TEXT ·Cmov(SB),NOSPLIT,$64
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    cselect(0(DI),0(SI),BX)
    RET

// func Cswap(x, y *Elt, n uint)
TEXT ·Cswap(SB),NOSPLIT,$64
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    cswap(0(DI),0(SI),BX)
    RET

// func Sub(z, x, y *Elt)
TEXT ·Sub(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    subtraction(0(DI),0(SI),0(BX))
    RET

#define addLegacy \
    additionLeg(0(DI),0(SI),0(BX))
#define addBmi2Adx \
    additionAdx(0(DI),0(SI),0(BX))

#define mulLegacy \
    integerMulLeg(0(SP),0(SI),0(BX)) \
    reduceFromDoubleLeg(0(DI),0(SP))
#define mulBmi2Adx \
    integerMulAdx(0(SP),0(SI),0(BX)) \
    reduceFromDoubleAdx(0(DI),0(SP))

#define sqrLegacy \
    integerSqrLeg(0(SP),0(SI)) \
    reduceFromDoubleLeg(0(DI),0(SP))
#define sqrBmi2Adx \
    integerSqrAdx(0(SP),0(SI)) \
    reduceFromDoubleAdx(0(DI),0(SP))

#define mulA24Legacy \
    multiplyA24Leg(0(DI),0(SI),CTE_A24)
#define mulA24Bmi2Adx \
    multiplyA24Adx(0(DI),0(SI),CTE_A24)

// func Add(z, x, y *Elt)
TEXT ·Add(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    CHECK_BMI2ADX(LADD, addLegacy, addBmi2Adx)

// func Mul(z, x, y *Elt)
TEXT ·Mul(SB),NOSPLIT,$64
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    MOVQ y+16(FP), BX
    CHECK_BMI2ADX(LMUL, mulLegacy, mulBmi2Adx)

// func Sqr(z, x *Elt)
TEXT ·Sqr(SB),NOSPLIT,$64
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    CHECK_BMI2ADX(LSQR, sqrLegacy, sqrBmi2Adx)

// func MulA24(z, x *Elt)
TEXT ·MulA24(SB),NOSPLIT,$0
    MOVQ z+0(FP), DI
    MOVQ x+8(FP), SI
    CHECK_BMI2ADX(LMA24, mulA24Legacy, mulA24Bmi2Adx)

// func Modp(z *Elt)
TEXT ·Modp(SB),NOSPLIT,$0
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
