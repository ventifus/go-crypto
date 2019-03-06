// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!gccgo,!appengine

#include "textflag.h"
#include "internal/fp/fp_amd64.h"

#define ladderStepLeg             \
    addSub(x2,z2)                 \
    addSub(x3,z3)                 \
    integerMulLeg(b0,x2,z3)       \
    integerMulLeg(b1,x3,z2)       \
    reduceFromDoubleLeg(t0,b0)    \
    reduceFromDoubleLeg(t1,b1)    \
    addSub(t0,t1)                 \
    cselect(x2,x3,regMove)        \
    cselect(z2,z3,regMove)        \
    integerSqrLeg(b0,t0)          \
    integerSqrLeg(b1,t1)          \
    reduceFromDoubleLeg(x3,b0)    \
    reduceFromDoubleLeg(z3,b1)    \
    integerMulLeg(b0,x1,z3)       \
    reduceFromDoubleLeg(z3,b0)    \
    integerSqrLeg(b0,x2)          \
    integerSqrLeg(b1,z2)          \
    reduceFromDoubleLeg(x2,b0)    \
    reduceFromDoubleLeg(z2,b1)    \
    subtraction(t0,x2,z2)         \
    multiplyA24Leg(t1,t0,CTE_A24) \
    additionLeg(t1,t1,z2)         \
    integerMulLeg(b0,x2,z2)       \
    integerMulLeg(b1,t0,t1)       \
    reduceFromDoubleLeg(x2,b0)    \
    reduceFromDoubleLeg(z2,b1)

#define ladderStepBmi2Adx         \
    addSub(x2,z2)                 \
    addSub(x3,z3)                 \
    integerMulAdx(b0,x2,z3)       \
    integerMulAdx(b1,x3,z2)       \
    reduceFromDoubleAdx(t0,b0)    \
    reduceFromDoubleAdx(t1,b1)    \
    addSub(t0,t1)                 \
    cselect(x2,x3,regMove)        \
    cselect(z2,z3,regMove)        \
    integerSqrAdx(b0,t0)          \
    integerSqrAdx(b1,t1)          \
    reduceFromDoubleAdx(x3,b0)    \
    reduceFromDoubleAdx(z3,b1)    \
    integerMulAdx(b0,x1,z3)       \
    reduceFromDoubleAdx(z3,b0)    \
    integerSqrAdx(b0,x2)          \
    integerSqrAdx(b1,z2)          \
    reduceFromDoubleAdx(x2,b0)    \
    reduceFromDoubleAdx(z2,b1)    \
    subtraction(t0,x2,z2)         \
    multiplyA24Adx(t1,t0,CTE_A24) \
    additionAdx(t1,t1,z2)         \
    integerMulAdx(b0,x2,z2)       \
    integerMulAdx(b1,t0,t1)       \
    reduceFromDoubleAdx(x2,b0)    \
    reduceFromDoubleAdx(z2,b1)

// func ladderStep(w *[5]fp.Elt, move uint)
//  w contains variables used in the Montgomery's ladder step,
//  (t0,t1) are two fp.Elt of fp.Size bytes, and
//  (b0,b1) are two fp.bigElt of 2*fp.Size bytes.
TEXT ·ladderStep(SB),NOSPLIT,$192
    // Parameters
    #define regWork DI
    #define regMove SI
    #define x1 0*Size(regWork)
    #define x2 1*Size(regWork)
    #define z2 2*Size(regWork)
    #define x3 3*Size(regWork)
    #define z3 4*Size(regWork)
    // Local variables
    #define t0 0*Size(SP)
    #define t1 1*Size(SP)
    #define b0 2*Size(SP)
    #define b1 4*Size(SP)
    MOVQ work+0(FP), regWork
    MOVQ move+8(FP), regMove
    CHECK_BMI2ADX(LLADSTEP, ladderStepLeg, ladderStepBmi2Adx)
    #undef regWork
    #undef regMove
    #undef x1
    #undef x2
    #undef z2
    #undef x3
    #undef z3
    #undef t0
    #undef t1
    #undef b0
    #undef b1

#define difAddLeg              \
    addSub(x1,z1)              \
    integerMulLeg(b0,z1,ui)    \
    reduceFromDoubleLeg(z1,b0) \
    addSub(x1,z1)              \
    integerSqrLeg(b0,x1)       \
    integerSqrLeg(b1,z1)       \
    reduceFromDoubleLeg(x1,b0) \
    reduceFromDoubleLeg(z1,b1) \
    integerMulLeg(b0,x1,z2)    \
    integerMulLeg(b1,z1,x2)    \
    reduceFromDoubleLeg(x1,b0) \
    reduceFromDoubleLeg(z1,b1)

#define difAddBmi2Adx          \
    addSub(x1,z1)              \
    integerMulAdx(b0,z1,ui)    \
    reduceFromDoubleAdx(z1,b0) \
    addSub(x1,z1)              \
    integerSqrAdx(b0,x1)       \
    integerSqrAdx(b1,z1)       \
    reduceFromDoubleAdx(x1,b0) \
    reduceFromDoubleAdx(z1,b1) \
    integerMulAdx(b0,x1,z2)    \
    integerMulAdx(b1,z1,x2)    \
    reduceFromDoubleAdx(x1,b0) \
    reduceFromDoubleAdx(z1,b1)


// func difAdd(work *[4]fp.Elt, mu *fp.Elt, swap uint)
// work contains variables used by the differential addition
// where {x1,z1,x2,z2} are four fp.Elt of fp.Size bytes, and
//       {b0,b1} are two fp.bigElt of 2*fp.Size bytes.
TEXT ·difAdd(SB),NOSPLIT,$192
    // Parameters
    #define regWork DI
    #define regMu   CX
    #define regSwap SI
    #define ui 0(regMu)
    #define x1 0*Size(regWork)
    #define z1 1*Size(regWork)
    #define x2 2*Size(regWork)
    #define z2 3*Size(regWork)
    // Local variables
    #define b0 0*Size(SP)
    #define b1 2*Size(SP)
    MOVQ work+0(FP), regWork
    MOVQ mu+8(FP), regMu
    MOVQ swap+16(FP), regSwap
    cswap(x1,x2,regSwap)
    cswap(z1,z2,regSwap)
    CHECK_BMI2ADX(LDIFADD, difAddLeg, difAddBmi2Adx)
    #undef regWork
    #undef regMu
    #undef regSwap
    #undef ui
    #undef x1
    #undef z1
    #undef x2
    #undef z2
    #undef b0
    #undef b1

#define doubleLeg                 \
    addSub(x1,z1)                 \
    integerSqrLeg(b0,x1)          \
    integerSqrLeg(b1,z1)          \
    reduceFromDoubleLeg(x1,b0)    \
    reduceFromDoubleLeg(z1,b1)    \
    subtraction(x2,x1,z1)         \
    multiplyA24Leg(z2,x2,CTE_A24) \
    additionLeg(z2,z2,z1)         \
    integerMulLeg(b0,x1,z1)       \
    integerMulLeg(b1,x2,z2)       \
    reduceFromDoubleLeg(x1,b0)    \
    reduceFromDoubleLeg(z1,b1)

#define doubleBmi2Adx             \
    addSub(x1,z1)                 \
    integerSqrAdx(b0,x1)          \
    integerSqrAdx(b1,z1)          \
    reduceFromDoubleAdx(x1,b0)    \
    reduceFromDoubleAdx(z1,b1)    \
    subtraction(x2,x1,z1)         \
    multiplyA24Adx(z2,x2,CTE_A24) \
    additionAdx(z2,z2,z1)         \
    integerMulAdx(b0,x1,z1)       \
    integerMulAdx(b1,x2,z2)       \
    reduceFromDoubleAdx(x1,b0)    \
    reduceFromDoubleAdx(z1,b1)


// func double(work *[4]fp.Elt)
// work contains variables used by the point doubling
// where {x1,z1,x2,z2} are four fp.Elt of fp.Size bytes, and
//       {b0,b1} are two fp.bigElt of 2*fp.Size bytes.
TEXT ·double(SB),NOSPLIT,$192
    // Parameters
    #define regWork DI
    #define x1 0*Size(regWork)
    #define z1 1*Size(regWork)
    #define x2 2*Size(regWork)
    #define z2 3*Size(regWork)
    // Local variables
    #define b0 0*Size(SP)
    #define b1 2*Size(SP)
    MOVQ work+0(FP), regWork
    CHECK_BMI2ADX(LDOUB,doubleLeg,doubleBmi2Adx)
    #undef regWork
    #undef x1
    #undef z1
    #undef x2
    #undef z2
    #undef b0
    #undef b1
