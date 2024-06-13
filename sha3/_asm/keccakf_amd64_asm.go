// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

//go:generate go run . -out ../keccakf_amd64.s -pkg sha3

// rc stores the round constants for use in the ι step.
var RcConstants = [24]uint64{
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808A,
	0x8000000080008000,
	0x000000000000808B,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008A,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000A,
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
}

var (
	// Temporary registers
	rT1 GPPhysical = RAX

	// Round vars
	rpState = RDI
	rpStack = RSP

	rDa = RBX
	rDe = RCX
	rDi = RDX
	rDo = R8
	rDu = R9

	rBa = R10
	rBe = R11
	rBi = R12
	rBo = R13
	rBu = R14

	rCa = RSI
	rCe = RBP
	rCi = rBi
	rCo = rBo
	rCu = R15
)

var (
	_ba = (0 * 8)
	_be = (1 * 8)
	_bi = (2 * 8)
	_bo = (3 * 8)
	_bu = (4 * 8)
	_ga = (5 * 8)
	_ge = (6 * 8)
	_gi = (7 * 8)
	_go = (8 * 8)
	_gu = (9 * 8)
	_ka = (10 * 8)
	_ke = (11 * 8)
	_ki = (12 * 8)
	_ko = (13 * 8)
	_ku = (14 * 8)
	_ma = (15 * 8)
	_me = (16 * 8)
	_mi = (17 * 8)
	_mo = (18 * 8)
	_mu = (19 * 8)
	_sa = (20 * 8)
	_se = (21 * 8)
	_si = (22 * 8)
	_so = (23 * 8)
	_su = (24 * 8)
)

func main() {
	Package("golang.org/x/crypto/sha3")
	ConstraintExpr("amd64,!purego,gc")
	keccakF1600()
	Generate()
}

func MOVQ_RBI_RCE() { MOVQ(rBi, rCe) }
func XORQ_RT1_RCA() { XORQ(rT1, rCa) }
func XORQ_RT1_RCE() { XORQ(rT1, rCe) }
func XORQ_RBA_RCU() { XORQ(rBa, rCu) }
func XORQ_RBE_RCU() { XORQ(rBe, rCu) }
func XORQ_RDU_RCU() { XORQ(rDu, rCu) }
func XORQ_RDA_RCA() { XORQ(rDa, rCa) }
func XORQ_RDE_RCE() { XORQ(rDe, rCe) }

type ArgReg = GPPhysical
type ArgMacro func()

func mKeccakRound(
	iState, oState ArgReg,
	rc U64,
	B_RBI_RCE, G_RT1_RCA, G_RT1_RCE, G_RBA_RCU,
	K_RT1_RCA, K_RT1_RCE, K_RBA_RCU, M_RT1_RCA,
	M_RT1_RCE, M_RBE_RCU, S_RDU_RCU, S_RDA_RCA,
	S_RDE_RCE ArgMacro,
) {
	Comment("Prepare round")
	MOVQ(rCe, rDa)
	ROLQ(Imm(1), rDa)

	MOVQ(Mem{Base: iState}.Offset(_bi), rCi)
	XORQ(Mem{Base: iState}.Offset(_gi), rDi)
	XORQ(rCu, rDa)
	XORQ(Mem{Base: iState}.Offset(_ki), rCi)
	XORQ(Mem{Base: iState}.Offset(_mi), rDi)
	XORQ(rDi, rCi)

	MOVQ(rCi, rDe)
	ROLQ(Imm(1), rDe)

	MOVQ(Mem{Base: iState}.Offset(_bo), rCo)
	XORQ(Mem{Base: iState}.Offset(_go), rDo)
	XORQ(rCa, rDe)
	XORQ(Mem{Base: iState}.Offset(_ko), rCo)
	XORQ(Mem{Base: iState}.Offset(_mo), rDo)
	XORQ(rDo, rCo)

	MOVQ(rCo, rDi)
	ROLQ(Imm(1), rDi)

	MOVQ(rCu, rDo)
	XORQ(rCe, rDi)
	ROLQ(Imm(1), rDo)

	MOVQ(rCa, rDu)
	XORQ(rCi, rDo)
	ROLQ(Imm(1), rDu)

	Comment("Result b")
	MOVQ(Mem{Base: iState}.Offset(_ba), rBa)
	MOVQ(Mem{Base: iState}.Offset(_ge), rBe)
	XORQ(rCo, rDu)
	MOVQ(Mem{Base: iState}.Offset(_ki), rBi)
	MOVQ(Mem{Base: iState}.Offset(_mo), rBo)
	MOVQ(Mem{Base: iState}.Offset(_su), rBu)
	XORQ(rDe, rBe)
	ROLQ(Imm(44), rBe)
	XORQ(rDi, rBi)
	XORQ(rDa, rBa)
	ROLQ(Imm(43), rBi)

	MOVQ(rBe, rCa)
	MOVQ(rc, rT1)
	ORQ(rBi, rCa)
	XORQ(rBa, rT1)
	XORQ(rT1, rCa)
	MOVQ(rCa, Mem{Base: oState}.Offset(_ba))

	XORQ(rDu, rBu)
	ROLQ(Imm(14), rBu)
	MOVQ(rBa, rCu)
	ANDQ(rBe, rCu)
	XORQ(rBu, rCu)
	MOVQ(rCu, Mem{Base: oState}.Offset(_bu))

	XORQ(rDo, rBo)
	ROLQ(Imm(21), rBo)
	MOVQ(rBo, rT1)
	ANDQ(rBu, rT1)
	XORQ(rBi, rT1)
	MOVQ(rT1, Mem{Base: oState}.Offset(_bi))

	NOTQ(rBi)
	ORQ(rBa, rBu)
	ORQ(rBo, rBi)
	XORQ(rBo, rBu)
	XORQ(rBe, rBi)
	MOVQ(rBu, Mem{Base: oState}.Offset(_bo))
	MOVQ(rBi, Mem{Base: oState}.Offset(_be))
	B_RBI_RCE()

	Comment("Result g")
	MOVQ(Mem{Base: iState}.Offset(_gu), rBe)
	XORQ(rDu, rBe)
	MOVQ(Mem{Base: iState}.Offset(_ka), rBi)
	ROLQ(Imm(20), rBe)
	XORQ(rDa, rBi)
	ROLQ(Imm(3), rBi)
	MOVQ(Mem{Base: iState}.Offset(_bo), rBa)
	MOVQ(rBe, rT1)
	ORQ(rBi, rT1)
	XORQ(rDo, rBa)
	MOVQ(Mem{Base: iState}.Offset(_me), rBo)
	MOVQ(Mem{Base: iState}.Offset(_si), rBu)
	ROLQ(Imm(28), rBa)
	XORQ(rBa, rT1)
	MOVQ(rT1, Mem{Base: oState}.Offset(_ga))
	G_RT1_RCA()

	XORQ(rDe, rBo)
	ROLQ(Imm(45), rBo)
	MOVQ(rBi, rT1)
	ANDQ(rBo, rT1)
	XORQ(rBe, rT1)
	MOVQ(rT1, Mem{Base: oState}.Offset(_ge))
	G_RT1_RCE()

	XORQ(rDi, rBu)
	ROLQ(Imm(61), rBu)
	MOVQ(rBu, rT1)
	ORQ(rBa, rT1)
	XORQ(rBo, rT1)
	MOVQ(rT1, Mem{Base: oState}.Offset(_go))

	ANDQ(rBe, rBa)
	XORQ(rBu, rBa)
	MOVQ(rBa, Mem{Base: oState}.Offset(_gu))
	NOTQ(rBu)
	G_RBA_RCU()

	ORQ(rBu, rBo)
	XORQ(rBi, rBo)
	MOVQ(rBo, Mem{Base: oState}.Offset(_gi))

	Comment("Result k")
	MOVQ(Mem{Base: iState}.Offset(_be), rBa)
	MOVQ(Mem{Base: iState}.Offset(_gi), rBe)
	MOVQ(Mem{Base: iState}.Offset(_ko), rBi)
	MOVQ(Mem{Base: iState}.Offset(_mu), rBo)
	MOVQ(Mem{Base: iState}.Offset(_sa), rBu)
	XORQ(rDi, rBe)
	ROLQ(Imm(6), rBe)
	XORQ(rDo, rBi)
	ROLQ(Imm(25), rBi)
	MOVQ(rBe, rT1)
	ORQ(rBi, rT1)
	XORQ(rDe, rBa)
	ROLQ(Imm(1), rBa)
	XORQ(rBa, rT1)
	MOVQ(rT1, Mem{Base: oState}.Offset(_ka))
	K_RT1_RCA()

	XORQ(rDu, rBo)
	ROLQ(Imm(8), rBo)
	MOVQ(rBi, rT1)
	ANDQ(rBo, rT1)
	XORQ(rBe, rT1)
	MOVQ(rT1, Mem{Base: oState}.Offset(_ke))
	K_RT1_RCE()

	XORQ(rDa, rBu)
	ROLQ(Imm(18), rBu)
	NOTQ(rBo)
	MOVQ(rBo, rT1)
	ANDQ(rBu, rT1)
	XORQ(rBi, rT1)
	MOVQ(rT1, Mem{Base: oState}.Offset(_ki))

	MOVQ(rBu, rT1)
	ORQ(rBa, rT1)
	XORQ(rBo, rT1)
	MOVQ(rT1, Mem{Base: oState}.Offset(_ko))

	ANDQ(rBe, rBa)
	XORQ(rBu, rBa)
	MOVQ(rBa, Mem{Base: oState}.Offset(_ku))
	K_RBA_RCU()

	Comment("Result m")
	MOVQ(Mem{Base: iState}.Offset(_ga), rBe)
	XORQ(rDa, rBe)
	MOVQ(Mem{Base: iState}.Offset(_ke), rBi)
	ROLQ(Imm(36), rBe)
	XORQ(rDe, rBi)
	MOVQ(Mem{Base: iState}.Offset(_bu), rBa)
	ROLQ(Imm(10), rBi)
	MOVQ(rBe, rT1)
	MOVQ(Mem{Base: iState}.Offset(_mi), rBo)
	ANDQ(rBi, rT1)
	XORQ(rDu, rBa)
	MOVQ(Mem{Base: iState}.Offset(_so), rBu)
	ROLQ(Imm(27), rBa)
	XORQ(rBa, rT1)
	MOVQ(rT1, Mem{Base: oState}.Offset(_ma))
	M_RT1_RCA()

	XORQ(rDi, rBo)
	ROLQ(Imm(15), rBo)
	MOVQ(rBi, rT1)
	ORQ(rBo, rT1)
	XORQ(rBe, rT1)
	MOVQ(rT1, Mem{Base: oState}.Offset(_me))
	M_RT1_RCE()

	XORQ(rDo, rBu)
	ROLQ(Imm(56), rBu)
	NOTQ(rBo)
	MOVQ(rBo, rT1)
	ORQ(rBu, rT1)
	XORQ(rBi, rT1)
	MOVQ(rT1, Mem{Base: oState}.Offset(_mi))

	ORQ(rBa, rBe)
	XORQ(rBu, rBe)
	MOVQ(rBe, Mem{Base: oState}.Offset(_mu))

	ANDQ(rBa, rBu)
	XORQ(rBo, rBu)
	MOVQ(rBu, Mem{Base: oState}.Offset(_mo))
	M_RBE_RCU()

	Comment("Result s")
	MOVQ(Mem{Base: iState}.Offset(_bi), rBa)
	MOVQ(Mem{Base: iState}.Offset(_go), rBe)
	MOVQ(Mem{Base: iState}.Offset(_ku), rBi)
	XORQ(rDi, rBa)
	MOVQ(Mem{Base: iState}.Offset(_ma), rBo)
	ROLQ(Imm(62), rBa)
	XORQ(rDo, rBe)
	MOVQ(Mem{Base: iState}.Offset(_se), rBu)
	ROLQ(Imm(55), rBe)

	XORQ(rDu, rBi)
	MOVQ(rBa, rDu)
	XORQ(rDe, rBu)
	ROLQ(Imm(2), rBu)
	ANDQ(rBe, rDu)
	XORQ(rBu, rDu)
	MOVQ(rDu, Mem{Base: oState}.Offset(_su))

	ROLQ(Imm(39), rBi)
	S_RDU_RCU()
	NOTQ(rBe)
	XORQ(rDa, rBo)
	MOVQ(rBe, rDa)
	ANDQ(rBi, rDa)
	XORQ(rBa, rDa)
	MOVQ(rDa, Mem{Base: oState}.Offset(_sa))
	S_RDA_RCA()

	ROLQ(Imm(41), rBo)
	MOVQ(rBi, rDe)
	ORQ(rBo, rDe)
	XORQ(rBe, rDe)
	MOVQ(rDe, Mem{Base: oState}.Offset(_se))
	S_RDE_RCE()

	MOVQ(rBo, rDi)
	MOVQ(rBu, rDo)
	ANDQ(rBu, rDi)
	ORQ(rBa, rDo)
	XORQ(rBi, rDi)
	XORQ(rBo, rDo)
	MOVQ(rDi, Mem{Base: oState}.Offset(_si))
	MOVQ(rDo, Mem{Base: oState}.Offset(_so))

}

// keccakF1600 applies the Keccak permutation to a 1600b-wide
// state represented as a slice of 25 uint64s.
func keccakF1600() {
	Implement("keccakF1600")
	AllocLocal(200)

	Load(Param("a"), rpState)

	Comment("Convert the user state into an internal state")
	NOTQ(Mem{Base: rpState}.Offset(_be))
	NOTQ(Mem{Base: rpState}.Offset(_bi))
	NOTQ(Mem{Base: rpState}.Offset(_go))
	NOTQ(Mem{Base: rpState}.Offset(_ki))
	NOTQ(Mem{Base: rpState}.Offset(_mi))
	NOTQ(Mem{Base: rpState}.Offset(_sa))

	Comment("Execute the KeccakF permutation")
	MOVQ(Mem{Base: rpState}.Offset(_ba), rCa)
	MOVQ(Mem{Base: rpState}.Offset(_be), rCe)
	MOVQ(Mem{Base: rpState}.Offset(_bu), rCu)

	XORQ(Mem{Base: rpState}.Offset(_ga), rCa)
	XORQ(Mem{Base: rpState}.Offset(_ge), rCe)
	XORQ(Mem{Base: rpState}.Offset(_gu), rCu)

	XORQ(Mem{Base: rpState}.Offset(_ka), rCa)
	XORQ(Mem{Base: rpState}.Offset(_ke), rCe)
	XORQ(Mem{Base: rpState}.Offset(_ku), rCu)

	XORQ(Mem{Base: rpState}.Offset(_ma), rCa)
	XORQ(Mem{Base: rpState}.Offset(_me), rCe)
	XORQ(Mem{Base: rpState}.Offset(_mu), rCu)

	XORQ(Mem{Base: rpState}.Offset(_sa), rCa)
	XORQ(Mem{Base: rpState}.Offset(_se), rCe)
	MOVQ(Mem{Base: rpState}.Offset(_si), rDi)
	MOVQ(Mem{Base: rpState}.Offset(_so), rDo)
	XORQ(Mem{Base: rpState}.Offset(_su), rCu)

	// Need to clean this up:
	for i, rc := range RcConstants {
		var iState, oState ArgReg
		if i%2 == 0 {
			iState, oState = rpState, rpStack
		} else {
			iState, oState = rpStack, rpState
		}

		if i != len(RcConstants)-1 {
			mKeccakRound(iState, oState, U64(rc), MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
		} else {
			mKeccakRound(iState, oState, U64(rc), NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP)
		}
	}

	Comment("Revert the internal state to the user state")
	NOTQ(Mem{Base: rpState}.Offset(_be))
	NOTQ(Mem{Base: rpState}.Offset(_bi))
	NOTQ(Mem{Base: rpState}.Offset(_go))
	NOTQ(Mem{Base: rpState}.Offset(_ki))
	NOTQ(Mem{Base: rpState}.Offset(_mi))
	NOTQ(Mem{Base: rpState}.Offset(_sa))

	RET()

	// mKeccakRound(rpState, rpStack, U64(0x0000000000000001), MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpStack, rpState, U64(0x0000000000008082), MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpState, rpStack, 0x800000000000808a, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpStack, rpState, 0x8000000080008000, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpState, rpStack, 0x000000000000808b, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpStack, rpState, 0x0000000080000001, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpState, rpStack, 0x8000000080008081, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpStack, rpState, 0x8000000000008009, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpState, rpStack, 0x000000000000008a, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpStack, rpState, 0x0000000000000088, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpState, rpStack, 0x0000000080008009, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpStack, rpState, 0x000000008000000a, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpState, rpStack, 0x000000008000808b, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpStack, rpState, 0x800000000000008b, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpState, rpStack, 0x8000000000008089, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpStack, rpState, 0x8000000000008003, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpState, rpStack, 0x8000000000008002, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpStack, rpState, 0x8000000000000080, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpState, rpStack, 0x000000000000800a, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpStack, rpState, 0x800000008000000a, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpState, rpStack, 0x8000000080008081, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpStack, rpState, 0x8000000000008080, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpState, rpStack, 0x0000000080000001, MOVQ_RBI_RCE, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBA_RCU, XORQ_RT1_RCA, XORQ_RT1_RCE, XORQ_RBE_RCU, XORQ_RDU_RCU, XORQ_RDA_RCA, XORQ_RDE_RCE)
	// mKeccakRound(rpStack, rpState, 0x8000000080008008, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP)

}
