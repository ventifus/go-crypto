// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build arm,!appengine,!gccgo

// This generates the plan9 assembly code from the native ARM assembly code - it assumes that one is running on a linux x86 system
// and the arm-linux-gnueabihf cross compiler utils are installed on and on the $PATH
// as well as the actual tool asm2go : https://github.com/anonymouse64/asm2go
//go:generate asm2go -as arm-linux-gnueabihf-as -file asm_src/keccakf_arm.s -gofile keccakf_arm.go -out keccakf_arm.s -as-opts -march=armv7-a -as-opts -mfpu=neon-vfpv4

package sha3

import _ "unsafe"

// To detect what version of arm we are running on we need to get goarm from the runtime
//go:linkname goarm runtime.goarm
var goarm uint8

//go:noescape
// This function is implemented in keccakf_arm.s
func KeccakF1600(state *[25]uint64, constants *[24]uint64)

// If NEON is available, use the NEON implementation, otherwise fallback on
// generic implementation
func keccakF1600(a *[25]uint64) {
	if goarm >= 7 {
		// rc is declared in keccakf_generic.go
		KeccakF1600(a, &rc)
	} else {
		keccakF1600Generic(a)
	}
}
