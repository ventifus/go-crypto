// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build arm
// +build arm

package sha3

import _ "unsafe"

// This function is implemented in keccakf_arm64.s.
//go:linkname goarm runtime.goarm
var goarm uint8

//go:noescape
func keccakF1600armv8(a *[25]uint64)

func keccakF1600(a *[25]uint64) {
	if goarm >= 8 {
		keccakF1600armv8(a)
	} else {
		keccakF1600Generic(a)
	}
}
