// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build arm64 && !purego && gc

package sha3

import "golang.org/x/sys/cpu"

//go:noescape
func keccakF1600NEON(a *[25]uint64)

func keccakF1600(a *[25]uint64) {
	if cpu.ARM64.HasSHA3 {
		keccakF1600NEON(a)
	} else {
		keccakF1600Generic(a)
	}
}
