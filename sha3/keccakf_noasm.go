// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (!arm64 && !s390x && !ppc64le) || !arm || !gc || purego
// +build !arm64,!s390x,!ppc64le !gc purego !arm

package sha3

// Use generic implementation
func keccakF1600(a *[25]uint64) {
	keccakF1600Generic(a)
}
