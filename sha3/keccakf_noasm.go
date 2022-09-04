// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (!amd64 && !arm64) || purego || !gc

package sha3

func keccakF1600(a *[25]uint64) {
	keccakF1600Generic(a)
}
