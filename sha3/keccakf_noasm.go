// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//  +build !amd64,!arm appengine gccgo

package sha3

// Use generic implementation
func keccakF1600(a *[25]uint64) {
	keccakF1600Generic(a)
}
