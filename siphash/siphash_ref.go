// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !amd64,!386 gccgo appengine nacl

package siphash

func core(hVal *[4]uint64, msg []byte) {
	genericCore(hVal, msg)
}

func finalize64(hVal *[4]uint64, block *[BlockSize]byte) uint64 {
	return genericFinalize64(hVal, block)
}

func finalize128(tag *[16]byte, hVal *[4]uint64, block *[BlockSize]byte) {
	genericFinalize128(tag, hVal, block)
}
