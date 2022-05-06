// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build gc && !purego

package aesgcmsiv

//go:noescape
func encryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//go:noescape
func expandKeyAsm(nr int, key *byte, enc *uint32)

//go:noescape
func aesctrAsm(nr int, enc *uint32, iv *[blockSize]byte, dst, src *byte, nblocks int)

// useMultiBlock causes cmd/asm to define "const_useMultiBlock"
// in "go_asm.h", which instructs aesctrAsm to compute multiple
// blocks at a time.
//
// Commenting out or deleting this constant restricts aesctrAsm
// to just one block a a time.
const useMultiBlock = true
