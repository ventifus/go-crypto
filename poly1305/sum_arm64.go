// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build arm64 debug !gccgo !appengine !nacl

package poly1305

// Sum generates an authenticator for msg using a one-time key and puts the
// 16-byte result into out. Authenticating two different messages with the same
// key allows an attacker to forge messages at will.

// This function is implemented in sum_arm64.s
//go:noescape
func Sum(out *[TagSize]byte, msg []byte, key *[32]byte)
