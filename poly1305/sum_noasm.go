// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !arm,!amd64,!s390x

package poly1305

// Sum generates an authenticator for msg using a one-time key and
// puts the 16-byte result into out. This invokes the generic implementation
// sumGeneric and wll be called on architectures where no assembly implementation is available.
func Sum(out *[TagSize]byte, msg []byte, key *[32]byte) {
	sumGeneric(out, msg, key)
}
