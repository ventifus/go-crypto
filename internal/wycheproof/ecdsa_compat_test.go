// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !go1.15

// ecdsa.VerifyASN1 was added in Go 1.15.

package wycheproof

import (
	"crypto/ecdsa"

	wecdsa "golang.org/x/crypto/internal/wycheproof/internal/ecdsa"
)

func verifyASN1(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	return wecdsa.VerifyASN1(pub, hash, sig)
}
