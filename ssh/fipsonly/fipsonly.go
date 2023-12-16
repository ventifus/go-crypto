// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build boringcrypto

// Package fipsonly restricts all SSH configuration to FIPS-approved settings.
//
// The effect is triggered by importing the package anywhere in a program, as in:
//
//	import _ "golang.org/x/crypto/ssh/fipsonly"
//
// This package only exists when using Go compiled with GOEXPERIMENT=boringcrypto.
package fipsonly

import "golang.org/x/crypto/ssh/internal/fips"

func init() {
	fips.Enabled = true
}
