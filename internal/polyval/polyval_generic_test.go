// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !(amd64 || arm64) || !gc || purego

package polyval

import "testing"

func runTests(t *testing.T, fn func(t *testing.T)) {
	t.Run("generic", fn)
}
