// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build s390x,!gccgo,!appengine

package chacha20

import (
	"testing"
)

func TestCoreNoVX(t *testing.T) {
	if !hasVX {
		t.Skipf("no vector implementation")
	}
	hasVX = false
	defer func() { hasVX = true }()

	testCore(t)
}
