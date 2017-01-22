// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.8,s390x,!gccgo,!appengine

package poly1305

import (
	"testing"
)

func TestSumNoVX(t *testing.T) {
	if !hasVX {
		t.Skipf("no vector facility")
	}
	hasVX = false
	testSum(t, false)
	hasVX = true
}

func TestSumNoVXUnaligned(t *testing.T) {
	if !hasVX {
		t.Skipf("no vector facility")
	}
	hasVX = false
	testSum(t, true)
	hasVX = true
}
