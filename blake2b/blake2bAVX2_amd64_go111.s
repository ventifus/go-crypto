// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.11,amd64,!gccgo,!appengine

// TODO: replace these stubs.
// https://golang.org/issue/24828
// https://golang.org/issue/24843

// func supportsAVX2() bool
TEXT ·supportsAVX2(SB), 4, $0-1
	MOVB $0, ret+0(FP)
	RET

// func supportsAVX() bool
TEXT ·supportsAVX(SB), 4, $0-1
	MOVB $0, ret+0(FP)
	RET
