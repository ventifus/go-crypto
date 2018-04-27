// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.7,!go1.11,amd64,!gccgo,!appengine

// func supportsAVX2() bool
TEXT ·supportsAVX2(SB), 4, $0-1
	MOVQ runtime·support_avx2(SB), AX
	MOVB AX, ret+0(FP)
	RET

// func supportsAVX() bool
TEXT ·supportsAVX(SB), 4, $0-1
	MOVQ runtime·support_avx(SB), AX
	MOVB AX, ret+0(FP)
	RET
