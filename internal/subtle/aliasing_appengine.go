// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This is Google App Engine standard variant which assumes that overlapping slices
// share the same base because unsafe package import and cgo are disallowed.

// +build appengine

package subtle

// AnyOverlap reports whether a and b share memory at any,
// not necessarily corresponding, index.
//
// This is Google App Engine variant.
func AnyOverlap(a, b []byte) bool {
	if cap(a) == 0 || cap(b) == 0 {
		return false
	}
	if &a[0:cap(a)][cap(a)-1] != &b[0:cap(b)][cap(b)-1] {
		return false
	}
	return cap(a)-len(a) < cap(b) && cap(b)-len(b) < cap(a)
}

// InexactOverlap reports whether x and y share memory at any non-corresponding
// index.
//
// This is Google App Engine variant.
func InexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	return AnyOverlap(x, y)
}
