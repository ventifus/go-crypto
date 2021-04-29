// Copyright (c) 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !amd64 || !gc || purego
// +build !amd64 !gc purego

package curve25519

func feMul(v, x, y *fieldElement) { feMulGeneric(v, x, y) }

func feSquare(v, x *fieldElement) { feSquareGeneric(v, x) }
