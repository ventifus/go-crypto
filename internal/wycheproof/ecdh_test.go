// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wycheproof

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"testing"
)

func TestECDH(t *testing.T) {
	type ECDHTestVector struct {
		// A brief description of the test case
		Comment string `json:"comment,omitempty"`
		// A list of flags
		Flags []string `json:"flags,omitempty"`
		// the private key
		Private string `json:"private,omitempty"`
		// Encoded public key
		Public string `json:"public,omitempty"`
		// Test result
		Result string `json:"result,omitempty"`
		// The shared secret key
		Shared string `json:"shared,omitempty"`
		// Identifier of the test case
		TcID int `json:"tcId,omitempty"`
	}

	type ECDHTestGroup struct {
		Curve string            `json:"curve,omitempty"`
		Tests []*ECDHTestVector `json:"tests,omitempty"`
	}

	type Root struct {
		TestGroups []*ECDHTestGroup `json:"testGroups,omitempty"`
	}

	flagsShouldPass := map[string]bool{
		// ParsePKIXPublicKey doesn't support compressed points.
		"CompressedPoint": false,
		// We don't support decoding custom curves.
		"UnnamedCurve": false,
		// WrongOrder and UnusedParam are only found with UnnamedCurve.
		"WrongOrder":  false,
		"UnusedParam": false,
	}

	// supportedCurves is a map of all elliptic curves supported
	// by crypto/elliptic, which can subsequently be parsed and tested.
	supportedCurves := map[string]bool{
		"secp224r1": true,
		"secp256r1": true,
		"secp384r1": true,
		"secp521r1": true,
	}

	var root Root
	readTestVector(t, "ecdh_test.json", &root)
	for _, tg := range root.TestGroups {
		if !supportedCurves[tg.Curve] {
			continue
		}
		for _, tt := range tg.Tests {
			shouldPass := shouldPass(tt.Result, tt.Flags, flagsShouldPass)

			p := decodeHex(tt.Public)
			pp, err := x509.ParsePKIXPublicKey(p)
			if err != nil {
				if shouldPass {
					t.Errorf("tcid: %d, type: %s, comment: %q, got error: %s", tt.TcID, tt.Result, tt.Comment, err)
				}
				continue
			}
			pub := pp.(*ecdsa.PublicKey)

			priv := decodeHex(tt.Private)
			shared := decodeHex(tt.Shared)

			x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, priv)
			xBytes := make([]byte, (pub.Curve.Params().BitSize+7)/8)
			got := bytes.Equal(shared, x.FillBytes(xBytes))

			if want := shouldPass; got != want {
				t.Errorf("tcid: %d, type: %s, comment: %q, wanted success: %t", tt.TcID, tt.Result, tt.Comment, want)
			}
		}
	}
}
