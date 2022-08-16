// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.20

package wycheproof

import (
	"bytes"
	"crypto/ecdh"
	"fmt"
	"testing"
)

func TestECDHStdLib(t *testing.T) {
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
		// We don't support compressed points.
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
		"secp256r1": true,
		"secp384r1": true,
		"secp521r1": true,
	}

	curveToCurve := map[string]ecdh.Curve{
		"secp256r1": ecdh.P256(),
		"secp384r1": ecdh.P384(),
		"secp521r1": ecdh.P521(),
	}

	curveToKeySize := map[string]int{
		"secp256r1": 32,
		"secp384r1": 48,
		"secp521r1": 66,
	}

	for _, f := range []string{
		"ecdh_secp256r1_ecpoint_test.json",
		"ecdh_secp384r1_ecpoint_test.json",
		"ecdh_secp521r1_ecpoint_test.json",
	} {
		var root Root
		readTestVector(t, f, &root)
		for _, tg := range root.TestGroups {
			if !supportedCurves[tg.Curve] {
				continue
			}
			for _, tt := range tg.Tests {
				tg, tt := tg, tt
				t.Run(fmt.Sprintf("%s/%d", tg.Curve, tt.TcID), func(t *testing.T) {
					t.Logf("Type: %v", tt.Result)
					t.Logf("Flags: %q", tt.Flags)
					t.Log(tt.Comment)

					shouldPass := shouldPass(tt.Result, tt.Flags, flagsShouldPass)

					curve := curveToCurve[tg.Curve]
					p := decodeHex(tt.Public)
					pub, err := curve.NewPublicKey(p)
					if err != nil {
						if shouldPass {
							t.Errorf("NewPublicKey: %v", err)
						}
						return
					}

					privBytes := decodeHex(tt.Private)
					if len(privBytes) != curveToKeySize[tg.Curve] {
						t.Skipf("non-standard key size %d", len(privBytes))
					}

					priv, err := curve.NewPrivateKey(privBytes)
					if err != nil {
						if shouldPass {
							t.Errorf("NewPrivateKey: %v", err)
						}
						return
					}

					shared := decodeHex(tt.Shared)
					x, err := curve.ECDH(priv, pub)
					if err != nil {
						if shouldPass {
							t.Errorf("ECDH: %v", err)
						}
						return
					}

					if bytes.Equal(shared, x) != shouldPass {
						if shouldPass {
							t.Errorf("ECDH = %x, want %x", shared, x)
						} else {
							t.Errorf("ECDH = %x, want anything else", shared)
						}
					}
				})
			}
		}
	}
}
