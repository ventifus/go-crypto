package wycheproof

import (
	"crypto/ecdsa"
	"crypto/x509"
	"math/big"
	"testing"
)

func TestEcdh(t *testing.T) {
	// AsnSignatureTestVector
	type EcdhTestVector struct {

		// A brief description of the test case
		Comment string `json:"comment,omitempty"`

		// A list of flags
		Flags []string `json:"flags,omitempty"`

		// The public key in ecdh
		Public string `json:"public,omitempty"`

		// The private key of ASN1 format
		Private string `json:"private,omitempty"`

		// The shard secret wanted
		Shared string `json:"shared,omitempty"`

		// Test result
		Result string `json:"result,omitempty"`

		// Identifier of the test case
		TcId int `json:"tcId,omitempty"`
	}

	// EcdsaTestGroup
	type EcdhTestGroup struct {

		// the EC group used by this public key
		Curve interface{} `json:"curve,omitempty"`

		// the encoding method
		Encoding string `json:"encoding,omitempty"`

		Tests []*EcdhTestVector `json:"tests,omitempty"`
		Type  interface{}       `json:"type,omitempty"`
	}

	// Notes a description of the labels used in the test vectors
	type Notes struct {
	}

	// Root
	type Root struct {

		// the primitive tested in the test file
		Algorithm string `json:"algorithm,omitempty"`

		// the version of the test vectors.
		GeneratorVersion string `json:"generatorVersion,omitempty"`

		// additional documentation
		Header []string `json:"header,omitempty"`

		// a description of the labels used in the test vectors
		Notes *Notes `json:"notes,omitempty"`

		// the number of test vectors in this test
		NumberOfTests int              `json:"numberOfTests,omitempty"`
		Schema        interface{}      `json:"schema,omitempty"`
		TestGroups    []*EcdhTestGroup `json:"testGroups,omitempty"`
	}
	flagsShouldPass := map[string]bool{
		// The public key does not use a named curve.
		"UnnamedCurve": true,
		// A parameter that is typically not used for ECDH has been modified.
		"UnusedParam": false,
		// The order of the public key has been modified.
		"WrongOrder": true,
		// The library doesn't support points in compressed format.
		"CompressedPoint": false,
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
		curve, ok := supportedCurves[tg.Curve.(string)]
		if !ok || !curve {
			continue
		}
		for _, test := range tg.Tests {
			var got bool
			//can't use decodePublicKey because the library doesn't support points in compressed format.
			pub, ok := decodeECDHPublicKey(test.Public)
			if !ok {
				got = false
			} else {
				var priv big.Int
				priv.SetString(test.Private, 16)

				var shard big.Int
				shard.SetBytes(decodeHex(test.Shared))

				got = verifyECDH(pub, &priv, &shard)
			}
			if want := shouldPass(test.Result, test.Flags, flagsShouldPass); got != want {
				t.Errorf("tcid: %d, type: %s, comment: %q, flags:%v, wanted success: %t", test.TcId, test.Result, test.Comment, test.Flags, want)
			}
		}
	}
}
func decodeECDHPublicKey(der string) (*ecdsa.PublicKey, bool) {
	d := decodeHex(der)
	pubTemp, err := x509.ParsePKIXPublicKey(d)
	if err != nil {
		return nil, false
	}
	pub, ok := pubTemp.(*ecdsa.PublicKey)
	if !ok {
		return nil, false
	}
	return pub, true
}
func verifyECDH(pub *ecdsa.PublicKey, priv, shard *big.Int) bool {
	shardScret, _ := pub.Curve.ScalarMult(pub.X, pub.Y, priv.Bytes())
	if shardScret.Cmp(shard) != 0 {
		return false
	}
	return true
}
