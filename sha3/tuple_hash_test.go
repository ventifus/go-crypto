// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"hash"
	"testing"
)

// Test vectors from
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TupleHash_samples.pdf
var tupleHashTests = []struct {
	security      int
	tuple         []string
	customization string
	output        string
}{
	{
		128,
		[]string{"000102", "101112131415"},
		"",
		"C5D8786C1AFB9B82111AB34B65B2C0048FA64E6D48E263264CE1707D3FFC8ED1",
	},
	{
		128,
		[]string{"000102", "101112131415"},
		"My Tuple App",
		"75CDB20FF4DB1154E841D758E24160C54BAE86EB8C13E7F5F40EB35588E96DFB",
	},
	{
		128,
		[]string{"000102", "101112131415", "202122232425262728"},
		"My Tuple App",
		"E60F202C89A2631EDA8D4C588CA5FD07F39E5151998DECCF973ADB3804BB6E84",
	},
	{
		256,
		[]string{"000102", "101112131415"},
		"",
		"CFB7058CACA5E668F81A12A20A2195CE97A925F1DBA3E7449A56F82201EC607311AC2696B1AB5EA2352DF1423BDE7BD4BB78C9AED1A853C78672F9EB23BBE194",
	},
	{
		256,
		[]string{"000102", "101112131415"},
		"My Tuple App",
		"147C2191D5ED7EFD98DBD96D7AB5A11692576F5FE2A5065F3E33DE6BBA9F3AA1C4E9A068A289C61C95AAB30AEE1E410B0B607DE3620E24A4E3BF9852A1D4367E",
	},
	{
		256,
		[]string{"000102", "101112131415", "202122232425262728"},
		"My Tuple App",
		"45000BE63F9B6BFD89F54717670F69A9BC763591A4F05C50D68891A744BCC6E7D6D5B5E82C018DA999ED35B0BB49C9678E526ABD8E85C13ED254021DB9E790CE",
	},
}

// Test vectors from
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TupleHashXOF_samples.pdf
var tupleHashXOFTests = []struct {
	security      int
	tuple         []string
	customization string
	output        string
}{
	{
		128,
		[]string{"000102", "101112131415"},
		"",
		"2F103CD7C32320353495C68DE1A8129245C6325F6F2A3D608D92179C96E68488",
	},
	{
		128,
		[]string{"000102", "101112131415"},
		"My Tuple App",
		"3FC8AD69453128292859A18B6C67D7AD85F01B32815E22CE839C49EC374E9B9A",
	},
	{
		128,
		[]string{"000102", "101112131415", "202122232425262728"},
		"My Tuple App",
		"900FE16CAD098D28E74D632ED852F99DAAB7F7DF4D99E775657885B4BF76D6F8",
	},
	{
		256,
		[]string{"000102", "101112131415"},
		"",
		"03DED4610ED6450A1E3F8BC44951D14FBC384AB0EFE57B000DF6B6DF5AAE7CD568E77377DAF13F37EC75CF5FC598B6841D51DD207C991CD45D210BA60AC52EB9",
	},
	{
		256,
		[]string{"000102", "101112131415"},
		"My Tuple App",
		"6483CB3C9952EB20E830AF4785851FC597EE3BF93BB7602C0EF6A65D741AECA7E63C3B128981AA05C6D27438C79D2754BB1B7191F125D6620FCA12CE658B2442",
	},
	{
		256,
		[]string{"000102", "101112131415", "202122232425262728"},
		"My Tuple App",
		"0C59B11464F2336C34663ED51B2B950BEC743610856F36C28D1D088D8A2446284DD09830A6A178DC752376199FAE935D86CFDEE5913D4922DFD369B66A53C897",
	},
}

func TestTupleHash(t *testing.T) {
	for i, test := range tupleHashTests {
		tuple := [][]byte{}
		for _, hexItem := range test.tuple {
			item, err := hex.DecodeString(hexItem)
			if err != nil {
				t.Errorf("error decoding KAT: %s", err)
			}
			tuple = append(tuple, item)
		}
		output, err := hex.DecodeString(test.output)
		if err != nil {
			t.Errorf("error decoding KAT: %s", err)
		}

		var h hash.Hash
		if test.security == 128 {
			h = NewTupleHash128(len(output), []byte(test.customization))
		} else {
			h = NewTupleHash256(len(output), []byte(test.customization))
		}
		for _, item := range tuple {
			h.Write(item)
		}
		computedOutput := h.Sum(nil)

		if !bytes.Equal(output, computedOutput) {
			t.Errorf("#%d: got %x, want %x", i, output, computedOutput)
		}

		if h.Size() != len(output) {
			t.Errorf("#%d: Size() = %x, want %x", i, h.Size(), len(output))
		}

		// Test if it works after Reset.
		h.Reset()
		for _, item := range tuple {
			h.Write(item)
		}
		computedOutput = h.Sum(nil)

		if !bytes.Equal(output, computedOutput) {
			t.Errorf("#%d: got %x, want %x", i, output, computedOutput)
		}

		// Test if Sum does not change state.
		if len(tuple) > 1 {
			h.Reset()
			h.Write(tuple[0])
			h.Sum(nil)
			for _, item := range tuple[1:] {
				h.Write(item)
			}
			computedOutput = h.Sum(nil)

			if !bytes.Equal(output, computedOutput) {
				t.Errorf("#%d: got %x, want %x", i, output, computedOutput)
			}
		}
	}
}

func TestTupleHashXOF(t *testing.T) {
	for i, test := range tupleHashXOFTests {
		tuple := [][]byte{}
		for _, hexItem := range test.tuple {
			item, err := hex.DecodeString(hexItem)
			if err != nil {
				t.Errorf("error decoding KAT: %s", err)
			}
			tuple = append(tuple, item)
		}
		output, err := hex.DecodeString(test.output)
		if err != nil {
			t.Errorf("error decoding KAT: %s", err)
		}

		var h ShakeHash
		if test.security == 128 {
			h = NewTupleHashXOF128([]byte(test.customization))
		} else {
			h = NewTupleHashXOF256([]byte(test.customization))
		}
		for _, item := range tuple {
			h.Write(item)
		}
		computedOutput := make([]byte, len(output))
		h.Read(computedOutput)

		if !bytes.Equal(output, computedOutput) {
			t.Errorf("#%d: got %x, want %x", i, output, computedOutput)
		}

		// Test if it works after Reset.
		h.Reset()
		for _, item := range tuple {
			h.Write(item)
		}
		computedOutput = make([]byte, len(output))
		h.Read(computedOutput)

		if !bytes.Equal(output, computedOutput) {
			t.Errorf("#%d: got %x, want %x", i, output, computedOutput)
		}

		// Test if it works after Clone.
		if len(tuple) > 1 {
			h.Reset()
			h.Write(tuple[0])
			newH := h.Clone()
			for _, item := range tuple[1:] {
				h.Write(item)
				newH.Write(item)
			}
			computedOutput = make([]byte, len(output))
			h.Read(computedOutput)
			clonedComputedOutput := make([]byte, len(output))
			newH.Read(clonedComputedOutput)

			if !bytes.Equal(output, computedOutput) {
				t.Errorf("#%d: got %x, want %x", i, output, computedOutput)
			}
			if !bytes.Equal(output, clonedComputedOutput) {
				t.Errorf("#%d: got %x, want %x", i, output, clonedComputedOutput)
			}
		}
	}
}

func ExampleNewTupleHash256() {
	tuple1 := []string{"The quick brown fox ", "jumps over the lazy dog"}

	// Example 1: 32-byte TupleHash256 with empty personalization string
	t := NewTupleHash256(32, nil)
	for _, item := range tuple1 {
		// Each item in the tuple must be written in a single Write call
		t.Write([]byte(item))
	}
	digest := t.Sum(nil)
	fmt.Println(hex.EncodeToString(digest))

	// Example 2: The same message split differently produces a different digest
	tuple2 := []string{"The quick brown fox jumps over ", "the lazy dog"}
	t.Reset()
	for _, item := range tuple2 {
		t.Write([]byte(item))
	}
	digest = t.Sum(nil)
	fmt.Println(hex.EncodeToString(digest))

	// Output:
	//b7fadd41d5c2d2c793d4eda5b4a6fb561af8f2211f74fda505db821330f3bd82
	//38966a7e13b2a4fc7f05bf869bcaded095335473e0b34c174d0f87318972bd1b
}

func ExampleNewTupleHashXOF256() {
	tuple1 := []string{"The quick brown fox ", "jumps over the lazy dog"}

	// Example 1: TupleHashXOF256 with empty personalization string
	t := NewTupleHashXOF256(nil)
	for _, item := range tuple1 {
		// Each item in the tuple must be written in a single Write call
		t.Write([]byte(item))
	}
	output := make([]byte, 32)
	t.Read(output)
	fmt.Println(hex.EncodeToString(output))

	// Example 2: The same message split differently produces a different digest
	tuple2 := []string{"The quick brown fox jumps over ", "the lazy dog"}
	t.Reset()
	for _, item := range tuple2 {
		t.Write([]byte(item))
	}
	// Arbitrary-length output can be read in parts if needed
	output = make([]byte, 32)
	t.Read(output[:16])
	t.Read(output[16:])
	fmt.Println(hex.EncodeToString(output))

	// Output:
	//ec8dab631ecf0cb3388bf5452e751c05dfa379f62740cb1a1884d2d2a54639cf
	//8446a9393860848aefdb7073e4a67f2a71f910adbc43abeeb997704607f5ad65
}
