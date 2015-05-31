// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tea

import "testing"

// A sample test key for when we just want to initialize a cipher
var testKey = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}

// Test that the block size for tea is correct
func TestBlocksize(t *testing.T) {
	if BlockSize != 8 {
		t.Errorf("BlockSize constant - expected 8, got %d", BlockSize)
		return
	}

	c, err := NewCipherWithRounds(testKey)
	if err != nil {
		t.Errorf("NewCipherWithRounds(%d bytes) = %s", len(testKey), err)
		return
	}

	result := c.BlockSize()
	if result != 8 {
		t.Errorf("BlockSize function - expected 8, got %d", result)
		return
	}
}

// Test that invalid key sizes return an error
func TestInvalidKeySize(t *testing.T) {
	// Test a long key
	key := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
	}

	_, err := NewCipherWithRounds(key)
	if err == nil {
		t.Errorf("Invalid key size %d didn't result in an error.", len(key))
	}

	// Test a short key
	key = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}

	_, err = NewCipherWithRounds(key)
	if err == nil {
		t.Errorf("Invalid key size %d didn't result in an error.", len(key))
	}
}

// Test that we can correctly decode some bytes we have encoded
func TestEncodeDecode(t *testing.T) {
	original := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	input := original
	output := make([]byte, BlockSize)

	c, err := NewCipherWithRounds(testKey)
	if err != nil {
		t.Errorf("NewCipherWithRounds(%d bytes) = %s", len(testKey), err)
		return
	}

	// Encrypt the input block
	c.Encrypt(output, input)

	// Check that the output does not match the input
	differs := false
	for i := 0; i < len(input); i++ {
		if output[i] != input[i] {
			differs = true
			break
		}
	}
	if differs == false {
		t.Error("Cipher.Encrypt: Failed to encrypt the input block.")
		return
	}

	// Decrypt the block we just encrypted
	input = output
	output = make([]byte, BlockSize)
	c.Decrypt(output, input)

	// Check that the output from decrypt matches our initial input
	for i := 0; i < len(input); i++ {
		if output[i] != original[i] {
			t.Errorf("Decrypted byte %d differed. Expected %02X, got %02X\n", i, original[i], output[i])
			return
		}
	}
}

// Test Vectors
type CryptTest struct {
	key        []byte
	plainText  []byte
	cipherText []byte
}

var CryptTests = []CryptTest{
	// These were sourced from https://github.com/froydnj/ironclad/blob/master/testing/test-vectors/tea.testvec
	{
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		[]byte{0x41, 0xea, 0x3a, 0x0a, 0x94, 0xba, 0xa9, 0x40},
	},
	{
		[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		[]byte{0x31, 0x9b, 0xbe, 0xfb, 0x01, 0x6a, 0xbd, 0xb2},
	},
}

// Test vectors for 16 round TEA variant
var CryptTests_16 = []CryptTest{
	{
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		[]byte{0xed, 0x28, 0x5d, 0xa1, 0x45, 0x5b, 0x33, 0xc1},
	},
}

// Test encryption
func TestCipherEncrypt(t *testing.T) {
	// Test encryption with standard 64 rounds
	for i, tt := range CryptTests {
		c, err := NewCipherWithRounds(tt.key)
		if err != nil {
			t.Errorf("NewCipherWithRounds(%d bytes), vector %d = %s", len(tt.key), i, err)
			continue
		}

		out := make([]byte, len(tt.plainText))
		c.Encrypt(out, tt.plainText)

		for j := 0; j < len(out); j++ {
			if out[j] != tt.cipherText[j] {
				t.Errorf("Cipher.Encrypt %d: out[%d] = %02X, expected %02X", i, j, out[j], tt.cipherText[j])
				break
			}
		}
	}

	// Test encryption with variable rounds
	for i, tt := range CryptTests_16 {
		c, err := NewCipherWithRounds(tt.key, 16)
		if err != nil {
			t.Errorf("NewCipherWithRounds(%d bytes), vector %d = %s", len(tt.key), i, err)
			continue
		}

		out := make([]byte, len(tt.plainText))
		c.Encrypt(out, tt.plainText)

		for j := 0; j < len(out); j++ {
			if out[j] != tt.cipherText[j] {
				t.Errorf("Cipher.Encrypt %d: out[%d] = %02X, expected %02X", i, j, out[j], tt.cipherText[j])
				break
			}
		}
	}
}

// Test decryption
func TestCipherDecrypt(t *testing.T) {
	// Test decryption with standard 64 rounds
	for i, tt := range CryptTests {
		c, err := NewCipherWithRounds(tt.key)
		if err != nil {
			t.Errorf("NewCipherWithRounds(%d bytes), vector %d = %s", len(tt.key), i, err)
			continue
		}

		out := make([]byte, len(tt.cipherText))
		c.Decrypt(out, tt.cipherText)

		for j := 0; j < len(out); j++ {
			if out[j] != tt.plainText[j] {
				t.Errorf("Cipher.Decrypt %d: out[%d] = %02X, expected %02X", i, j, out[j], tt.plainText[j])
				break
			}
		}
	}

	// Test decryption with variable rounds
	for i, tt := range CryptTests_16 {
		c, err := NewCipherWithRounds(tt.key, 16)
		if err != nil {
			t.Errorf("NewCipherWithRounds(%d bytes), vector %d = %s", len(tt.key), i, err)
			continue
		}

		out := make([]byte, len(tt.cipherText))
		c.Decrypt(out, tt.cipherText)

		for j := 0; j < len(out); j++ {
			if out[j] != tt.plainText[j] {
				t.Errorf("Cipher.Decrypt %d: out[%d] = %02X, expected %02X", i, j, out[j], tt.plainText[j])
				break
			}
		}
	}
}
