package chacha20

import (
	"encoding/hex"
	"testing"
)

func TestCore(t *testing.T) {
	testCore(t)
}

func testCore(t *testing.T) {
	// This is just a smoke test that checks the example from
	// https://tools.ietf.org/html/rfc7539#section-2.3.2. The
	// chacha20poly1305 package contains much more extensive tests of this
	// code.
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}

	var input [16]byte
	input[0] = 1
	input[7] = 9
	input[11] = 0x4a

	var out [64]byte
	XORKeyStream(out[:], out[:], &input, &key)
	const expected = "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
	if result := hex.EncodeToString(out[:]); result != expected {
		t.Errorf("wanted %x but got %x", expected, result)
	}
}

// TestBoundsCheck tests that a call to XORKeyStream panics if the output slice
// is shorter than the input slice.
// Note: this test primarily exists to ensure that assembly implementations
// panic correctly.
func TestBoundsCheck(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			return
		}
		t.Errorf("expected panic")
	}()

	var key [32]byte
	var counter [16]byte
	msg := make([]byte, 256)
	XORKeyStream(msg[:len(msg)-2], msg, &counter, &key)
}

// TestNoInput tests that XORKeyStream correctly accepts input slices with
// a length of 0.
func TestNoInput(t *testing.T) {
	var key [32]byte
	var counter [16]byte
	msg := make([]byte, 256)
	for i := range msg {
		msg[i] = byte(i)
	}
	XORKeyStream(msg, msg[:0], &counter, &key)
	for i := range msg {
		if msg[i] != byte(i) {
			t.Errorf("msg[%v]: got %v, want %v", i, msg[i], byte(i))
		}
	}
}
