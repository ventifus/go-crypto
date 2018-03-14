package sign

import (
	"io"

	"golang.org/x/crypto/ed25519"
)

// Overhead is the number of bytes of overhead when signing a message.
const Overhead = 64

// GenerateKey generates a new public/private key pair suitable for use with
// Seal and Open.
func GenerateKey(rand io.Reader) (publicKey *[32]byte, privateKey *[64]byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}
	publicKey, privateKey = new([32]byte), new([64]byte)
	copy((*publicKey)[:], pub)
	copy((*privateKey)[:], priv)
	return publicKey, privateKey, nil
}

// Sign appends a signed copy of message to out, which will be Overhead bytes
// longer than the original and must not overlap it.
func Sign(out, message []byte, privateKey *[64]byte) []byte {
	var sig = ed25519.Sign(ed25519.PrivateKey((*privateKey)[:]), message)
	ret, out := sliceForAppend(out, Overhead+len(message))
	copy(out, sig)
	copy(out[Overhead:], message)
	return ret
}

// Open verifies a signed message produced by Sign and appends the message to
// out, which must not overlap the signed message. The output will be Overhead
// bytes smaller than the signed message.
func Open(out, signedMessage []byte, publicKey *[32]byte) ([]byte, bool) {
	if len(signedMessage) < Overhead {
		return nil, false
	}
	if !ed25519.Verify(ed25519.PublicKey((*publicKey)[:]), signedMessage[Overhead:], signedMessage[:Overhead]) {
		return nil, false
	}
	ret, out := sliceForAppend(out, len(signedMessage)-Overhead)
	copy(out, signedMessage[Overhead:])
	return ret, true
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
