package secretbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

func Example() {
	// Load your secret key from a safe place and reuse it across multiple Seal
	// calls. (Obviously don't use this example key for anything real.)
	secretKeyBytes, err := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	if err != nil {
		panic(err)
	}

	// You must use a different nonce for each message you encrypt with the
	// same key.
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}

	// This encrypts "hello world" and appends the result to the nonce.
	encrypted := Seal(nonce[:], []byte("hello world"), &nonce, &secretkey)

	// When you decrypt, you must use the same nonce and key you used to
	// encrypt the message. One way to achieve this is to store the nonce
	// alongside the encrypted message. Above, we stored the nonce in the first
	// 24 bytes of the encrypted text.
	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	decrypted, _ := Open([]byte{}, encrypted[24:], &decryptNonce, &secretkey)
	fmt.Println(string(decrypted))
	// Output: hello world
}
