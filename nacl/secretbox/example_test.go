package secretbox

import (
	"crypto/rand"
	"fmt"
)

func Example() {
	// Load this key from a safe place and reuse it across multiple Seal calls.
	var secretkey [32]byte
	copy(secretkey[:], "change this password to a secret")

	// You must use a different nonce for each message you encrypt.
	nonceSlice := make([]byte, 24)
	rand.Read(nonceSlice)
	var nonce [24]byte
	copy(nonce[:], nonceSlice)

	// This encrypts "hello world" and appends the result to the nonce.
	encrypted := Seal(nonceSlice, []byte("hello world"), &nonce, &secretkey)

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
