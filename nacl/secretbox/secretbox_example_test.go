package secretbox

import (
	"encoding/hex"
	"fmt"
)

func Example() {
	// Load this key from a safe place and reuse it across multiple Seal calls.
	var secretkey [32]byte
	copy(secretkey[:], "change this password to a secret")

	var nonce [24]byte
	// Unlike this example, you must use a different nonce for each Seal call.
	// In your own code, consider using rand.Read(nonce[:])
	copy(nonce[:], "1111111111111111111111111")
	encrypted := Seal([]byte{}, []byte("hello world"), &nonce, &secretkey)
	fmt.Println(hex.EncodeToString(encrypted))

	// You must use the same nonce and key to decrypt the message.
	decrypted, ok := Open([]byte{}, encrypted, &nonce, &secretkey)
	fmt.Println(string(decrypted))
	// Output: 61d2034a63baa22ac6a4e063670117157410d46d4db103b732eea8
	// hello world
}
