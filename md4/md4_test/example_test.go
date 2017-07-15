package md4_test

import (
	"fmt"
	"io"

	"golang.org/x/crypto/md4"
)

func ExampleNew() {
	h := md4.New()
	data := "These pretzels are making me thirsty."
	io.WriteString(h, data)
	fmt.Printf("%x", h.Sum(nil))
	// Output: 48c4e365090b30a32f084c4888deceaa
}
