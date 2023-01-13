package x509roots

import (
	"fmt"
	"os"
	"testing"
)

func TestParser(t *testing.T) {
	f, err := os.Open("certdata.txt")
	if err != nil {
		t.Fatal(err)
	}
	certs, err := ParseCertData(f)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(len(certs), certs)
	for _, c := range certs {
		if c.Certificate == nil {
			fmt.Println("BAD?")
		}
		if c.DistrustAfter != nil {
			fmt.Println(c.Certificate.Subject, c.DistrustAfter)
		}
	}
}
