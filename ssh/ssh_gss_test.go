package ssh

import (
	"encoding/asn1"
	"testing"
)

func TestParseGSSAPIPayload(t *testing.T) {
	payload := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x06, 0x09,
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
	res, err := parseGSSAPIPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if ok := res.OIDS[0].Equal(krb5Mesh); !ok {
		t.Fatal("not equal")
	}
}

func TestSSHGSSOIDS(t *testing.T) {
	oids := sshgssoids()
	expected := []byte{0x00, 0x00, 0x00, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
	if len(oids) != len(expected) {
		t.Fatal("length is not equal")
	}
	for i := 0; i < len(oids); i++ {
		if oids[i] != expected[i] {
			t.Fatalf("val is not equal, index: %d\n", i)
		}
	}
}
