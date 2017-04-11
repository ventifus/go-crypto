package knownhosts

import (
	"bytes"
	"fmt"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
)

const edKeyStr = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGBAarftlLeoyf+v+nVchEZII/vna2PCV8FaX4vsF5BX"
const ecKeyStr = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNLCu01+wpXe3xB5olXCN4SqU2rQu0qjSRKJO4Bg+JRCPU+ENcgdA5srTU8xYDz/GEa4dzK5ldPw4J/gZgSXCMs="

var ecKey, edKey ssh.PublicKey
var testAddr = &net.TCPAddr{
	IP:   net.IP{198, 41, 30, 196},
	Port: 22,
}

func init() {
	var err error
	ecKey, _, _, _, err = ssh.ParseAuthorizedKey([]byte(ecKeyStr))
	if err != nil {
		panic(err)
	}
	edKey, _, _, _, err = ssh.ParseAuthorizedKey([]byte(edKeyStr))
	if err != nil {
		panic(err)
	}
}

func testDB(t *testing.T, s string) *hostKeyDB {
	db := newHostKeyDB()
	if err := db.Read(bytes.NewBufferString(s)); err != nil {
		t.Fatalf("Read: %v", err)
	}

	return db
}

func TestRevoked(t *testing.T) {
	db := testDB(t, "@revoked * "+edKeyStr+"\n")
	if err := db.check("", &net.TCPAddr{
		Port: 42,
	}, edKey); err == nil {
		t.Fatal("no error for revoked key")
	} else if _, ok := err.(*KeyRevoked); !ok {
		t.Fatalf("got type %T, want *KeyRevoked", err)
	}
}

func TestBracket(t *testing.T) {
	db := testDB(t, `[git.eclipse.org]:29418,[198.41.30.196]:29418 `+edKeyStr)

	if err := db.check("git.eclipse.org:29418", &net.TCPAddr{
		IP:   net.IP{198, 41, 30, 196},
		Port: 29418,
	}, edKey); err != nil {
		t.Errorf("got error %v, want none", err)
	}

	if err := db.check("git.eclipse.org:29419", &net.TCPAddr{
		Port: 42,
	}, edKey); err == nil {
		t.Fatalf("no error for unknown address")
	} else if ke, ok := err.(*KeyError); !ok {
		t.Fatalf("got type %T, want *KeyError", err)
	} else if len(ke.Want) > 0 {
		t.Fatalf("got Want %v, want []", ke.Want)
	}
}

func TestNewKeyType(t *testing.T) {
	str := fmt.Sprintf("%s %s", testAddr, edKeyStr)
	db := testDB(t, str)
	if err := db.check("", testAddr, ecKey); err == nil {
		t.Fatalf("no error for unknown address")
	} else if ke, ok := err.(*KeyError); !ok {
		t.Fatalf("got type %T, want *KeyError", err)
	} else if len(ke.Want) == 0 {
		t.Fatalf("got empty KeyError.Want")
	}
}

func TestIPAddress(t *testing.T) {
	str := fmt.Sprintf("%s %s", testAddr, edKeyStr)
	db := testDB(t, str)
	if err := db.check("", testAddr, edKey); err != nil {
		t.Errorf("got error %q, want none", err)
	}
}

func TestDefaultPort(t *testing.T) {
	str := fmt.Sprintf("server.org,%s %s", testAddr, edKeyStr)
	db := testDB(t, str)
	if err := db.check("server.org:22", testAddr, edKey); err != nil {
		t.Errorf("got error %q, want none", err)
	}
}

func TestNegate(t *testing.T) {
	str := fmt.Sprintf("%s,!server.org %s", testAddr, edKeyStr)
	db := testDB(t, str)
	if err := db.check("server.org:22", testAddr, ecKey); err == nil {
		t.Errorf("succeeded")
	} else if ke, ok := err.(*KeyError); !ok {
		t.Errorf("got error type %T, want *KeyError", err)
	} else if len(ke.Want) != 0 {
		t.Errorf("got expected keys %d (first of type %s), want []",
			len(ke.Want), ke.Want[0].Type())
	}
}

func TestWildcard(t *testing.T) {
	db := newHostKeyDB()
	if err := db.Read(bytes.NewBufferString(`* ` + edKeyStr)); err == nil {
		t.Fatalf("succeeded parsing * wildcard")
	}
	if err := db.Read(bytes.NewBufferString(`a.b.c? ` + edKeyStr)); err == nil {
		t.Fatalf("succeeded parsing ? wildcard")
	}
}

func TestLine(t *testing.T) {
	for in, want := range map[string]string{
		"server.org":    "server.org " + edKeyStr,
		"server.org:22": "server.org " + edKeyStr,
		"server.org:23": "[server.org]:23 " + edKeyStr,
	} {

		got := Line([]string{in}, edKey)
		if got != want {
			t.Errorf("Line(%q) = %q, want %q", got, want)
		}
	}
}

// TODO(hanwen): test coverage for certificates.
