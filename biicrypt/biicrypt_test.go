package biicrypt

import (
	"crypto/subtle"
	"testing"

	b "golang.org/x/crypto/bcrypt"
)

func TestBiiCrypt(t *testing.T) {
	pass := "mypassword"
	hash, secret, err := GenerateFromPassword([]byte(pass), DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword error: %s", err)
	}

	other_hash, err := GenerateWithSecret([]byte(pass), secret)
	if err != nil {
		t.Fatalf("GenerateWithSecret error: %s", err)
	}

	if subtle.ConstantTimeCompare(hash, other_hash) != 1 {
		t.Fatalf("GenerateWithSecret does not return idential hash from stored secret")
	}

	notPass := "notthepass"
	wrong_hash, err := GenerateWithSecret([]byte(notPass), secret)
	if err != nil {
		t.Fatalf("GenerateWithSecret error: %s", err)
	}
	if subtle.ConstantTimeCompare(hash, wrong_hash) == 1 {
		t.Fatalf("Generate with secret does not generate different hashes for identical inputs")
	}
}

func TestBiiCryptReformatSecret(t *testing.T) {

	password := "MySafePassword"
	hash, err := b.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		t.Fatalf("There has been an error: %s", err)
	}

	newPasswordHash, newSecretHash, err := Reformat(hash)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}

	newnew, err := GenerateWithSecret([]byte(password), newSecretHash)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}

	if subtle.ConstantTimeCompare(newPasswordHash, newnew) != 1 {
		t.Fatalf("Expected password and password generated from new secret do not match")
	}
}

func BenchmarkEqual(b *testing.B) {
	b.StopTimer()
	passwd := []byte("somepasswordyoulike")
	hash, secret, _ := GenerateFromPassword(passwd, DefaultCost)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		other_hash, _ := GenerateWithSecret(passwd, secret)
		subtle.ConstantTimeCompare(hash, other_hash)
	}
}

func BenchmarkDefaultCost(b *testing.B) {
	b.StopTimer()
	passwd := []byte("mylongpassword1234")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		GenerateFromPassword(passwd, DefaultCost)
	}
}

func TestPasswordTooLong(t *testing.T) {
	_, _, err := GenerateFromPassword(make([]byte, 73), 1)
	if err != ErrPasswordTooLong {
		t.Errorf("unexpected error: got %q, want %q", err, ErrPasswordTooLong)
	}
}
