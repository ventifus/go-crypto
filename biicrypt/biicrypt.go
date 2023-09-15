// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package bcrypt implements Provos and Mazières's bcrypt adaptive hashing
// algorithm. See http://www.usenix.org/event/usenix99/provos/provos.pdf
package biicrypt // import "golang.org/x/crypto/biicrypt"

// The code is a port of Provos and Mazières's C implementation.
import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strconv"

	"golang.org/x/crypto/blowfish"
)

const (
	MinCost     int = 4  // the minimum allowable cost as passed in to GenerateFromPassword
	MaxCost     int = 31 // the maximum allowable cost as passed in to GenerateFromPassword
	DefaultCost int = 10 // the cost that will actually be set if a cost below MinCost is passed into GenerateFromPassword
)

// The error returned from CompareHashAndPassword when a password and hash do
// not match.
var ErrMismatchedHashAndPassword = errors.New("crypto/biicrypt: hashedPassword is not the hash of the given password")

// The error returned from CompareHashAndPassword when a hash is too short to
// be a bcrypt hash.
var ErrHashTooShort = errors.New("crypto/biicrypt: hashedSecret too short to be a bcrypted password")

// The error returned from CompareHashAndPassword when a hash was created with
// a bcrypt algorithm newer than this implementation.
type HashVersionTooNewError byte

func (hv HashVersionTooNewError) Error() string {
	return fmt.Sprintf("crypto/biicrypt: bcrypt algorithm version '%c' requested is newer than current version '%c'", byte(hv), majorVersion)
}

// The error returned from CompareHashAndPassword when a hash starts with something other than '$'
type InvalidHashPrefixError byte

func (ih InvalidHashPrefixError) Error() string {
	return fmt.Sprintf("crypto/biicrypt: bcrypt hashes must start with '$', but hashedSecret started with '%c'", byte(ih))
}

type InvalidCostError int

func (ic InvalidCostError) Error() string {
	return fmt.Sprintf("crypto/biicrypt: cost %d is outside allowed range (%d,%d)", int(ic), MinCost, MaxCost)
}

const (
	majorVersion       = '3'
	minorVersion       = '\u0000'
	maxSaltSize        = 16
	maxCryptedHashSize = 23
	encodedSaltSize    = 22
	encodedHashSize    = 31
	// minSecretSize is used for secrets generated with Major version '3'
	minSecretSize = 28
	// minHashSize is used for verification on passwords that used Major Version '2'
	minHashSize = 59
)

type hashed struct {
	hash  []byte
	salt  []byte
	cost  int // allowed range is MinCost to MaxCost
	major byte
	minor byte
}

// ErrPasswordTooLong is returned when the password passed to
// GenerateFromPassword is too long (i.e. > 72 bytes).
var ErrPasswordTooLong = errors.New("bcrypt: password length exceeds 72 bytes")

// GenerateFromPassword returns the bcrypt hash and secret of the password at the
// given cost. If the cost given is less than MinCost, the cost will be set to
// DefaultCost, instead. Feed the returned secret along with the user inputed password
// into GenerateWithSecret to get the password hash. Compare this hash directly with your
// stored hashed password in your database
func GenerateFromPassword(password []byte, cost int) ([]byte, []byte, error) {
	if len(password) > 72 {
		return nil, nil, ErrPasswordTooLong
	}
	p, err := newFromPassword(password, cost)
	if err != nil {
		return nil, nil, err
	}
	return p.hash, p.notSoSecret(), nil
}

func GenerateWithSecret(password []byte, secret []byte) ([]byte, error) {
	p, err := newFromHash(secret)
	if err != nil {
		return nil, err
	}

	hash, err := bcrypt(password, p.cost, p.salt)
	if err != nil {
		return nil, err
	}

	return hash, nil
}

func newFromPassword(password []byte, cost int) (*hashed, error) {
	if cost < MinCost || cost > MaxCost {
		cost = DefaultCost
	}
	p := new(hashed)
	p.major = majorVersion
	p.minor = minorVersion
	p.cost = cost
	p.salt = make([]byte, maxSaltSize)

	_, err := io.ReadFull(rand.Reader, p.salt)
	if err != nil {
		return nil, err
	}

	p.hash, err = bcrypt(password, p.cost, p.salt)
	if err != nil {
		return nil, err
	}

	return p, err
}

func newFromHash(hashedSecret []byte) (*hashed, error) {
	if len(hashedSecret) < minSecretSize {
		return nil, ErrHashTooShort
	}

	p := new(hashed)
	err := p.decodeVersion(&hashedSecret)
	if err != nil {
		return nil, err
	}

	err = p.decodeCost(&hashedSecret)
	if err != nil {
		return nil, err
	}

	p.salt, err = base64Decode(hashedSecret[:encodedSaltSize])
	if err != nil {
		return nil, err
	}

	return p, nil
}

func bcrypt(password []byte, cost int, salt []byte) ([]byte, error) {
	// magicCipherData is an IV for the 64 Blowfish encryption calls in
	// bcrypt(). It's the string "OrpheanBeholderScryDoubt" in big-endian bytes.
	magicCipherData := []byte{
		0x4f, 0x72, 0x70, 0x68,
		0x65, 0x61, 0x6e, 0x42,
		0x65, 0x68, 0x6f, 0x6c,
		0x64, 0x65, 0x72, 0x53,
		0x63, 0x72, 0x79, 0x44,
		0x6f, 0x75, 0x62, 0x74,
	}

	c, err := expensiveBlowfishSetup(password, uint8(cost), salt)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 24; i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(magicCipherData[i:i+8], magicCipherData[i:i+8])
		}
	}

	// Bug compatibility with C bcrypt implementations. We only encode 23 of
	// the 24 bytes encrypted.
	hsh := base64Encode(magicCipherData[:maxCryptedHashSize])
	return hsh, nil
}

func expensiveBlowfishSetup(key []byte, cost uint8, salt []byte) (*blowfish.Cipher, error) {
	// Bug compatibility with C bcrypt implementations. They use the trailing
	// NULL in the key string during expansion.
	// We copy the key to prevent changing the underlying array.
	ckey := append(key[:len(key):len(key)], 0)

	c, err := blowfish.NewSaltedCipher(ckey, salt)
	if err != nil {
		return nil, err
	}

	var i, rounds uint64
	rounds = 1 << cost
	for i = 0; i < rounds; i++ {
		blowfish.ExpandKey(ckey, c)
		blowfish.ExpandKey(salt, c)
	}

	return c, nil
}

// notSoSecret returns the formatted and encoded []byte of the salt + cost. This should be the
// only selectable data from a database
func (p *hashed) notSoSecret() []byte {
	arr := make([]byte, 30)
	arr[0] = '$'
	arr[1] = p.major
	n := 2
	if p.minor != 0 {
		arr[2] = p.minor
		n = 3
	}
	arr[n] = '$'
	n++
	copy(arr[n:], []byte(fmt.Sprintf("%02d", p.cost)))
	n += 2
	arr[n] = '$'
	n++
	p.salt = base64Encode(p.salt)
	copy(arr[n:], p.salt)
	n += encodedSaltSize
	return arr[:n]
}

func (p *hashed) decodeVersion(hashedSecret *[]byte) error {
	if (*hashedSecret)[0] != '$' {
		return InvalidHashPrefixError((*hashedSecret)[0])
	}
	if (*hashedSecret)[1] > majorVersion {
		return HashVersionTooNewError((*hashedSecret)[1])
	}
	p.major = (*hashedSecret)[1]
	n := 3
	if (*hashedSecret)[2] != '$' {
		p.minor = (*hashedSecret)[2]
		n++
	}

	(*hashedSecret) = (*hashedSecret)[n:]

	return nil
}

func (p *hashed) decodeCost(hashedSecret *[]byte) (err error) {
	p.cost, err = strconv.Atoi(string((*hashedSecret)[0:2]))
	if err != nil {
		return
	}

	err = checkCost(p.cost)
	if err != nil {
		return
	}

	(*hashedSecret) = (*hashedSecret)[3:]
	return
}

func checkCost(cost int) error {
	if cost < MinCost || cost > MaxCost {
		return InvalidCostError(cost)
	}
	return nil
}

// DANGER! Make sure you have taken the correct precautions before using this function in
// productions. This function is made in order to safely split previously concatenated
// password hashes and secrets(salt and cost). This function should never be run twice on
// the same hash. Note that the returned hashed secret uses the standard base64 encoding.
func Reformat(hashedSecret []byte) (password_hash []byte, secret []byte, err error) {

	if len(hashedSecret) < minHashSize {
		err = ErrHashTooShort
		return
	}
	p := new(hashed)
	err = p.decodeVersion(&hashedSecret)
	if err != nil {
		return
	}
	if p.major != '2' {
		err = errors.New("error: this function must be conducted passwords hashed on major version 2")
		return
	}
	err = p.decodeCost(&hashedSecret)
	if err != nil {
		return
	}

	// Copy of passwordhash slice must be made to avoid the mutation from salt decoding.
	encodedPasswordHash := append([]byte(nil), hashedSecret[encodedSaltSize:]...)

	// Only decode the salt since it is encoded in the hash() function
	p.salt, err = legacyDecoder(hashedSecret[:encodedSaltSize])
	if err != nil {
		return
	}

	p.major = majorVersion
	p.minor = minorVersion

	password_hash, err = reEncodeFromLegacy(encodedPasswordHash)
	if err != nil {
		return
	}

	secret = p.notSoSecret()
	return
}
