// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"

	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// Supported ciphers. Ciphers based on AES CBC and RC4 are no longer considered
// secure.
const (
	CipherAlgoAES128GCM        = "aes128-gcm@openssh.com"
	CipherAlgoAES256GCM        = "aes256-gcm@openssh.com"
	CipherAlgoChacha20Poly1305 = "chacha20-poly1305@openssh.com"
	CipherAlgoAES128CTR        = "aes128-ctr"
	CipherAlgoAES192CTR        = "aes192-ctr"
	CipherAlgoAES256CTR        = "aes256-ctr"
	CipherAlgoAES128CBC        = "aes128-cbc"
	CipherAlgoTripleDESCBC     = "3des-cbc"
	CipherAlgoRC4              = "arcfour"
	CipherAlgoRC4128           = "arcfour128"
	CipherAlgoRC4256           = "arcfour256"
)

// Supported key exchanges algorithms. SHA-1 based KEXs are no longer considered
// secure.
const (
	KexAlgoDH1SHA1    = "diffie-hellman-group1-sha1"
	KexAlgoDH14SHA1   = "diffie-hellman-group14-sha1"
	KexAlgoDH14SHA256 = "diffie-hellman-group14-sha256"
	KexAlgoDH16SHA512 = "diffie-hellman-group16-sha512"
	KexAlgoECDH256    = "ecdh-sha2-nistp256"
	KexAlgoECDH384    = "ecdh-sha2-nistp384"
	KexAlgoECDH521    = "ecdh-sha2-nistp521"
	// This KEX enables both curve25519-sha256 and curve25519-sha256@libssh.org
	KexAlgoCurve25519SHA256       = "curve25519-sha256"
	kexAlgoCurve25519SHA256LibSSH = "curve25519-sha256@libssh.org"
	KexAlgoDHGEXSHA1              = "diffie-hellman-group-exchange-sha1"
	KexAlgoDHGEXSHA256            = "diffie-hellman-group-exchange-sha256"
)

// Supported message authentication code (MAC) algorithms. SHA-1 based MACs are
// no longer considered secure.
const (
	MACAlgoHMACSHA256ETM = "hmac-sha2-256-etm@openssh.com"
	MACAlgoHMACSHA512ETM = "hmac-sha2-512-etm@openssh.com"
	MACAlgoHMACSHA256    = "hmac-sha2-256"
	MACAlgoHMACSHA512    = "hmac-sha2-512"
	MACAlgoHMACSHA1      = "hmac-sha1"
	MACAlgoHMACSHA196    = "hmac-sha1-96"
)

// Supported compression algorithms.
const (
	CompressionNone = "none"
)

var (
	supportedCompressions = []string{CompressionNone}
	// supportedServerKexAlgos specifies server-side key-exchange algorithms
	// implemented by this package in preference order, excluding those with
	// security issues.
	supportedKexAlgos = []string{KexAlgoCurve25519SHA256,
		KexAlgoECDH256, KexAlgoECDH384, KexAlgoECDH521,
		KexAlgoDH14SHA256, KexAlgoDH16SHA512, KexAlgoDHGEXSHA256}
	preferredKexAlgos = []string{KexAlgoCurve25519SHA256,
		KexAlgoECDH256, KexAlgoECDH384, KexAlgoECDH521,
		KexAlgoDH14SHA256, KexAlgoDH14SHA1,
	}
	// supportedCiphers specifies cipher algorithms implemented by this package
	// in preference order, excluding those with security issues.
	supportedCiphers = []string{
		CipherAlgoAES128GCM, CipherAlgoAES256GCM,
		CipherAlgoChacha20Poly1305,
		CipherAlgoAES128CTR, CipherAlgoAES192CTR, CipherAlgoAES256CTR,
	}
	// supportedMACs specifies MAC algorithms implemented by this package in
	// preference order, excluding those with security issues.
	supportedMACs = []string{MACAlgoHMACSHA256ETM, MACAlgoHMACSHA512ETM,
		MACAlgoHMACSHA256, MACAlgoHMACSHA512,
	}
	// preferredMACs specifies the default preference for MAC algorithms in
	// preference order.
	preferredMACs = []string{MACAlgoHMACSHA256ETM, MACAlgoHMACSHA512ETM,
		MACAlgoHMACSHA256, MACAlgoHMACSHA512, MACAlgoHMACSHA196, MACAlgoHMACSHA1,
	}
	// supportedHostKeyAlgos specifies the supported host-key algorithms (i.e.
	// methods of authenticating servers) implemented by this package in
	// preference order, excluding those with security issues.
	supportedHostKeyAlgos = []string{
		CertAlgoRSASHA256v01, CertAlgoRSASHA512v01,
		CertAlgoECDSA256v01, CertAlgoECDSA384v01, CertAlgoECDSA521v01,
		CertAlgoED25519v01,

		KeyAlgoECDSA256, KeyAlgoECDSA384, KeyAlgoECDSA521,
		KeyAlgoRSASHA256, KeyAlgoRSASHA512,
		KeyAlgoED25519,
	}
	// preferredHostKeyAlgos specifies the default preference for host-key
	// algorithms in preference order.
	preferredHostKeyAlgos = []string{
		CertAlgoRSASHA256v01, CertAlgoRSASHA512v01,
		CertAlgoRSAv01, CertAlgoDSAv01, CertAlgoECDSA256v01,
		CertAlgoECDSA384v01, CertAlgoECDSA521v01, CertAlgoED25519v01,

		KeyAlgoECDSA256, KeyAlgoECDSA384, KeyAlgoECDSA521,
		KeyAlgoRSASHA256, KeyAlgoRSASHA512,
		KeyAlgoRSA, KeyAlgoDSA,

		KeyAlgoED25519,
	}
	// supportedPubKeyAuthAlgos specifies the supported client public key
	// authentication algorithms. Note that this doesn't include certificate
	// types since those use the underlying algorithm. Order is irrelevant.
	supportedPubKeyAuthAlgos = []string{
		KeyAlgoED25519,
		KeyAlgoSKED25519, KeyAlgoSKECDSA256,
		KeyAlgoECDSA256, KeyAlgoECDSA384, KeyAlgoECDSA521,
		KeyAlgoRSASHA256, KeyAlgoRSASHA512,
	}

	// preferredPubKeyAuthAlgos specifies the preferred client public key
	// authentication algorithms. This list is sent to the client if it supports
	// the server-sig-algs extension. Order is irrelevant.
	preferredPubKeyAuthAlgos = []string{
		KeyAlgoED25519,
		KeyAlgoSKED25519, KeyAlgoSKECDSA256,
		KeyAlgoECDSA256, KeyAlgoECDSA384, KeyAlgoECDSA521,
		KeyAlgoRSASHA256, KeyAlgoRSASHA512, KeyAlgoRSA,
		KeyAlgoDSA,
	}

	preferredPubKeyAuthAlgosList = strings.Join(preferredPubKeyAuthAlgos, ",")
)

// These are string constants in the SSH protocol.
const (
	serviceUserAuth = "ssh-userauth"
	serviceSSH      = "ssh-connection"
)

// Algorithms defines the algorithms for an SSH connection.
type Algorithms struct {
	KEXs         []string
	Ciphers      []string
	MACs         []string
	HostKeys     []string
	PublicKeys   []string
	Compressions []string
}

// SupportedAlgorithms returns algorithms currently implemented by this package,
// excluding those with security issues, which are returned by
// InsecureAlgorithms. The algorithms listed here are in preference order.
// Please note that the algorithms used by default may not match these ones for
// backward compatibility reasons.
func SupportedAlgorithms() Algorithms {
	return Algorithms{
		Ciphers:      supportedCiphers,
		MACs:         supportedMACs,
		KEXs:         supportedKexAlgos,
		HostKeys:     supportedHostKeyAlgos,
		PublicKeys:   supportedPubKeyAuthAlgos,
		Compressions: supportedCompressions,
	}
}

// InsecureAlgorithms returns algorithms currently implemented by this package
// and which have security issues.
func InsecureAlgorithms() Algorithms {
	return Algorithms{
		KEXs: []string{KexAlgoDH14SHA1, KexAlgoDH1SHA1, KexAlgoDHGEXSHA1},
		Ciphers: []string{
			CipherAlgoAES128CBC,
			CipherAlgoTripleDESCBC,
			CipherAlgoRC4256, CipherAlgoRC4128, CipherAlgoRC4,
		},
		MACs:         []string{MACAlgoHMACSHA196, MACAlgoHMACSHA1},
		HostKeys:     []string{CertAlgoRSAv01, CertAlgoDSAv01, KeyAlgoRSA, KeyAlgoDSA},
		PublicKeys:   []string{KeyAlgoRSA, KeyAlgoDSA},
		Compressions: nil,
	}
}

// serverForbiddenKexAlgos contains key exchange algorithms, that are forbidden
// for the server half.
var serverForbiddenKexAlgos = map[string]struct{}{
	KexAlgoDHGEXSHA1:   {}, // server half implementation is only minimal to satisfy the automated tests
	KexAlgoDHGEXSHA256: {}, // server half implementation is only minimal to satisfy the automated tests
}

// hashFuncs keeps the mapping of supported signature algorithms to their
// respective hashes needed for signing and verification.
var hashFuncs = map[string]crypto.Hash{
	KeyAlgoRSA:       crypto.SHA1,
	KeyAlgoRSASHA256: crypto.SHA256,
	KeyAlgoRSASHA512: crypto.SHA512,
	KeyAlgoDSA:       crypto.SHA1,
	KeyAlgoECDSA256:  crypto.SHA256,
	KeyAlgoECDSA384:  crypto.SHA384,
	KeyAlgoECDSA521:  crypto.SHA512,
	// KeyAlgoED25519 doesn't pre-hash.
	KeyAlgoSKECDSA256: crypto.SHA256,
	KeyAlgoSKED25519:  crypto.SHA256,
}

// algorithmsForKeyFormat returns the supported signature algorithms for a given
// public key format (PublicKey.Type), in order of preference. See RFC 8332,
// Section 2. See also the note in sendKexInit on backwards compatibility.
func algorithmsForKeyFormat(keyFormat string) []string {
	switch keyFormat {
	case KeyAlgoRSA:
		return []string{KeyAlgoRSASHA256, KeyAlgoRSASHA512, KeyAlgoRSA}
	case CertAlgoRSAv01:
		return []string{CertAlgoRSASHA256v01, CertAlgoRSASHA512v01, CertAlgoRSAv01}
	default:
		return []string{keyFormat}
	}
}

// isRSA returns whether algo is a supported RSA algorithm, including certificate
// algorithms.
func isRSA(algo string) bool {
	algos := algorithmsForKeyFormat(KeyAlgoRSA)
	return contains(algos, underlyingAlgo(algo))
}

// unexpectedMessageError results when the SSH message that we received didn't
// match what we wanted.
func unexpectedMessageError(expected, got uint8) error {
	return fmt.Errorf("ssh: unexpected message type %d (expected %d)", got, expected)
}

// parseError results from a malformed SSH message.
func parseError(tag uint8) error {
	return fmt.Errorf("ssh: parse error in message type %d", tag)
}

func findCommon(what string, client []string, server []string) (common string, err error) {
	for _, c := range client {
		for _, s := range server {
			if c == s {
				return c, nil
			}
		}
	}
	return "", fmt.Errorf("ssh: no common algorithm for %s; client offered: %v, server offered: %v", what, client, server)
}

// directionAlgorithms records algorithm choices in one direction (either read or write)
type directionAlgorithms struct {
	Cipher      string
	MAC         string
	Compression string
}

// rekeyBytes returns a rekeying intervals in bytes.
func (a *directionAlgorithms) rekeyBytes() int64 {
	// According to RFC 4344 block ciphers should rekey after
	// 2^(BLOCKSIZE/4) blocks. For all AES flavors BLOCKSIZE is
	// 128.
	switch a.Cipher {
	case CipherAlgoAES128CTR, CipherAlgoAES192CTR, CipherAlgoAES256CTR, CipherAlgoAES128GCM, CipherAlgoAES256GCM, CipherAlgoAES128CBC:
		return 16 * (1 << 32)

	}

	// For others, stick with RFC 4253 recommendation to rekey after 1 Gb of data.
	return 1 << 30
}

var aeadCiphers = map[string]bool{
	CipherAlgoAES128GCM:        true,
	CipherAlgoAES256GCM:        true,
	CipherAlgoChacha20Poly1305: true,
}

type algorithms struct {
	kex     string
	hostKey string
	w       directionAlgorithms
	r       directionAlgorithms
}

func findAgreedAlgorithms(isClient bool, clientKexInit, serverKexInit *kexInitMsg) (algs *algorithms, err error) {
	result := &algorithms{}

	result.kex, err = findCommon("key exchange", clientKexInit.KexAlgos, serverKexInit.KexAlgos)
	if err != nil {
		return
	}

	result.hostKey, err = findCommon("host key", clientKexInit.ServerHostKeyAlgos, serverKexInit.ServerHostKeyAlgos)
	if err != nil {
		return
	}

	stoc, ctos := &result.w, &result.r
	if isClient {
		ctos, stoc = stoc, ctos
	}

	ctos.Cipher, err = findCommon("client to server cipher", clientKexInit.CiphersClientServer, serverKexInit.CiphersClientServer)
	if err != nil {
		return
	}

	stoc.Cipher, err = findCommon("server to client cipher", clientKexInit.CiphersServerClient, serverKexInit.CiphersServerClient)
	if err != nil {
		return
	}

	if !aeadCiphers[ctos.Cipher] {
		ctos.MAC, err = findCommon("client to server MAC", clientKexInit.MACsClientServer, serverKexInit.MACsClientServer)
		if err != nil {
			return
		}
	}

	if !aeadCiphers[stoc.Cipher] {
		stoc.MAC, err = findCommon("server to client MAC", clientKexInit.MACsServerClient, serverKexInit.MACsServerClient)
		if err != nil {
			return
		}
	}

	ctos.Compression, err = findCommon("client to server compression", clientKexInit.CompressionClientServer, serverKexInit.CompressionClientServer)
	if err != nil {
		return
	}

	stoc.Compression, err = findCommon("server to client compression", clientKexInit.CompressionServerClient, serverKexInit.CompressionServerClient)
	if err != nil {
		return
	}

	return result, nil
}

// If rekeythreshold is too small, we can't make any progress sending
// stuff.
const minRekeyThreshold uint64 = 256

// Config contains configuration data common to both ServerConfig and
// ClientConfig.
type Config struct {
	// Rand provides the source of entropy for cryptographic
	// primitives. If Rand is nil, the cryptographic random reader
	// in package crypto/rand will be used.
	Rand io.Reader

	// The maximum number of bytes sent or received after which a
	// new key is negotiated. It must be at least 256. If
	// unspecified, a size suitable for the chosen cipher is used.
	RekeyThreshold uint64

	// The allowed key exchanges algorithms. If unspecified then a default set
	// of algorithms is used. Unsupported values are silently ignored.
	KeyExchanges []string

	// The allowed cipher algorithms. If unspecified then a sensible default is
	// used. Unsupported values are silently ignored.
	Ciphers []string

	// The allowed MAC algorithms. If unspecified then a sensible default is
	// used. Unsupported values are silently ignored.
	MACs []string
}

// SetDefaults sets sensible values for unset fields in config. This is
// exported for testing: Configs passed to SSH functions are copied and have
// default values set automatically.
func (c *Config) SetDefaults() {
	if c.Rand == nil {
		c.Rand = rand.Reader
	}
	if c.Ciphers == nil {
		c.Ciphers = supportedCiphers
	}
	var ciphers []string
	for _, c := range c.Ciphers {
		if cipherModes[c] != nil {
			// Ignore the cipher if we have no cipherModes definition.
			ciphers = append(ciphers, c)
		}
	}
	c.Ciphers = ciphers

	if c.KeyExchanges == nil {
		c.KeyExchanges = preferredKexAlgos
	}
	if contains(c.KeyExchanges, KexAlgoCurve25519SHA256) && !contains(c.KeyExchanges, kexAlgoCurve25519SHA256LibSSH) {
		c.KeyExchanges = append(c.KeyExchanges, kexAlgoCurve25519SHA256LibSSH)
	}
	var kexs []string
	for _, k := range c.KeyExchanges {
		if kexAlgoMap[k] != nil {
			// Ignore the KEX if we have no kexAlgoMap definition.
			kexs = append(kexs, k)
		}
	}
	c.KeyExchanges = kexs

	if c.MACs == nil {
		c.MACs = preferredMACs
	}
	var macs []string
	for _, m := range c.MACs {
		if macModes[m] != nil {
			// Ignore the MAC if we have no macModes definition.
			macs = append(macs, m)
		}
	}
	c.MACs = macs

	if c.RekeyThreshold == 0 {
		// cipher specific default
	} else if c.RekeyThreshold < minRekeyThreshold {
		c.RekeyThreshold = minRekeyThreshold
	} else if c.RekeyThreshold >= math.MaxInt64 {
		// Avoid weirdness if somebody uses -1 as a threshold.
		c.RekeyThreshold = math.MaxInt64
	}
}

// buildDataSignedForAuth returns the data that is signed in order to prove
// possession of a private key. See RFC 4252, section 7. algo is the advertised
// algorithm, and may be a certificate type.
func buildDataSignedForAuth(sessionID []byte, req userAuthRequestMsg, algo string, pubKey []byte) []byte {
	data := struct {
		Session []byte
		Type    byte
		User    string
		Service string
		Method  string
		Sign    bool
		Algo    string
		PubKey  []byte
	}{
		sessionID,
		msgUserAuthRequest,
		req.User,
		req.Service,
		req.Method,
		true,
		algo,
		pubKey,
	}
	return Marshal(data)
}

func appendU16(buf []byte, n uint16) []byte {
	return append(buf, byte(n>>8), byte(n))
}

func appendU32(buf []byte, n uint32) []byte {
	return append(buf, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func appendU64(buf []byte, n uint64) []byte {
	return append(buf,
		byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
		byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func appendInt(buf []byte, n int) []byte {
	return appendU32(buf, uint32(n))
}

func appendString(buf []byte, s string) []byte {
	buf = appendU32(buf, uint32(len(s)))
	buf = append(buf, s...)
	return buf
}

func appendBool(buf []byte, b bool) []byte {
	if b {
		return append(buf, 1)
	}
	return append(buf, 0)
}

// newCond is a helper to hide the fact that there is no usable zero
// value for sync.Cond.
func newCond() *sync.Cond { return sync.NewCond(new(sync.Mutex)) }

// window represents the buffer available to clients
// wishing to write to a channel.
type window struct {
	*sync.Cond
	win          uint32 // RFC 4254 5.2 says the window size can grow to 2^32-1
	writeWaiters int
	closed       bool
}

// add adds win to the amount of window available
// for consumers.
func (w *window) add(win uint32) bool {
	// a zero sized window adjust is a noop.
	if win == 0 {
		return true
	}
	w.L.Lock()
	if w.win+win < win {
		w.L.Unlock()
		return false
	}
	w.win += win
	// It is unusual that multiple goroutines would be attempting to reserve
	// window space, but not guaranteed. Use broadcast to notify all waiters
	// that additional window is available.
	w.Broadcast()
	w.L.Unlock()
	return true
}

// close sets the window to closed, so all reservations fail
// immediately.
func (w *window) close() {
	w.L.Lock()
	w.closed = true
	w.Broadcast()
	w.L.Unlock()
}

// reserve reserves win from the available window capacity.
// If no capacity remains, reserve will block. reserve may
// return less than requested.
func (w *window) reserve(win uint32) (uint32, error) {
	var err error
	w.L.Lock()
	w.writeWaiters++
	w.Broadcast()
	for w.win == 0 && !w.closed {
		w.Wait()
	}
	w.writeWaiters--
	if w.win < win {
		win = w.win
	}
	w.win -= win
	if w.closed {
		err = io.EOF
	}
	w.L.Unlock()
	return win, err
}

// waitWriterBlocked waits until some goroutine is blocked for further
// writes. It is used in tests only.
func (w *window) waitWriterBlocked() {
	w.Cond.L.Lock()
	for w.writeWaiters == 0 {
		w.Cond.Wait()
	}
	w.Cond.L.Unlock()
}
