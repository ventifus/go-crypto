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
	"slices"
	"sync"

	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"

	"golang.org/x/crypto/ssh/internal/fips"
)

// These are string constants in the SSH protocol.
const (
	compressionNone = "none"
	serviceUserAuth = "ssh-userauth"
	serviceSSH      = "ssh-connection"
)

// Implemented ciphers algorithms.
const (
	CipherAES128GCM            = "aes128-gcm@openssh.com"
	CipherAES256GCM            = "aes256-gcm@openssh.com"
	CipherChacha20Poly1305     = "chacha20-poly1305@openssh.com"
	CipherAES128CTR            = "aes128-ctr"
	CipherAES192CTR            = "aes192-ctr"
	CipherAES256CTR            = "aes256-ctr"
	InsecureCipherAES128CBC    = "aes128-cbc"
	InsecureCipherTripleDESCBC = "3des-cbc"
	InsecureCipherRC4          = "arcfour"
	InsecureCipherRC4128       = "arcfour128"
	InsecureCipherRC4256       = "arcfour256"
)

// Implemented key exchanges algorithms.
const (
	InsecureKeyExchangeDH1SHA1   = "diffie-hellman-group1-sha1"
	InsecureKeyExchangeDH14SHA1  = "diffie-hellman-group14-sha1"
	KeyExchangeDH14SHA256        = "diffie-hellman-group14-sha256"
	KeyExchangeDH16SHA512        = "diffie-hellman-group16-sha512"
	KeyExchangeECDHP256          = "ecdh-sha2-nistp256"
	KeyExchangeECDHP384          = "ecdh-sha2-nistp384"
	KeyExchangeECDHP521          = "ecdh-sha2-nistp521"
	KeyExchangeCurve25519SHA256  = "curve25519-sha256"
	InsecureKeyExchangeDHGEXSHA1 = "diffie-hellman-group-exchange-sha1"
	KeyExchangeDHGEXSHA256       = "diffie-hellman-group-exchange-sha256"
	// The key exchange algorithm mlkem768x25519-sha256 is supported starting
	// from Go version 1.24.
	KeyExchangeMLKEM768X25519SHA256 = "mlkem768x25519-sha256"

	// An alias for KeyExchangeCurve25519SHA256. This kex ID will be added if
	// KeyExchangeCurve25519SHA256 is requested for backward compatibility with
	// OpenSSH versions up to 7.2.
	keyExchangeCurve25519SHA256LibSSH = "curve25519-sha256@libssh.org"
)

// Implemented message authentication code (MAC) algorithms.
const (
	HMACSHA256ETM      = "hmac-sha2-256-etm@openssh.com"
	HMACSHA512ETM      = "hmac-sha2-512-etm@openssh.com"
	HMACSHA256         = "hmac-sha2-256"
	HMACSHA512         = "hmac-sha2-512"
	InsecureHMACSHA1   = "hmac-sha1"
	InsecureHMACSHA196 = "hmac-sha1-96"
)

var (
	// supportedKexAlgos specifies key-exchange algorithms implemented by this
	// package in preference order, excluding those with security issues.
	supportedKexAlgos = []string{KeyExchangeCurve25519SHA256,
		KeyExchangeECDHP256, KeyExchangeECDHP384, KeyExchangeECDHP521,
		KeyExchangeDH14SHA256, KeyExchangeDH16SHA512, KeyExchangeDHGEXSHA256}
	// preferredKexAlgos specifies the default preference for key-exchange
	// algorithms in preference order.
	preferredKexAlgos = []string{KeyExchangeCurve25519SHA256,
		KeyExchangeECDHP256, KeyExchangeECDHP384, KeyExchangeECDHP521,
		KeyExchangeDH14SHA256, InsecureKeyExchangeDH14SHA1,
	}
	// insecureKexAlgos specifies key-exchange algorithms implemented by this
	// package and which have security issues.
	insecureKexAlgos = []string{InsecureKeyExchangeDH14SHA1, InsecureKeyExchangeDH1SHA1,
		InsecureKeyExchangeDHGEXSHA1}
	// fipsKexAlgos specifies FIPS approved key-exchange algorithms implemented
	// by this package.
	fipsKexAlgos = []string{KeyExchangeECDHP256, KeyExchangeECDHP384}
	// supportedCiphers specifies cipher algorithms implemented by this package
	// in preference order, excluding those with security issues.
	supportedCiphers = []string{
		CipherAES128GCM, CipherAES256GCM,
		CipherChacha20Poly1305,
		CipherAES128CTR, CipherAES192CTR, CipherAES256CTR,
	}
	// preferredCiphers specifies the default preference for ciphers algorithms
	// in preference order.
	preferredCiphers = supportedCiphers
	// insecureCiphers specifies cipher algorithms implemented by this
	// package and which have security issues.
	insecureCiphers = []string{InsecureCipherAES128CBC,
		InsecureCipherTripleDESCBC,
		InsecureCipherRC4256, InsecureCipherRC4128, InsecureCipherRC4,
	}
	// fipsCiphers specifies FIPS approved cipher algorithms implemented by this
	// package.
	fipsCiphers = []string{
		CipherAES128GCM, CipherAES256GCM,
		CipherAES128CTR, CipherAES192CTR, CipherAES256CTR,
	}
	// supportedMACs specifies MAC algorithms implemented by this package in
	// preference order, excluding those with security issues.
	supportedMACs = []string{HMACSHA256ETM, HMACSHA512ETM,
		HMACSHA256, HMACSHA512,
	}
	// preferredMACs specifies the default preference for MAC algorithms in
	// preference order.
	preferredMACs = []string{HMACSHA256ETM, HMACSHA512ETM,
		HMACSHA256, HMACSHA512, InsecureHMACSHA1, InsecureHMACSHA196,
	}
	// insecureMACs specifies MAC algorithms implemented by this
	// package and which have security issues.
	insecureMACs = []string{InsecureHMACSHA196, InsecureHMACSHA1}
	// fipsMACs specifies FIPS approved MAC algorithms implemented by this
	// package.
	fipsMACs = []string{HMACSHA256ETM, HMACSHA512ETM,
		HMACSHA256, HMACSHA512,
	}
	// supportedHostKeyAlgos specifies the supported host-key algorithms (i.e.
	// methods of authenticating servers) implemented by this package in
	// preference order, excluding those with security issues.
	supportedHostKeyAlgos = []string{
		CertAlgoRSASHA256v01, CertAlgoRSASHA512v01,
		CertAlgoECDSA256v01, CertAlgoECDSA384v01, CertAlgoECDSA521v01,
		CertAlgoED25519v01,

		KeyAlgoRSASHA256, KeyAlgoRSASHA512,
		KeyAlgoECDSA256, KeyAlgoECDSA384, KeyAlgoECDSA521,
		KeyAlgoED25519,
	}
	// preferredHostKeyAlgos specifies the default preference for host-key
	// algorithms in preference order.
	preferredHostKeyAlgos = []string{
		CertAlgoRSASHA256v01, CertAlgoRSASHA512v01,
		CertAlgoRSAv01, InsecureCertAlgoDSAv01, CertAlgoECDSA256v01,
		CertAlgoECDSA384v01, CertAlgoECDSA521v01, CertAlgoED25519v01,

		KeyAlgoECDSA256, KeyAlgoECDSA384, KeyAlgoECDSA521,
		KeyAlgoRSASHA256, KeyAlgoRSASHA512,
		KeyAlgoRSA, InsecureKeyAlgoDSA,

		KeyAlgoED25519,
	}
	// insecureHostKeyAlgos specifies host-key algorithms implemented by this
	// package and which have security issues.
	insecureHostKeyAlgos = []string{KeyAlgoRSA, InsecureKeyAlgoDSA,
		CertAlgoRSAv01, InsecureCertAlgoDSAv01,
	}
	// fipsHostKeyAlgos specifies FIPS approved host-key algorithms implemented
	// by this package.
	fipsHostKeyAlgos = []string{
		CertAlgoRSASHA256v01, CertAlgoRSASHA512v01,
		CertAlgoECDSA256v01, CertAlgoECDSA384v01,

		KeyAlgoECDSA256, KeyAlgoECDSA384,
		KeyAlgoRSASHA256, KeyAlgoRSASHA512,
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
		InsecureKeyAlgoDSA,
	}
	// insecurePubKeyAuthAlgos specifies client public key authentication
	// algorithms implemented by this package and which have security issues.
	insecurePubKeyAuthAlgos = []string{KeyAlgoRSA, InsecureKeyAlgoDSA}
	// fipsPubKeyAuthAlgos specifies FIPS approved public key authentication
	// algorithms implemented by this package.
	fipsPubKeyAuthAlgos = []string{
		KeyAlgoECDSA256, KeyAlgoECDSA384,
		KeyAlgoRSASHA256, KeyAlgoRSASHA512,
	}
)

// NegotiatedAlgorithms defines algorithms negotiated between client and server.
type NegotiatedAlgorithms struct {
	KeyExchange string
	HostKey     string
	Read        DirectionAlgorithms
	Write       DirectionAlgorithms
}

// Algorithms defines a set of algorithms that can be configured in the client
// or server config for negotiation during a handshake.
type Algorithms struct {
	KeyExchanges   []string
	Ciphers        []string
	MACs           []string
	HostKeys       []string
	PublicKeyAuths []string
}

// isFIPSSupportedRSASize returns true if the specified size (in bits) is
// supported for RSA keys in FIPS mode.
func isFIPSSupportedRSASize(size int) bool {
	return size == 2048 || size == 3072 || size == 4096
}

// isFIPSSupportedECDSASize returns true if the specified size (in bits) is
// supported for ECDSA keys in FIPS mode.
func isFIPSSupportedECDSASize(size int) bool {
	return size == 256 || size == 384
}

// SupportedAlgorithms returns algorithms currently implemented by this package,
// excluding those with security issues, which are returned by
// InsecureAlgorithms. The algorithms listed here are in preference order.
func SupportedAlgorithms() Algorithms {
	if fips.Enabled {
		return Algorithms{
			Ciphers:        slices.Clone(fipsCiphers),
			MACs:           slices.Clone(fipsMACs),
			KeyExchanges:   slices.Clone(fipsKexAlgos),
			HostKeys:       slices.Clone(fipsHostKeyAlgos),
			PublicKeyAuths: slices.Clone(fipsPubKeyAuthAlgos),
		}
	}
	return Algorithms{
		Ciphers:        slices.Clone(supportedCiphers),
		MACs:           slices.Clone(supportedMACs),
		KeyExchanges:   slices.Clone(supportedKexAlgos),
		HostKeys:       slices.Clone(supportedHostKeyAlgos),
		PublicKeyAuths: slices.Clone(supportedPubKeyAuthAlgos),
	}
}

// InsecureAlgorithms returns algorithms currently implemented by this package
// and which have security issues.
func InsecureAlgorithms() Algorithms {
	if fips.Enabled {
		return Algorithms{}
	}
	return Algorithms{
		KeyExchanges:   slices.Clone(insecureKexAlgos),
		Ciphers:        slices.Clone(insecureCiphers),
		MACs:           slices.Clone(insecureMACs),
		HostKeys:       slices.Clone(insecureHostKeyAlgos),
		PublicKeyAuths: slices.Clone(insecurePubKeyAuthAlgos),
	}
}

func allAlgorithms() Algorithms {
	supported := SupportedAlgorithms()
	insecure := InsecureAlgorithms()

	return Algorithms{
		KeyExchanges:   append(supported.KeyExchanges, insecure.KeyExchanges...),
		Ciphers:        append(supported.Ciphers, insecure.Ciphers...),
		MACs:           append(supported.MACs, insecure.MACs...),
		HostKeys:       append(supported.HostKeys, insecure.HostKeys...),
		PublicKeyAuths: append(supported.PublicKeyAuths, insecure.PublicKeyAuths...),
	}
}

var supportedCompressions = []string{compressionNone}

// hashFuncs keeps the mapping of supported signature algorithms to their
// respective hashes needed for signing and verification.
var hashFuncs = map[string]crypto.Hash{
	KeyAlgoRSA:         crypto.SHA1,
	KeyAlgoRSASHA256:   crypto.SHA256,
	KeyAlgoRSASHA512:   crypto.SHA512,
	InsecureKeyAlgoDSA: crypto.SHA1,
	KeyAlgoECDSA256:    crypto.SHA256,
	KeyAlgoECDSA384:    crypto.SHA384,
	KeyAlgoECDSA521:    crypto.SHA512,
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

func isRSACert(algo string) bool {
	_, ok := certKeyAlgoNames[algo]
	if !ok {
		return false
	}
	return isRSA(algo)
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

// DirectionAlgorithms defines the algorithms negotiated in one direction
// (either read or write).
type DirectionAlgorithms struct {
	Cipher      string
	MAC         string
	compression string
}

// rekeyBytes returns a rekeying intervals in bytes.
func (a *DirectionAlgorithms) rekeyBytes() int64 {
	// According to RFC 4344 block ciphers should rekey after
	// 2^(BLOCKSIZE/4) blocks. For all AES flavors BLOCKSIZE is
	// 128.
	switch a.Cipher {
	case CipherAES128CTR, CipherAES192CTR, CipherAES256CTR, CipherAES128GCM, CipherAES256GCM, InsecureCipherAES128CBC:
		return 16 * (1 << 32)

	}

	// For others, stick with RFC 4253 recommendation to rekey after 1 Gb of data.
	return 1 << 30
}

var aeadCiphers = map[string]bool{
	CipherAES128GCM:        true,
	CipherAES256GCM:        true,
	CipherChacha20Poly1305: true,
}

func findAgreedAlgorithms(isClient bool, clientKexInit, serverKexInit *kexInitMsg) (algs *NegotiatedAlgorithms, err error) {
	result := &NegotiatedAlgorithms{}

	result.KeyExchange, err = findCommon("key exchange", clientKexInit.KexAlgos, serverKexInit.KexAlgos)
	if err != nil {
		return
	}

	result.HostKey, err = findCommon("host key", clientKexInit.ServerHostKeyAlgos, serverKexInit.ServerHostKeyAlgos)
	if err != nil {
		return
	}

	stoc, ctos := &result.Write, &result.Read
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

	ctos.compression, err = findCommon("client to server compression", clientKexInit.CompressionClientServer, serverKexInit.CompressionClientServer)
	if err != nil {
		return
	}

	stoc.compression, err = findCommon("server to client compression", clientKexInit.CompressionServerClient, serverKexInit.CompressionServerClient)
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
	algos := allAlgorithms()
	if c.Rand == nil {
		c.Rand = rand.Reader
	}
	if len(c.Ciphers) == 0 {
		if fips.Enabled {
			c.Ciphers = fipsCiphers
		} else {
			c.Ciphers = preferredCiphers
		}
	} else {
		var ciphers []string
		for _, c := range c.Ciphers {
			// Ignore unsupported ciphers.
			if contains(algos.Ciphers, c) {
				ciphers = append(ciphers, c)
			}
		}
		c.Ciphers = ciphers
	}

	if len(c.KeyExchanges) == 0 {
		if fips.Enabled {
			c.KeyExchanges = fipsKexAlgos
		} else {
			c.KeyExchanges = preferredKexAlgos
		}
	}
	var kexs []string
	hasKexCurve25519SHA256 := contains(algos.KeyExchanges, KeyExchangeCurve25519SHA256)
	for _, k := range c.KeyExchanges {
		// Ignore unsupported KEXs, we accept keyExchangeCurve25519SHA256LibSSH
		// if KeyExchangeCurve25519SHA256 is supported.
		if contains(algos.KeyExchanges, k) || (k == keyExchangeCurve25519SHA256LibSSH && hasKexCurve25519SHA256) {
			kexs = append(kexs, k)
			if k == KeyExchangeCurve25519SHA256 && !contains(c.KeyExchanges, keyExchangeCurve25519SHA256LibSSH) {
				kexs = append(kexs, keyExchangeCurve25519SHA256LibSSH)
			}
		}
	}
	c.KeyExchanges = kexs

	if len(c.MACs) == 0 {
		if fips.Enabled {
			c.MACs = fipsMACs
		} else {
			c.MACs = preferredMACs
		}
	} else {
		var macs []string
		for _, m := range c.MACs {
			// Ignore unsupported MACs.
			if contains(algos.MACs, m) {
				macs = append(macs, m)
			}
		}
		c.MACs = macs
	}

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
