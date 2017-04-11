// Package knownhosts implements a full-fledged parser for the
// OpenSSH's known_hosts host key database.
package knownhosts

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// See the sshd manpage for background.

type addr struct{ host, port string }

func (a *addr) String() string {
	return a.host + ":" + a.port
}

func (a *addr) eq(b addr) bool {
	return a.host == b.host && a.port == b.port
}

type hostPattern struct {
	negate bool
	addr   addr
}

func (p *hostPattern) String() string {
	n := ""
	if p.negate {
		n = "!"
	}

	return n + p.addr.String()
}

func (l *hostPattern) match(a addr) bool {
	if strings.Contains(l.addr.host, "?") || strings.Contains(l.addr.host, "*") {
		panic("wildcards not implemented.")
	}
	return l.addr.eq(a)
}

type keyDBLine struct {
	cert     bool
	patterns []*hostPattern
	key      ssh.PublicKey
}

func (l *keyDBLine) String() string {
	c := ""
	if l.cert {
		c = markerCert + " "
	}

	var ss []string
	for _, p := range l.patterns {
		ss = append(ss, p.String())
	}

	return c + strings.Join(ss, ",") + " " + serialize(l.key)
}

func serialize(k ssh.PublicKey) string {
	return k.Type() + " " + base64.StdEncoding.EncodeToString(k.Marshal())
}

func (l *keyDBLine) match(addrs []addr) bool {
	matched := false
	for _, p := range l.patterns {
		for _, a := range addrs {
			m := p.match(a)
			if p.negate {
				if m {
					return false
				} else {
					continue
				}
			}

			if m {
				matched = true
			}
		}
	}

	return matched
}

type hostKeyDB struct {
	// Serialized version of revoked keys
	revoked map[string]ssh.PublicKey
	lines   []keyDBLine
}

func (db *hostKeyDB) String() string {
	var ls []string
	for _, k := range db.revoked {
		ls = append(ls, markerRevoked+" * "+serialize(k))
	}
	for _, l := range db.lines {
		ls = append(ls, l.String())
	}
	return strings.Join(ls, "\n")
}

func newHostKeyDB() *hostKeyDB {
	db := &hostKeyDB{
		revoked: make(map[string]ssh.PublicKey),
	}

	return db
}

func keyEq(a, b ssh.PublicKey) bool {
	return bytes.Equal(a.Marshal(), b.Marshal())
}

// IsAuthority can be used as a callback in ssh.CertChecker
func (db *hostKeyDB) IsAuthority(auth ssh.PublicKey) bool {
	for _, l := range db.lines {
		// TODO(hanwen): should we check the hostname against host pattern?
		if l.cert && keyEq(l.key, auth) {
			return true
		}
	}
	return false
}

// IsRevoked can be used as a callback in ssh.CertChecker
func (db *hostKeyDB) IsRevoked(key *ssh.Certificate) bool {
	_, ok := db.revoked[string(key.Marshal())]
	return ok
}

const markerCert = "@cert-authority"
const markerRevoked = "@revoked"

func parseLine(line []byte) (marker string, pattern []string, key ssh.PublicKey, err error) {
	for _, m := range []string{markerCert, markerRevoked} {
		if trim := bytes.TrimPrefix(line, []byte(m)); len(trim) != len(line) {
			marker = m
			line = bytes.TrimSpace(trim)
		}
	}

	if i := bytes.IndexAny(line, "\t "); i == -1 {
		return "", nil, nil, fmt.Errorf("knownhosts: missing host pattern")
	} else {
		hostPart := string(line[:i])
		if len(hostPart) > 0 && hostPart[0] == '|' {
			return "", nil, nil, fmt.Errorf("knownhosts: hashed hostnames not implemented")
		}

		pattern = strings.Split(hostPart, ",")
		line = bytes.TrimSpace(line[i:])
	}

	if i := bytes.IndexAny(line, "\t "); i == -1 {
		return "", nil, nil, fmt.Errorf("knownhosts: missing key type pattern")
	} else {
		line = bytes.TrimSpace(line[i:])
	}

	if i := bytes.IndexAny(line, "\t "); i != -1 {
		line = bytes.TrimSpace(line[:i])
	}

	keyBytes, err := base64.StdEncoding.DecodeString(string(line))
	if err != nil {
		return "", nil, nil, err
	}
	key, err = ssh.ParsePublicKey(keyBytes)
	if err != nil {
		return "", nil, nil, err
	}

	return marker, pattern, key, nil
}

func (db *hostKeyDB) parseLine(line []byte) error {
	marker, patterns, key, err := parseLine(line)
	if err != nil {
		return err
	}

	if marker == markerRevoked {
		db.revoked[string(key.Marshal())] = key
		return nil
	}

	entry := keyDBLine{
		cert: marker == markerCert,
		key:  key,
	}
	for _, p := range patterns {
		if len(p) == 0 {
			continue
		}

		var a addr
		var negate bool
		if p[0] == '!' {
			negate = true
			p = p[1:]
		}

		if p[0] == '[' {
			a.host, a.port, err = net.SplitHostPort(p)
			if err != nil {
				return err
			}
		} else {
			a.host, a.port, err = net.SplitHostPort(p)
			if err != nil {
				a.host = p
				a.port = "22"
			}
		}

		if strings.Contains(a.host, "?") || strings.Contains(a.host, "*") {
			// TODO(hanwen): implement wildcards.
			return fmt.Errorf("knownhosts: wildcards not implemented.")
		}

		entry.patterns = append(entry.patterns, &hostPattern{
			negate: negate,
			addr:   a,
		})
	}

	db.lines = append(db.lines, entry)
	return nil
}

// KeyError is returned if we did not find the key in the host key
// database, or there was a mismatch.  Typically, in batch
// applications, this should be interpreted as failure. Interactive
// applications can offer an interactive prompt to the user.
type KeyError struct {
	// Want holds the accepted host keys. For each key algorithm,
	// there can be one hostkey.  If Want is empty, the host is
	// unknown. If Want is non-empty, there was a mismatch, which
	// can signify a MITM attack.
	Want []ssh.PublicKey

	// maybe line number + filename?
}

func (u *KeyError) Error() string {
	if len(u.Want) == 0 {
		return "knownhosts: key is unknown"
	}
	return "knownhosts: key mismatch"
}

// KeyRevoked is returned if we found a key that was revoked.
type KeyRevoked struct {
	// maybe line number + filename?
}

func (r *KeyRevoked) Error() string {
	return "knownhosts: key is revoked"
}

// check checks a key against the host database. This should not be
// used for verifying certificates.
func (db *hostKeyDB) check(address string, remote net.Addr, key ssh.PublicKey) error {
	if _, ok := db.revoked[string(key.Marshal())]; ok {
		return &KeyRevoked{}
	}

	host, port, err := net.SplitHostPort(remote.String())
	if err != nil {
		return fmt.Errorf("SplitHostPort(%s): %v", remote, err)
	}

	addrs := []addr{
		{host, port},
	}

	if address != "" {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("SplitHostPort(%s): %v", address, err)
		}

		addrs = append(addrs, addr{host, port})
	}

	return db.checkAddrs(addrs, key)
}

// checkAddrs checks if we can find the given public key for any of
// the given addresses.  If we only find an entry for the IP address,
// or only the hostname, then this still succeeds. (NOSUBMIT: are
// these the right semantics? What if there is just a key for the IP
// address, but not for the hostname?)
func (db *hostKeyDB) checkAddrs(addrs []addr, key ssh.PublicKey) error {
	// Algorithm => key.
	knownKeys := map[string]ssh.PublicKey{}
	for _, l := range db.lines {
		if l.match(addrs) {
			if _, ok := knownKeys[l.key.Type()]; !ok {
				knownKeys[l.key.Type()] = key
			}
		}
	}

	keyErr := &KeyError{}

	for _, v := range knownKeys {
		keyErr.Want = append(keyErr.Want, v)
	}

	// Unknown remote host.
	if len(knownKeys) == 0 {
		return keyErr
	}

	// If the remote host starts using a different, unknown key type, we
	// also interpret that as a mismatch.
	if known := knownKeys[key.Type()]; known == nil || !keyEq(known, key) {
		return keyErr
	}

	return nil
}

func (db *hostKeyDB) Read(r io.Reader) error {
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Bytes()
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		if err := db.parseLine(line); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// New creates a host key callback from the given OpenSSH host key
// files. The returned callback is for use in
// ssh.ClientConfig.HostKeyCallback. Hostnames are ignored for
// certificates, ie. any certificate authority is assumed to be valid
// for all remote hosts. Wildcards and hashed hostnames are
// not supported.
func New(files ...string) (ssh.HostKeyCallback, error) {
	db := newHostKeyDB()
	for _, f := range files {
		f, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if err := db.Read(f); err != nil {
			return nil, err
		}
	}

	// TODO(hanwen): properly supporting certificates requires an
	// API change in the SSH library: IsAuthority should provide
	// the address too?

	var certChecker ssh.CertChecker
	certChecker.IsAuthority = db.IsAuthority
	certChecker.IsRevoked = db.IsRevoked
	certChecker.HostKeyFallback = db.check

	return certChecker.CheckHostKey, nil
}

// Line returns a line to add append to the known_hosts files.
func Line(addresses []string, key ssh.PublicKey) string {
	var trimmed []string
	for _, a := range addresses {
		host, port, err := net.SplitHostPort(a)
		if err != nil {
			host = a
			port = "22"
		}

		entry := host
		if port != "22" {
			entry = "[" + entry + "]:" + port
		}

		trimmed = append(trimmed, entry)
	}

	return strings.Join(trimmed, ",") + " " + serialize(key)
}
