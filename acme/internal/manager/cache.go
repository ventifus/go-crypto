package manager

import (
	"crypto/tls"
	"errors"
)

// Cache is used by Manager to store and retrieve previously obtained certificates.
type Cache interface {
	// Get returns a TLS certificate valid for the specified domain name.
	Get(name string) (tls.Certificate, error)

	// Put stores the TLS certificate in cache.
	// It's up to the implementations how much to store, as long as
	// the reverse result of Get is valid.
	Put(tls.Certificate) error
}

// NewDirCache creates a local disk cache using provided dir name as root.
func NewDirCache(name string) (Cache, error) {
	return nil, errors.New("not implemented")
}
