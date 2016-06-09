package manager

import "errors"

// Cache is used by Manager to store and retrieve its state.
type Cache interface {
	// Get returns a Manager instance from cache.
	Get() (*Manager, error)
	// Put stores a Manager instance in cache.
	Put(*Manager) error
}

// NewDirCache creates a local disk cache using provided dir name as root.
// If the name argument is empty, system default temporary directory is used.
func NewDirCache(name string) (Cache, error) {
	return nil, errors.New("not implemented")
}
