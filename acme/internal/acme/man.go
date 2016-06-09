package acme

import (
	"crypto/tls"
	"errors"
)

const letsEncryptURL = "https://acme-v01.api.letsencrypt.org/directory"

// Manager is a stateful certificates manager built on top of the Client.
// It obtains new and refreshes expiring certificates automatically,
// as well as providing them to a TLS server via tls.Config.
type Manager struct {
	client *Client
	disco  string
}

// NewManager initializes a Manager using the given client.
// The client.Key must not be nil and is expected to be registered with the CA.
// If the directory URL discoURL is empty, Let's Encrypt CA is used.
func NewManager(client *Client, discoURL string) *Manager {
	m := &Manager{
		client: client,
		disco:  discoURL,
		hosts:  make([]string, len(hosts)),
	}
	copy(m.hosts, hosts)
	strings.Sort(m.hosts)
	if m.disco == "" {
		m.disco = letsEncryptURL
	}
	return m
}

// Watch will call function f whenever m's state is changed.
// Caching m's state is a typical use case. For instance,
//
// 	func dump(m *Manager) {
//		b, err := m.MarshalBinary()
//		if err != nil {
//			log.Printf("dump: %v", err)
//			return
//		}
//		ioutil.WriteFile("cache.bin", b, 0600)
//	}
//	m.Watch(dump)
//
// Watch allows registering multiple functions, at any time.
func (m *Manager) Watch(f func(*Manager)) {
	// not implemented
}

// GetCertificate fits well with tls.Config's GetCertificate field.
// It provides a TLS certificate for hello.ServerName host, including *.acme.invalid.
// All other fields of hello are ignored.
//
// A simple usage can be shown as follows:
//
//	s := &http.Server{
//		Addr: ":https",
//		TLSConfig: &tls.Config{
//			GetCertificate: m.GetCertificate,
//		},
//	}
//	s.ListenAndServeTLS("", "")
//
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, errors.New("not implemented")
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (m *Manager) MarshalBinary() ([]byte, error) {
	return nil, errors.New("not implemented")
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (m *Manager) UnmarshalBinary(data []byte) error {
	return errors.New("not implemented")
}
