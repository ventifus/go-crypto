// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package manager provides high-level ACME-based certificates management,
// built on top of the acme package.
package manager

import (
	"crypto/tls"
	"errors"

	"golang.org/x/crypto/acme/internal/acme"
)

// Manager is a stateful certificates manager built on top of acme.Client.
// It obtains new and refreshes expiring certificates automatically,
// as well as providing them to a TLS server via tls.Config.
//
// A zero value Manager is a valid state, in which case Let's Encrypt CA is used
// with a newly generated RSA account key of 2048 bit size.
type Manager struct {
	Client *acme.Client
	Cache  Cache
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
// It returns m's internal state representation.
func (m *Manager) MarshalBinary() ([]byte, error) {
	return nil, errors.New("not implemented")
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
// It resets m to a state encoded in data.
func (m *Manager) UnmarshalBinary(data []byte) error {
	return errors.New("not implemented")
}
