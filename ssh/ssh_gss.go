// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"encoding/asn1"
	"errors"
)

var krb5OID []byte

func init() {
	krb5OID, _ = asn1.Marshal(krb5Mesh)
}

// GSSAPIClient is wrapper to gss-api some functions for SSH2 client "gssapi-with-mic" authorization.
type GSSAPIClient interface {
	// InitSecContext initializes a GSS-API context.
	// Returns output token which should be transferred to
	// the server, where the server will present it to AcceptSecContext.
	// If one or more reply tokens may be required from the server, it returns true.
	// See RFC 2744 session 5.19.
	InitSecContext(target string, token []byte, isGSSDelegCreds bool) ([]byte, bool, error)
	// GetMIC creates the MIC token for a SSH2 message.
	// See RFC 2744 session 5.15.
	GetMIC(micFiled []byte) ([]byte, error)
	// Release release all resources if any
	Release() error
}

// GSSAPIServer is wrapper to gss-api some functions for SSH2 server "gssapi-with-mic" authorization.
type GSSAPIServer interface {
	// AcceptSecContext accept a GSS-API context (server mode).
	// See RFC 2744 session 5.1
	AcceptSecContext(token []byte) ([]byte, bool, error)
	// VerifyMIC verifies the MIC token for a SSH2 message.
	// See RFC 2744 session 5.32
	VerifyMIC(micField []byte, micToken []byte) error
	// GetSrcName returns the srcName which returns from gss_accept_sec_context,
	// also be used as the authenticated username
	GetSrcName() (string, error)
	// Release release all resources if any
	Release() error
}

var (
	// OpenSSH supports Kerberos V5 mechanism only for GSS-API authentication,
	// so we also support the krb5 mechanism only.
	// See RFC 1964 session 1.
	krb5Mesh = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}
)

// The GSS-API authentication method is initiated when the client sends an SSH_MSG_USERAUTH_REQUEST
// See 4462 session 3.2
type userAuthRequestGSSAPI struct {
	N    uint32
	OIDS []asn1.ObjectIdentifier
}

func parseGSSAPIPayload(payload []byte) (*userAuthRequestGSSAPI, error) {
	n, rest, ok := parseUint32(payload)
	if !ok {
		return nil, errors.New("parse uint32 failed")
	}
	s := &userAuthRequestGSSAPI{
		N:    n,
		OIDS: make([]asn1.ObjectIdentifier, n),
	}
	for i := 0; i < int(n); i++ {
		var (
			desiredMech []byte
			err         error
		)
		desiredMech, rest, ok = parseString(rest)
		if !ok {
			return nil, errors.New("parse string failed")
		}
		if rest, err = asn1.Unmarshal(desiredMech, &s.OIDS[i]); err != nil {
			return nil, err
		}

	}
	return s, nil
}

func sshgssoids() []byte {
	return krb5OID
}

// See RFC 4462 session 3.6
func buildMIC(sessionID string, username string, service string, authMethod string) []byte {
	out := make([]byte, 0, 0)
	out = appendString(out, sessionID)
	out = append(out, msgUserAuthRequest)
	out = appendString(out, username)
	out = appendString(out, service)
	out = appendString(out, authMethod)
	return out
}
