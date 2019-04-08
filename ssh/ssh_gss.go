package ssh

import (
	"encoding/asn1"
	"errors"
)

type GSSAPIClient interface {
	InitSecContext(target string, token []byte, isGSSDelegCreds bool) ([]byte, bool, error)
	GetMIC(micFiled []byte) ([]byte, error)
	Release() error
}

type GSSAPIServer interface {
	AcceptSecContext(token []byte) ([]byte, bool, error)
	VerifyMIC(micField []byte, micToken []byte) error
	GetSrcName() (string, error)
	Release() error
}

var (
	krb5Mesh = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}
)

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
	var desiredMech []byte
	var err error
	for i := 0; i < int(n); i++ {
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
	krb5_OID, _ := asn1.Marshal(krb5Mesh)
	return krb5_OID
}

func buildMIC(sessionID string, username string, service string, authMethod string) []byte {
	out := make([]byte, 0, 0)
	out = appendString(out, sessionID)
	out = append(out, msgUserAuthRequest)
	out = appendString(out, username)
	out = appendString(out, service)
	out = appendString(out, authMethod)
	return out
}
