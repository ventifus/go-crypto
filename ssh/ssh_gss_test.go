package ssh

import (
	"testing"
)

func TestParseGSSAPIPayload(t *testing.T) {
	payload := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x06, 0x09,
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
	res, err := parseGSSAPIPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if ok := res.OIDS[0].Equal(krb5Mesh); !ok {
		t.Fatal("not equal")
	}
}

func TestBuildMIC(t *testing.T) {
	sessionID := []byte{134, 180, 134, 194, 62, 145, 171, 82, 119, 149, 254, 196, 125, 173, 177, 145, 187, 85, 53,
		183, 44, 150, 219, 129, 166, 195, 19, 33, 209, 246, 175, 121}
	username := "testuser"
	service := "ssh-connection"
	authMethod := "gssapi-with-mic"
	expected := []byte{0, 0, 0, 32, 134, 180, 134, 194, 62, 145, 171, 82, 119, 149, 254, 196, 125, 173, 177, 145, 187,
		85, 53, 183, 44, 150, 219, 129, 166, 195, 19, 33, 209, 246, 175, 121, 50, 0, 0, 0, 5, 104, 101, 108, 108, 111,
		0, 0, 0, 14, 115, 115, 104, 45, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110, 0, 0, 0, 15, 103, 115, 115, 97,
		112, 105, 45, 119, 105, 116, 104, 45, 109, 105, 99}
	if string(buildMIC(string(sessionID), username, service, authMethod)) != string(expected) {
		t.Fatal("the result of buildMIC is not expected")
	}
}

type FakeGSSAPIClient struct {
	t                    *testing.T
	fakeInitSecContext   func(target string, token []byte, isGSSDelegCreds bool) (outputToken []byte, needContinue bool, err error)
	fakeGetMIC           func(micFiled []byte) ([]byte, error)
	fakeDeleteSecContext func() error
}

func (f *FakeGSSAPIClient) InitSecContext(target string, token []byte, isGSSDelegCreds bool) (outputToken []byte, needContinue bool, err error) {
	if f.fakeInitSecContext != nil {
		return f.fakeInitSecContext(target, token, isGSSDelegCreds)
	}
	if token == nil {
		return []byte{1}, true, nil
	}
	expectedToken := []byte{2}
	if string(expectedToken) != string(token) {
		f.t.Fatal("InitSecContext unexpected token")
	}
	return []byte{}, false, nil
}

func (f *FakeGSSAPIClient) GetMIC(micFiled []byte) ([]byte, error) {
	if f.fakeGetMIC != nil {
		return f.fakeGetMIC(micFiled)
	}
	return []byte{1}, nil
}

func (f *FakeGSSAPIClient) DeleteSecContext() error {
	if f.fakeDeleteSecContext != nil {
		return f.fakeDeleteSecContext()
	}
	return nil
}

type FakeGSSAPIServer struct {
	t                    *testing.T
	fakeAcceptSecContext func(token []byte) (outputToken []byte, needContinue bool, err error)
	fakeVerifyMIC        func(micField []byte, micToken []byte) error
	fakeGetSrcName       func() (string, error)
}

func (f *FakeGSSAPIServer) AcceptSecContext(token []byte) (outputToken []byte, needContinue bool, err error) {
	if f.fakeAcceptSecContext != nil {
		return f.fakeAcceptSecContext(token)
	}
	expectedToken := []byte{1}
	if string(expectedToken) != string(token) {
		f.t.Fatal("AcceptSecContext unexpected token")
	}
	return []byte{2}, false, nil
}

func (f *FakeGSSAPIServer) VerifyMIC(micField []byte, micToken []byte) error {
	if f.fakeVerifyMIC != nil {
		return f.fakeVerifyMIC(micField, micToken)
	}
	return nil
}

func (f *FakeGSSAPIServer) GetSrcName() (string, error) {
	if f.fakeGetSrcName != nil {
		return f.fakeGetSrcName()
	}
	return "testuser", nil
}

func (f *FakeGSSAPIServer) DeleteSecContext() error {
	return nil
}
