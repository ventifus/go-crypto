package ssh

import (
	"errors"
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

type exchange struct {
	outToken      string
	expectedToken string
}

type FakeClient struct {
	exchanges []*exchange
	i         int
	mic       []byte
	round     int
}

func (f *FakeClient) InitSecContext(target string, token []byte, isGSSDelegCreds bool) (outputToken []byte, needContinue bool, err error) {
	if token == nil {
		if f.exchanges[f.i].expectedToken != "" {
			err = errors.New("token is invalid")
		} else {
			outputToken = []byte(f.exchanges[f.i].outToken)
		}
	} else {
		if string(token) != string(f.exchanges[f.i].expectedToken) {
			err = errors.New("token is invalid")
		} else {
			outputToken = []byte(f.exchanges[f.i].outToken)
		}
	}
	f.i++
	needContinue = f.i < f.round
	return
}

func (f *FakeClient) GetMIC(micField []byte) ([]byte, error) {
	return f.mic, nil
}

func (f *FakeClient) DeleteSecContext() error {
	return nil
}

type FakeGSSAPIClient struct {
	t                  *testing.T
	fakeInitSecContext func(target string, token []byte, isGSSDelegCreds bool) (outputToken []byte, needContinue bool, err error)
	fakeGetMIC         func(micFiled []byte) ([]byte, error)
}

type FakeServer struct {
	exchanges   []*exchange
	i           int
	expectedMIC []byte
	srcName     string
	round       int
}

func (f *FakeServer) AcceptSecContext(token []byte) (outputToken []byte, srcName string, needContinue bool, err error) {
	if token == nil {
		if f.exchanges[f.i].expectedToken != "" {
			err = errors.New("token is invalid")
		} else {
			outputToken = []byte(f.exchanges[f.i].outToken)
		}
	} else {
		if string(token) != string(f.exchanges[f.i].expectedToken) {
			err = errors.New("token is invalid")
		} else {
			outputToken = []byte(f.exchanges[f.i].outToken)
		}
	}
	f.i++
	needContinue = f.i < f.round
	srcName = f.srcName
	return
}

func (f *FakeServer) VerifyMIC(micField []byte, micToken []byte) error {
	if string(micToken) != string(f.expectedMIC) {
		return errors.New("VerifyMIC fail")
	}
	return nil
}

func (f *FakeServer) DeleteSecContext() error {
	return nil
}
