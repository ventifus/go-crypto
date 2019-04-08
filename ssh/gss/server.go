package gss

import (
	"errors"

	"github.com/apcera/gssapi"
)

func NewSSHGSSAPIServerSide() (*SSHGSSAPIServerSide, error) {
	lib, err := gssapi.Load(nil)
	if err != nil {
		return nil, err
	}
	return &SSHGSSAPIServerSide{
		lib: lib,
	}, nil
}

type SSHGSSAPIServerSide struct {
	lib     *gssapi.Lib
	ctx     *gssapi.CtxId
	srcName *gssapi.Name
}

func (s *SSHGSSAPIServerSide) AcceptSecContext(token []byte) ([]byte, bool, error) {
	inputToken, err := s.lib.MakeBufferBytes(token)
	defer inputToken.Release()
	if err != nil {
		return nil, false, err
	}
	ctx, srcName, _, outToken, _, _, _, err := s.lib.AcceptSecContext(s.lib.GSS_C_NO_CONTEXT, s.lib.GSS_C_NO_CREDENTIAL, inputToken, s.lib.GSS_C_NO_CHANNEL_BINDINGS)
	defer outToken.Release()
	s.ctx = ctx
	s.srcName = srcName
	if err != nil {
		if err == gssapi.ErrContinueNeeded {
			return outToken.Bytes(), true, nil
		}
		return outToken.Bytes(), false, err
	}
	return outToken.Bytes(), false, nil
}

func (s *SSHGSSAPIServerSide) VerifyMIC(micField []byte, micToken []byte) error {
	if s.ctx == nil {
		return errors.New("ctx is nil, acceptSecContext before VerifyMIC")
	}
	messageBuffer, _ := s.lib.MakeBufferBytes(micField)
	defer messageBuffer.Release()
	tokenBuffer, _ := s.lib.MakeBufferBytes(micToken)
	defer tokenBuffer.Release()
	if _, err := s.ctx.VerifyMIC(messageBuffer, tokenBuffer); err != nil {
		return err
	}
	return nil
}

func (s *SSHGSSAPIServerSide) GetSrcName() (string, error) {
	if s.ctx == nil {
		return "", errors.New("ctx is nil, check you called acceptSecContext")
	}
	return s.srcName.String(), nil
}

func (s *SSHGSSAPIServerSide) Release() error {
	if s.ctx != nil {
		s.ctx.Release()
	}
	if s.srcName != nil {
		s.srcName.Release()
	}
	return nil
}
