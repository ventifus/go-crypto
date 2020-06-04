package ssh

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
)

func createServerAndDial(t *testing.T, config *ServerConfig) {
	reader := rand.Reader
	bitSize := 2048
	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		t.Fatalf("failed to generate temporary host key (%v)", err)
	}
	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	var hostKeyBuffer bytes.Buffer
	err = pem.Encode(bufio.NewWriter(&hostKeyBuffer), privateKey)
	if err != nil {
		t.Fatalf("failed to encode temporary host key (%s)", err)
	}

	private, _ := ParsePrivateKey(hostKeyBuffer.Bytes())
	config.AddHostKey(private)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to open listen socket (%v)", err)
	}
	defer listener.Close()

	clientError := make(chan error)
	var tcpConn net.Conn

	go func() {
		clientError <- dialServer(listener)
	}()

	tcpConn, err = listener.Accept()
	if err != nil {
		t.Fatalf("failed to accept incoming connection (%v)", err)
	}
	_, _, _, sshConnError := NewServerConn(tcpConn, config)
	tcpConn.Close()

	clientErr := <-clientError
	if sshConnError != nil && clientErr == nil {
		// Server error, but no client error
		t.Fatalf("server correctly received an error on invalid configuration but the client did not (%v)", sshConnError)
	} else if sshConnError == nil && clientErr != nil {
		// No server error, but received client error
		t.Fatalf("the server did not correctly return an error on an invalid SSH configuration, but the client did as expected (%v)", <-clientError)
	} else if sshConnError == nil && clientErr == nil {
		// No error on either end
		t.Fatalf("neither the server nor the client received an error as expected")
	}
}

func dialServer(listener net.Listener) error {
	sshConfig := &ClientConfig{
		User: "Test",
	}
	sshConfig.HostKeyCallback = InsecureIgnoreHostKey()
	for {
		client, err := Dial("tcp", listener.Addr().String(), sshConfig)
		if err != nil {
			return err
		}
		// The handshake succeeded, let's close the connection.
		return client.Close()
	}
}

// This test checks if an error is thrown if the server configuration contains an unsupported MAC
func TestDialFailsAgainstServerWithAnUnsupportedMac(t *testing.T) {
	config := &ServerConfig{
		Config: Config{
			MACs: []string{"unsupported-mac", supportedMACs[0]},
		},
		NoClientAuth: true,
	}
	createServerAndDial(t, config)
}

// This test checks if an error is thrown if the server configuration contains an unsupported Key Exchange Algorithm
func TestDialFailsAgainstServerWithAnUnsupportedKex(t *testing.T) {
	config := &ServerConfig{
		Config: Config{
			KeyExchanges: []string{"unsupported-kex", supportedKexAlgos[0]},
		},
		NoClientAuth: true,
	}
	createServerAndDial(t, config)
}

// Note: A check for ciphers is not needed since the fullConf.SetDefaults() filters out unsupported ciphers.
