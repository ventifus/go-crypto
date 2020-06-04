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

func testUnsupportedHelper(config *ServerConfig, t *testing.T) {
	reader := rand.Reader
	bitSize := 2048
	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		t.Errorf("Failed to generate temporary host key (%s)", err)
	}
	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	var hostKeyBuffer bytes.Buffer
	err = pem.Encode(bufio.NewWriter(&hostKeyBuffer), privateKey)
	if err != nil {
		t.Errorf("Failed to encode temporary host key (%s)", err)
	}

	private, _ := ParsePrivateKey(hostKeyBuffer.Bytes())
	config.AddHostKey(private)

	listener, err := net.Listen("tcp", "127.0.0.1:0")

	clientReceivedError := make(chan bool)
	clientError := make(chan error)
	var tcpConn net.Conn

	cleanup := func() {
		_ = listener.Close()
		if tcpConn != nil {
			_ = tcpConn.Close()
		}
	}
	defer cleanup()

	go func() {
		defer close(clientReceivedError)
		defer close(clientError)

		err := testUnsupportedClient(listener)
		if err != nil {
			clientReceivedError <- true
			clientError <- err
			return
		}
		clientReceivedError <- false
		clientError <- nil
	}()

	tcpConn, err = listener.Accept()
	if err != nil {
		t.Fatalf("Failed to accept incoming connection (%s)", err)
		return
	}
	_, _, _, sshConnError := NewServerConn(tcpConn, config)
	_ = tcpConn.Close()

	if sshConnError != nil {
		//Server error, good
		if <-clientReceivedError {
			//Client error, good
			return
		}
		// No client error
		t.Fatalf("Server correctly received an error on invalid configuration (%s) but the client did not.", sshConnError)
		return
	}
	if <-clientReceivedError {
		//No server error, but received client error
		t.Fatalf("The server did not correctly return an error on an invalid SSH configuration, but the client did as expected (%s).", <-clientError)
		return
	}
	//No error on either end
	t.Fatalf("Neither the server nor the client received an error as expected.")
	return
}

func testUnsupportedClient(listener net.Listener) error {
	sshConfig := &ClientConfig{
		User: "Test",
	}
	sshConfig.HostKeyCallback = InsecureIgnoreHostKey()
	for {
		client, err := Dial("tcp", listener.Addr().String(), sshConfig)
		if err != nil {
			return err
		}
		//The handshake succeeded, let's close the connection.
		_ = client.Close()
		return nil
	}
}

//This test checks if an error is thrown if the server configuration contains an unsupported MAC
func TestUnsupportedMACError(t *testing.T) {
	config := &ServerConfig{
		Config: Config{
			MACs: []string{"unsupported-mac", supportedMACs[0]},
		},
		NoClientAuth: true,
	}
	testUnsupportedHelper(config, t)
}

//This test checks if an error is thrown if the server configuration contains an unsupported Key Exchange Algorithm
func TestUnsupportedKex(t *testing.T) {
	config := &ServerConfig{
		Config: Config{
			KeyExchanges: []string{"unsupported-kex", supportedKexAlgos[0]},
		},
		NoClientAuth: true,
	}
	testUnsupportedHelper(config, t)
}

//Note: A check for ciphers is not needed since the fullConf.SetDefaults() filters out unsupported ciphers.
