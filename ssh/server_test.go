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
	config.NoClientAuth = true
	reader := rand.Reader
	bitSize := 2048
	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		t.Errorf("Failed to generate temporary host key")
	}
	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	var hostKeyBuffer bytes.Buffer
	err = pem.Encode(bufio.NewWriter(&hostKeyBuffer), privateKey)
	if err != nil {
		t.Errorf("Failed to encode temporary host key")
	}

	private, _ := ParsePrivateKey(hostKeyBuffer.Bytes())
	config.AddHostKey(private)

	listener, err := net.Listen("tcp", "127.0.0.1:0")

	go func() {
		sshConfig := &ClientConfig{
			User: "Test",
		}
		sshConfig.HostKeyCallback = InsecureIgnoreHostKey()
		client, err := Dial("tcp", listener.Addr().String(), sshConfig)
		if err == nil {
			_, err = client.NewSession()
			if err == nil {
				//Bad, we did not receive an error.
				t.Errorf("Client did not receive an error")
				t.Fail()
			}
			client.Close()
		}
	}()

	tcpConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to accept incoming connection (%s)", err)
	}
	_, _, _, err = NewServerConn(tcpConn, config)
	if err == nil {
		t.Errorf("Server did not receive an error")
		t.Fail()
	}

	tcpConn.Close()
}

//This test checks if an error is thrown if the server configuration contains an unsupported MAC
func TestUnsupportedMACError(t *testing.T) {
	config := &ServerConfig{}
	config.MACs = []string{"unsupported-mac", supportedMACs[0]}
	testUnsupportedHelper(config, t)
}

//This test checks if an error is thrown if the server configuration contains an unsupported Key Exchange Algorithm
func TestUnsupportedKex(t *testing.T) {
	config := &ServerConfig{}
	config.KeyExchanges = []string{"unsupported-kex", supportedKexAlgos[0]}
	testUnsupportedHelper(config, t)
}

//A check for ciphers is not needed since the fullConf.SetDefaults() filters out unsupported ciphers.
