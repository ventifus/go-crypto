package ssh

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/crypto/ssh/testdata"
)

func TestServerCompression(t *testing.T) {
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ServerConfig{
		NoClientAuth: true,
	}
	config.CompressionMethods = []string{"zlib@openssh.com"}

	private, err := ParsePrivateKey(testdata.PEMBytes["rsa"])
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	go func() {
		for {
			nConn, err := listener.Accept()
			if err != nil {
				log.Fatal("failed to accept incoming connection: ", err)
			}

			// Before use, a handshake must be performed on the incoming
			// net.Conn.
			conn, chans, reqs, err := NewServerConn(nConn, config)
			if err != nil {
				log.Fatal("failed to handshake: ", err)
			}
			log.Printf("logged in %v ", conn.Permissions)

			// The incoming Request channel must be serviced.
			go DiscardRequests(reqs)

			// Service the incoming Channel channel.
			for newChannel := range chans {
				if newChannel.ChannelType() != "session" {
					newChannel.Reject(UnknownChannelType, "unknown channel type")
					continue
				}
				channel, requests, err := newChannel.Accept()
				if err != nil {
					log.Fatalf("Could not accept channel: %v", err)
				}

				go func(in <-chan *Request) {
					for req := range in {
						req.Reply(req.Type == "shell", nil)
					}
				}(requests)

				term := terminal.NewTerminal(channel, "> ")

				go func() {
					defer channel.Close()
					for {
						line, err := term.ReadLine()
						if err != nil {
							break
						}
						fmt.Println(line)
					}
				}()
			}

			log.Printf("wait: %v", conn.Wait())
		}
	}()

	cmd := exec.Command("ssh",
		"-oUserKnownHostsFile=/dev/null",
		"-vvv", "-p", "2022", "-oStrictHostKeyChecking=no", "localhost", "/bin/true")
	cmd.Stdout = os.Stdout
	cmd.Stdin = &bytes.Buffer{}
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
}
