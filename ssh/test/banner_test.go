// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin dragonfly freebsd linux netbsd openbsd
package test

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/testdata"
)

func getFreeRandomPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}

	l.Close()

	return l.Addr().(*net.TCPAddr).Port, nil
}

func TestBannerCallbackAgainstOpenSSH(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test due to -short")
	}

	bin, err := exec.LookPath("sshd")
	if err != nil {
		// sshd is not always available.
		t.Skip("could not find sshd")
	}

	dir, err := ioutil.TempDir("", "go-banner-openssh")
	if err != nil {
		t.Fatalf("ioutil.TempDir: %v", err)
	}
	defer os.RemoveAll(dir)

	bannerPath := filepath.Join(dir, "banner")
	err = ioutil.WriteFile(bannerPath, []byte("Hello World"), 0444)
	if err != nil {
		t.Fatalf("ioutil.WriteFile: %v", err)
	}

	hostKeyPath := filepath.Join(dir, "host_key")
	err = ioutil.WriteFile(hostKeyPath, testdata.PEMBytes["rsa"], 0400)
	if err != nil {
		t.Fatalf("ioutil.WriteFile: %v", err)
	}

	port, err := getFreeRandomPort()
	if err != nil {
		t.Fatalf("getFreeRandomPort: %v", err)
	}

	cmd := exec.Command(bin, "-D", "-p", strconv.Itoa(port), "-h", hostKeyPath, "-o", fmt.Sprintf("Banner %s", bannerPath))
	err = cmd.Start()
	if err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	defer cmd.Process.Kill()

	var conn net.Conn

	// let's give some time (~5s) to SSHD to properly start
	retry := 0
	for retry < 50 {
		time.Sleep(100 * time.Millisecond)
		conn, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			break
		}

		retry++
	}

	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer conn.Close()

	var receivedBanner string
	clientConf := ssh.ClientConfig{
		User:            "user",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		BannerCallback: func(message string) error {
			receivedBanner = message
			return nil
		},
	}

	_, _, _, err = ssh.NewClientConn(conn, "", &clientConf)
	// authentication errors are expected (as we don't have a full system setup
	// with users and so on), so we look at errors only we didn't receive a
	// banner, if we received one the error is probably not about banners.
	if receivedBanner == "" && err != nil {
		t.Fatal(err)
	}

	expected := "Hello World"
	if receivedBanner != expected {
		t.Fatalf("got %v; want %v", receivedBanner, expected)
	}
}
