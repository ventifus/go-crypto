// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package acme_test

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func spawnServerProcess(t *testing.T, dir string, cmd string, args ...string) {
	t.Helper()

	cmdInstance := exec.Command("go", append([]string{"run", "-mod", "mod", cmd}, args...)...)
	cmdInstance.Dir = dir
	cmdInstance.Stdout = os.Stdout
	cmdInstance.Stderr = os.Stderr
	// The 'go run' command will spawn the server processes as children.
	// We want to kill the 'go run' and subprocesses in one operation by
	// killing the process group.
	cmdInstance.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmdInstance.Start(); err != nil {
		t.Fatalf("failed to start %s: %v", cmd, err)
	}
	t.Cleanup(func() {
		syscall.Kill(-cmdInstance.Process.Pid, syscall.SIGTERM)
	})
}
