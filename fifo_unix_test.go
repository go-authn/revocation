// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package revocation

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A file:// source that names a FIFO (or any special file) blocked open(2)
// forever, ignoring the context: the agent stopped syncing, and with it the
// fail-closed on lapse.
func TestAFileSourceThatIsNotARegularFileIsRefusedNotWaitedFor(t *testing.T) {
	p := filepath.Join(t.TempDir(), "krl")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { // release a reader blocked in open
		if w, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
	})
	ca := newSSHCA(t)
	f, err := NewFetcher(Source{URL: FileURL(p), Kind: KRL, SSHCA: ca.pub}, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := f.Fetch(context.Background()); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO was read as a list")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Fetch is blocked opening a FIFO")
	}
}
