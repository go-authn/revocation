// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// A real SIGHUP, sent to this process, makes the running agent sync now --
// and does not kill it. Uncaught, it killed the process (Go's default), and
// systemd counts that as a clean exit: a Restart=on-failure unit stayed down
// while sshd kept reading a KRL nothing would fail closed any more (found in
// go-authn/authnd). Without the handler this test binary dies with
// "signal: hangup"; with a handler that does not wake the agent, it waits
// out its deadline and fails.
func TestSIGHUPSyncsNowAndDoesNotKill(t *testing.T) {
	dir := t.TempDir()
	is := newSSHIssuer(t)
	is.issue(1, time.Now(), time.Hour)
	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/krl" {
			fetches.Add(1)
		}
		is.ServeHTTP(w, r)
	}))
	defer srv.Close()
	body := `refresh = "1h"` + "\n" + oneSource(dir, srv.URL+"/krl", is.caFile(t, dir, "a.pub"), filepath.Join(dir, "o"))
	a := agentFor(t, dir, body)

	hup, stop := notifyHUP()
	defer stop()
	a.wake = hup
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitFor := func(n int32) bool {
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if fetches.Load() >= n {
				return true
			}
		}
		return false
	}
	if !waitFor(1) {
		t.Fatal("control: the first sync never fetched")
	}
	// The refresh is an hour: only the signal can bring a second fetch.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	if !waitFor(2) {
		t.Fatalf("SIGHUP did not make the agent sync: %d fetch(es)", fetches.Load())
	}
}
