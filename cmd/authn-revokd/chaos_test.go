// SPDX-License-Identifier: BSD-3-Clause

// Chaos tests of the 2026-11 audit: an upstream that hangs, a reload command
// that hangs, an output file damaged behind the agent's back, a list that
// lapses between two syncs. Each failed before its fix.

package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-authn/krl"
)

const chaosSlack = 5 * time.Second

// hangUntil is an on_change command that signals started, then blocks until
// release is closed (nil: forever) or it is killed by its context.
func hangUntil(started chan<- struct{}, release <-chan struct{}) func(context.Context, []string) error {
	return func(ctx context.Context, argv []string) error {
		started <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func within(t *testing.T, what string, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s: still blocked after %v", what, d)
	}
}

// A reload command that hangs must not hold the lock /healthz and the mirror's
// bookkeeping need: a hung `systemctl reload` made /healthz hang with it.
func TestAHungReloadCommandDoesNotBlockHealthz(t *testing.T) {
	dir := t.TempDir()
	x := newX509Issuer(t)
	x.issue(t, 1, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), 7)
	ca := write(t, dir, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x.cert.Raw}))
	srv := httptest.NewTLSServer(x)
	defer srv.Close()
	out := filepath.Join(dir, "n.crl")
	a := agentFor(t, dir, fmt.Sprintf(`
state_dir = %q
source "x" {
  url     = %q
  x509_ca = %q
}
output "nginx" {
  path      = %q
  sources   = ["x"]
  on_change = ["reload", "nginx"]
}
`, filepath.Join(dir, "state"), srv.URL+"/crl", ca, out), srv.Client())
	started, release := make(chan struct{}, 1), make(chan struct{})
	a.exec = hangUntil(started, release)
	defer close(release)
	synced := make(chan struct{})
	go func() { a.syncOnce(context.Background()); close(synced) }()
	select {
	case <-started:
	case <-time.After(chaosSlack):
		t.Fatal("the reload command never ran")
	}
	within(t, "/healthz while the reload command hangs", 2*time.Second, func() {
		rec := httptest.NewRecorder()
		a.handler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	})
}

// One upstream that never answers must not keep the others from being fetched,
// nor the outputs from being written: failing closed is the product.
func TestASlowSourceDoesNotDelayTheOthers(t *testing.T) {
	dir := t.TempDir()
	ia, ib := newSSHIssuer(t), newSSHIssuer(t)
	now := time.Now()
	ia.issue(1, now.Add(-time.Minute), time.Hour)
	ib.issue(1, now.Add(-time.Minute), time.Hour)
	seenB := make(chan struct{})
	var once sync.Once
	// A answers only once B has been asked: a sequential agent waits for A first.
	sa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-seenB:
			ia.ServeHTTP(w, r)
		case <-r.Context().Done():
		}
	}))
	defer sa.Close()
	sb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(seenB) })
		ib.ServeHTTP(w, r)
	}))
	defer sb.Close()
	out := filepath.Join(dir, "revoked.krl")
	a := agentFor(t, dir, twoSources(dir, sa.URL+"/krl", ia.caFile(t, dir, "a.pub"), sb.URL+"/krl", ib.caFile(t, dir, "b.pub"), out, ""))
	var err error
	within(t, "syncOnce with a source waiting for another", 20*time.Second, func() { err = a.syncOnce(context.Background()) })
	if err != nil {
		t.Errorf("both sources answer, A once B was asked: %v", err)
	}
}

// A source that never answers is given up after fetchTimeout, and its CA is
// refused from then on.
func TestASourceThatNeverAnswersIsGivenUp(t *testing.T) {
	old := fetchTimeout
	fetchTimeout = 300 * time.Millisecond
	defer func() { fetchTimeout = old }()
	dir := t.TempDir()
	is := newSSHIssuer(t)
	is.issue(1, time.Now().Add(-time.Minute), time.Hour)
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer hang.Close()
	out := filepath.Join(dir, "revoked.krl")
	a := agentFor(t, dir, oneSource(dir, hang.URL+"/krl", is.caFile(t, dir, "a.pub"), out))
	var err error
	within(t, "syncOnce against a server that never answers", 10*time.Second, func() { err = a.syncOnce(context.Background()) })
	if err == nil {
		t.Fatal("no error")
	}
	if got := revokedBy(t, out, is.cert(t, 1)); !got[0] {
		t.Errorf("the CA of a source with no list is not refused: %v", got)
	}
}

// A reload command is killed at onChangeTimeout, and tried again at the next
// sync like any failure.
func TestAReloadCommandThatNeverReturnsIsKilled(t *testing.T) {
	old := onChangeTimeout
	onChangeTimeout = 300 * time.Millisecond
	defer func() { onChangeTimeout = old }()
	dir := t.TempDir()
	x := newX509Issuer(t)
	x.issue(t, 1, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), 7)
	ca := write(t, dir, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x.cert.Raw}))
	srv := httptest.NewTLSServer(x)
	defer srv.Close()
	a := agentFor(t, dir, fmt.Sprintf(`
state_dir = %q
source "x" {
  url     = %q
  x509_ca = %q
}
output "nginx" {
  path      = %q
  sources   = ["x"]
  on_change = ["reload", "nginx"]
}
`, filepath.Join(dir, "state"), srv.URL+"/crl", ca, filepath.Join(dir, "n.crl")), srv.Client())
	started := make(chan struct{}, 4)
	a.exec = hangUntil(started, nil)
	var err error
	within(t, "syncOnce with a reload command that never returns", 10*time.Second, func() { err = a.syncOnce(context.Background()) })
	if err == nil || !strings.Contains(err.Error(), "output nginx") {
		t.Errorf("a reload that timed out is not reported: %v", err)
	}
	within(t, "the second sync", 10*time.Second, func() { a.syncOnce(context.Background()) })
	if len(started) != 2 {
		t.Errorf("the reload was run %d times, want 2 (once per sync until it succeeds)", len(started))
	}
}

// A list that lapses between two syncs is refused when it lapses, not at the
// next refresh: with refresh = 1h, sshd kept a revoked-nothing list for up to
// an hour after the issuer stopped.
func TestTheOutputFailsClosedWhenAListLapsesNotAtTheNextRefresh(t *testing.T) {
	dir := t.TempDir()
	is := newSSHIssuer(t)
	is.issue(1, time.Now().Add(-time.Minute), time.Minute+4*time.Second) // lapses in about 4 s
	srv := httptest.NewServer(is)
	defer srv.Close()
	out := filepath.Join(dir, "revoked.krl")
	body := oneSource(dir, srv.URL+"/krl", is.caFile(t, dir, "a.pub"), out)
	a := agentFor(t, dir, body+"\nrefresh = \"1h\"\n")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	cert := is.cert(t, 1)
	deadline := time.Now().Add(15 * time.Second)
	for {
		if raw, err := os.ReadFile(out); err == nil && len(raw) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first sync wrote nothing")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Judged by go-authn/krl alone: the file is rewritten while this runs,
	// and a second reader (ssh-keygen) could see another version.
	revoked := func() bool {
		raw, err := os.ReadFile(out)
		if err != nil {
			return false
		}
		k, err := krl.Parse(raw)
		return err == nil && k.IsRevoked(cert)
	}
	if time.Now().Before(a.fetchers[0].Held().Expires.Add(-time.Second)) && revoked() {
		t.Fatal("setup: the CA is refused while its list is current")
	}
	for !revoked() {
		if time.Now().After(deadline) {
			t.Fatal("15 s after its list lapsed, the CA is still not refused (the next sync is an hour away)")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// An output deleted or damaged behind the agent's back is written again at
// the next sync, not when the list next changes (which may be days).
func TestAnOutputDamagedBehindTheAgentsBackIsWrittenAgain(t *testing.T) {
	dir := t.TempDir()
	is := newSSHIssuer(t)
	is.issue(1, time.Now().Add(-time.Minute), time.Hour, 5)
	srv := httptest.NewServer(is)
	defer srv.Close()
	out := filepath.Join(dir, "revoked.krl")
	a := agentFor(t, dir, oneSource(dir, srv.URL+"/krl", is.caFile(t, dir, "a.pub"), out))
	if err := a.syncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(out)
	for name, damage := range map[string]func(){
		"deleted":   func() { os.Remove(out) },
		"truncated": func() { os.WriteFile(out, good[:len(good)/2], 0o644) },
		"emptied":   func() { os.WriteFile(out, nil, 0o644) },
	} {
		damage()
		if err := a.syncOnce(context.Background()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got, _ := os.ReadFile(out); string(got) != string(good) {
			t.Errorf("%s: the output was not written again", name)
		}
	}
}

// A killed write leaves its temporary file; they must not pile up.
func TestStaleTemporaryFilesOfAKilledWriteAreSwept(t *testing.T) {
	dir := t.TempDir()
	is := newSSHIssuer(t)
	is.issue(1, time.Now().Add(-time.Minute), time.Hour)
	srv := httptest.NewServer(is)
	defer srv.Close()
	out := filepath.Join(dir, "revoked.krl")
	body := oneSource(dir, srv.URL+"/krl", is.caFile(t, dir, "a.pub"), out)
	state := filepath.Join(dir, "state")
	os.MkdirAll(state, 0o700)
	stale := write(t, state, ".a.state.123456789", []byte("half a write"))
	keep := write(t, state, "notes.txt", []byte("an operator's file"))
	agentFor(t, dir, body)
	if _, err := os.Stat(stale); err == nil {
		t.Error("the temporary file of a killed write is still there")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("a file that is not ours was removed: %v", err)
	}
}

// The mirror must not be held open by a client that never reads.
func TestTheMirrorHasTimeouts(t *testing.T) {
	srv := newMirror(nil)
	if srv.ReadHeaderTimeout == 0 || srv.WriteTimeout == 0 || srv.ReadTimeout == 0 || srv.IdleTimeout == 0 {
		t.Errorf("a mirror without every timeout: %+v", srv)
	}
}
