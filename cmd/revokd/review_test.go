// SPDX-License-Identifier: BSD-3-Clause

// The tests in this file were written by an adversarial review of revokd
// v0.1.1, each proving a defect it found; they stay as the regression tests
// of the fixes.

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
	"testing"
	"time"

	"github.com/go-authn/krl"
	"github.com/go-authn/revocation"
)

func oneSource(dir, url, caFile, out string) string {
	return fmt.Sprintf(`
state_dir = %q
source "a" {
  url    = %q
  ssh_ca = %q
}
output "sshd" {
  path    = %q
  sources = ["a"]
}
`, filepath.Join(dir, "state"), url, caFile, out)
}

// A crash between keep()'s two writes (list, then .sig) leaves a pair that
// does not verify; at restart loadHeld drops it and the rollback guard with
// it: a signed older list, still unexpired, un-revokes.
func TestFoundCrashBetweenStateWritesAllowsRollback(t *testing.T) {
	dir := t.TempDir()
	is := newSSHIssuer(t)
	now := time.Now()
	is.issue(1, now.Add(-2*time.Minute), time.Hour) // v1 revokes nothing
	v1raw, v1sig := is.raw, is.sig
	srv := httptest.NewTLSServer(is)
	defer srv.Close()
	out := filepath.Join(dir, "revoked.krl")
	body := oneSource(dir, srv.URL+"/krl", is.caFile(t, dir, "a.pub"), out)
	a := agentFor(t, dir, body, srv.Client())
	if err := a.syncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	is.issue(2, now.Add(-time.Minute), time.Hour, 10) // v2 revokes serial 10
	if err := a.syncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := revokedBy(t, out, is.cert(t, 10)); !got[0] {
		t.Fatal("setup: v2 not applied")
	}
	// Power loss after writeAtomic(state/a, v2) and before writeAtomic(state/a.sig, v2).
	os.WriteFile(filepath.Join(dir, "state", "a.sig"), v1sig, 0o644)

	// A hostile mirror replays v1, properly signed and unexpired.
	is.mu.Lock()
	is.raw, is.sig = v1raw, v1sig
	is.mu.Unlock()
	again := agentFor(t, dir, body, srv.Client())
	err := again.syncOnce(context.Background())
	if got := revokedBy(t, out, is.cert(t, 10)); !got[0] {
		t.Errorf("after a crash between the two state writes and a restart, a replayed v1 was accepted (sync err=%v, held v%v): serial 10 is no longer revoked in %s",
			err, again.fetchers[0].Held().Version, out)
	}
}

// max_age on a source a CRL output takes is refused: revokd cannot shorten
// a CRL's life -- the TLS server judges it by nextUpdate, and keeps one it
// loaded in memory until then. v0.1 accepted it, logged the lapse, and
// OpenSSL kept accepting the CRL (found by the adversarial review).
func TestFoundCRLOutputRefusesMaxAge(t *testing.T) {
	dir := t.TempDir()
	x := newX509Issuer(t)
	ca := write(t, dir, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x.cert.Raw}))
	body := func(maxAge string) string {
		return fmt.Sprintf(`
state_dir = %q
source "x" {
  url     = "https://ca.example/crl"
  x509_ca = %q
  %s
}
output "nginx" {
  path    = %q
  sources = ["x"]
}
`, filepath.Join(dir, "state"), ca, maxAge, filepath.Join(dir, "ca.crl"))
	}
	_, err := loadConfig(write(t, dir, "a.hcl", []byte(body(`max_age = "1h"`))))
	if err == nil || !strings.Contains(err.Error(), "cannot enforce") {
		t.Errorf("max_age on a CRL output's source: %v", err)
	}
	if _, err := loadConfig(write(t, dir, "b.hcl", []byte(body("")))); err != nil {
		t.Errorf("control: without max_age: %v", err)
	}
}

// A render error (here Builder.Merge's 4M-range bound, reached by one CA's
// signed list) leaves the output untouched -- including when ANOTHER source
// lapses, so that source's CA is never revoked: fail-closed is lost.
func TestFoundRenderErrorBlocksFailClosedOfOtherSources(t *testing.T) {
	dir := t.TempDir()
	ia, ib := newSSHIssuer(t), newSSHIssuer(t)
	now := time.Now()
	ia.issue(1, now, 2*time.Hour, 10)
	ib.issue(1, now, time.Hour, 20)
	sa, sb := httptest.NewTLSServer(ia), httptest.NewTLSServer(ib)
	defer sa.Close()
	defer sb.Close()
	out := filepath.Join(dir, "revoked.krl")
	a := agentFor(t, dir, fmt.Sprintf(`
state_dir = %q
source "a" {
  url    = %q
  ssh_ca = %q
}
source "b" {
  url    = %q
  ssh_ca = %q
}
output "sshd" {
  path    = %q
  sources = ["a", "b"]
}
`, filepath.Join(dir, "state"), sa.URL+"/krl", ia.caFile(t, dir, "a.pub"), sb.URL+"/krl", ib.caFile(t, dir, "b.pub"), out), sa.Client())
	ctx := context.Background()
	if err := a.syncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// A's CA issues v2: 2^22+1 alternating serials, a ~1 MiB bitmap KRL.
	bld := krl.NewBuilder(2, "big")
	for s := uint64(1); s <= 2*(1<<22)+1; s += 2 {
		bld.RevokeSerial(ia.signer.PublicKey(), s)
	}
	bld.SetExpires(now.Add(2 * time.Hour))
	raw, err := bld.Marshal(now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := revocation.SignKRL(raw, ia.signer)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("A's v2: %d bytes", len(raw))
	ia.mu.Lock()
	ia.raw, ia.sig = raw, sig
	ia.mu.Unlock()
	err = a.syncOnce(ctx)
	h0 := httptest.NewRecorder()
	a.health(h0, nil)
	t.Logf("sync with A v2: %v; healthz %d %q", err, h0.Code, strings.TrimSpace(h0.Body.String()))
	// B's issuer stops; B lapses.
	sb.Close()
	a.now = func() time.Time { return now.Add(61 * time.Minute) }
	err = a.syncOnce(ctx)
	h := httptest.NewRecorder()
	a.health(h, nil)
	t.Logf("sync after B lapsed: %v; healthz %d", err, h.Code)
	got := revokedBy(t, out, ib.cert(t, 21), ia.cert(t, 3))
	if !got[0] {
		t.Errorf("B lapsed but B's certificate 21 is accepted by %s: the fail-closed list was never written", out)
	}
	if !got[1] {
		t.Errorf("A's v2 revocation of serial 3 never reached %s", out)
	}
}

// One CA's signed list can revoke another CA's certificates in the merged
// output: PROTOCOL.md says the fail-closed list revokes "nothing else", and
// that signing with the CA key needs no new trust.
func TestFoundOneCAsListRevokesAnotherCA(t *testing.T) {
	dir := t.TempDir()
	ia, ib := newSSHIssuer(t), newSSHIssuer(t)
	now := time.Now()
	bld := krl.NewBuilder(1, "a")
	bld.RevokeKey(ib.signer.PublicKey())      // B's CA key, explicitly
	bld.RevokeSerialRange(nil, 1, ^uint64(0)) // every serial, any CA
	bld.SetExpires(now.Add(time.Hour))
	raw, _ := bld.Marshal(now)
	sig, _ := revocation.SignKRL(raw, ia.signer)
	ia.raw, ia.sig = raw, sig
	ib.issue(1, now, time.Hour)
	sa, sb := httptest.NewTLSServer(ia), httptest.NewTLSServer(ib)
	defer sa.Close()
	defer sb.Close()
	out := filepath.Join(dir, "revoked.krl")
	a := agentFor(t, dir, fmt.Sprintf(`
state_dir = %q
source "a" {
  url    = %q
  ssh_ca = %q
}
source "b" {
  url    = %q
  ssh_ca = %q
}
output "sshd" {
  path    = %q
  sources = ["a", "b"]
}
`, filepath.Join(dir, "state"), sa.URL+"/krl", ia.caFile(t, dir, "a.pub"), sb.URL+"/krl", ib.caFile(t, dir, "b.pub"), out), sa.Client())
	if err := a.syncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := revokedBy(t, out, ib.cert(t, 5)); got[0] {
		t.Errorf("CA A's list revokes CA B's certificate 5 in %s (B's own list revokes nothing)", out)
	}
	// What was left out is said once per issue of the list, not at every
	// sync.
	a.syncOnce(context.Background())
	if n := strings.Count(a.log.(*safeBuffer).String(), "left out"); n != 1 {
		t.Errorf("said %d times that A's list reaches past A, want once:\n%s", n, a.log.(*safeBuffer).String())
	}
}

// The mirror serves /<name>, /<name>.sig and /healthz: names that are those
// paths are refused (found by the adversarial review: a source "a.sig" was
// served as source a's signature).
func TestFoundSourceNamesThatAreMirrorPaths(t *testing.T) {
	dir := t.TempDir()
	ca := newSSHIssuer(t).caFile(t, dir, "a.pub")
	for _, name := range []string{"a.sig", "healthz"} {
		body := fmt.Sprintf("state_dir = %q\nsource %q {\n  url = \"https://x/krl\"\n  ssh_ca = %q\n}\n",
			filepath.Join(dir, "state"), name, ca)
		if _, err := loadConfig(write(t, dir, "c.hcl", []byte(body))); err == nil {
			t.Errorf("a source named %q: accepted", name)
		}
	}
}

// Fetch holds the fetcher's mutex across network I/O; Held() (the mirror,
// healthz) waits on it: a slow upstream stalls every mirror request.
func TestFoundMirrorBlocksBehindSlowUpstream(t *testing.T) {
	dir := t.TempDir()
	is := newSSHIssuer(t)
	is.issue(1, time.Now(), time.Hour, 10)
	slow := make(chan struct{})
	var delay = 0 * time.Second
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(delay):
		case <-slow:
		}
		is.ServeHTTP(w, r)
	})
	srv := httptest.NewTLSServer(h)
	defer srv.Close()
	defer close(slow)
	a := agentFor(t, dir, fmt.Sprintf(`
state_dir = %q
source "a" {
  url    = %q
  ssh_ca = %q
}
`, filepath.Join(dir, "state"), srv.URL+"/krl", is.caFile(t, dir, "a.pub")), srv.Client())
	if err := a.syncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	m := httptest.NewServer(a.handler())
	defer m.Close()
	delay = 3 * time.Second
	go a.syncOnce(context.Background())
	time.Sleep(200 * time.Millisecond)
	for _, p := range []string{"/a", "/healthz"} {
		start := time.Now()
		res, err := http.Get(m.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if d := time.Since(start); d > time.Second {
			t.Errorf("mirror GET %s took %v while the upstream was slow (it serves from memory)", p, d.Round(time.Millisecond))
		}
	}
}
