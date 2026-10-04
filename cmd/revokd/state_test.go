// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/krl"
)

// A v0.1 state -- the list and its signature as two files -- is read once,
// and replaced by the one-file state at the next change.
func TestAV01StateIsCarriedOver(t *testing.T) {
	dir := t.TempDir()
	is := newSSHIssuer(t)
	now := time.Now()
	is.issue(5, now, time.Hour, 10)
	state := filepath.Join(dir, "state")
	os.MkdirAll(state, 0o700)
	write(t, state, "a", is.raw)
	write(t, state, "a.sig", is.sig)
	srv := httptest.NewTLSServer(is)
	defer srv.Close()
	body := oneSource(dir, srv.URL+"/krl", is.caFile(t, dir, "a.pub"), filepath.Join(dir, "out.krl"))
	a := agentFor(t, dir, body, srv.Client())
	if h := a.fetchers[0].Held(); h == nil || h.Version.Uint64() != 5 {
		t.Fatalf("the v0.1 state was not read: %+v", h)
	}
	is.issue(6, now, time.Hour, 10, 11)
	if err := a.syncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(state)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if fmt.Sprint(names) != "[a.state]" {
		t.Errorf("state after the change: %v, want only a.state", names)
	}
}

// Truncated or foreign state files are not trusted.
func TestABrokenStateIsNotUsed(t *testing.T) {
	for name, data := range map[string]string{
		"foreign":   "not a state",
		"truncated": stateMagic + "\x00\x00\x00\x00\x00\x00\x10\x00short",
		"empty":     "",
	} {
		dir := t.TempDir()
		is := newSSHIssuer(t)
		state := filepath.Join(dir, "state")
		os.MkdirAll(state, 0o700)
		write(t, state, "a.state", []byte(data))
		log := &safeBuffer{}
		p := write(t, dir, "revokd.hcl", []byte(oneSource(dir, "https://127.0.0.1:1/krl", is.caFile(t, dir, "a.pub"), filepath.Join(dir, "o"))))
		cfg, err := loadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		a, err := newAgent(cfg, log, nil)
		if err != nil || a.fetchers[0].Held() != nil || !strings.Contains(log.String(), "not used") {
			t.Errorf("%s: held=%v err=%v log=%q", name, a.fetchers[0].Held(), err, log)
		}
	}
}

// A state directory others may write to is refused: whoever empties it
// lets a replayed older list in.
func TestAStateDirOthersCanWriteIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not say who may write on Windows")
	}
	dir := t.TempDir()
	is := newSSHIssuer(t)
	state := filepath.Join(dir, "state")
	os.MkdirAll(state, 0o700)
	os.Chmod(state, 0o777)
	p := write(t, dir, "revokd.hcl", []byte(oneSource(dir, "https://127.0.0.1:1/krl", is.caFile(t, dir, "a.pub"), filepath.Join(dir, "o"))))
	cfg, _ := loadConfig(p)
	if _, err := newAgent(cfg, &safeBuffer{}, nil); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("a world-writable state_dir: %v", err)
	}
	os.Chmod(state, 0o755)
	if _, err := newAgent(cfg, &safeBuffer{}, nil); err != nil {
		t.Errorf("control: a 0755 state_dir: %v", err)
	}
	f := write(t, dir, "file", nil)
	cfg.StateDir = f
	if _, err := newAgent(cfg, &safeBuffer{}, nil); err == nil {
		t.Error("a state_dir that is a file: no error")
	}
}

// The merged sshd output expires with the first of its current inputs: a
// reader that checks the expiry (fileshare's ssh_krl_file) sees revokd
// stop updating it, as it would see the issuer stop.
func TestTheMergedOutputExpiresWithItsInputs(t *testing.T) {
	dir := t.TempDir()
	a1, b1 := newSSHIssuer(t), newSSHIssuer(t)
	now := time.Now().Truncate(time.Second)
	a1.issue(1, now, time.Hour)
	b1.issue(1, now, 30*time.Minute)
	sa, sb := httptest.NewTLSServer(a1), httptest.NewTLSServer(b1)
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
`, filepath.Join(dir, "state"), sa.URL+"/krl", a1.caFile(t, dir, "a.pub"), sb.URL+"/krl", b1.caFile(t, dir, "b.pub"), out), sa.Client())
	if err := a.syncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(out)
	k, err := krl.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(30 * time.Minute).UTC(); !k.Expires.Equal(want) {
		t.Errorf("the merged output expires at %v, want the first input's %v", k.Expires, want)
	}
}

// A v0.1 CRL state -- one file, the CRL -- is read too.
func TestAV01CRLStateIsCarriedOver(t *testing.T) {
	dir := t.TempDir()
	x := newX509Issuer(t)
	now := time.Now()
	x.issue(t, 4, now.Add(-time.Minute), now.Add(time.Hour))
	state := filepath.Join(dir, "state")
	os.MkdirAll(state, 0o700)
	write(t, state, "x", x.crl)
	ca := write(t, dir, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x.cert.Raw}))
	p := write(t, dir, "revokd.hcl", []byte(fmt.Sprintf("state_dir = %q\nsource \"x\" {\n  url = \"https://127.0.0.1:1/crl\"\n  x509_ca = %q\n}\n", state, ca)))
	cfg, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	a, err := newAgent(cfg, &safeBuffer{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h := a.fetchers[0].Held(); h == nil || h.Version.Int64() != 4 {
		t.Errorf("the v0.1 CRL state was not read: %+v", h)
	}
}

// A state file that cannot be read, or a v0.1 KRL whose signature is
// missing, is not used -- and said.
func TestAnUnreadableStateIsNotUsed(t *testing.T) {
	for name, prepare := range map[string]func(state string){
		"a directory":              func(state string) { os.MkdirAll(filepath.Join(state, "a.state"), 0o700) },
		"a v0.1 KRL, no signature": func(state string) { os.WriteFile(filepath.Join(state, "a"), []byte("x"), 0o600) },
	} {
		dir := t.TempDir()
		is := newSSHIssuer(t)
		state := filepath.Join(dir, "state")
		os.MkdirAll(state, 0o700)
		prepare(state)
		log := &safeBuffer{}
		p := write(t, dir, "revokd.hcl", []byte(oneSource(dir, "https://127.0.0.1:1/krl", is.caFile(t, dir, "a.pub"), filepath.Join(dir, "o"))))
		cfg, _ := loadConfig(p)
		a, err := newAgent(cfg, log, nil)
		if err != nil || a.fetchers[0].Held() != nil || !strings.Contains(log.String(), "not used") {
			t.Errorf("%s: err=%v log=%q", name, err, log)
		}
	}
}
