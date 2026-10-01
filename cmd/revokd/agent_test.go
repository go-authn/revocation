// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-authn/krl"
	"github.com/go-authn/revocation"
	"golang.org/x/crypto/ssh"
)

// ---- an issuer, as go-authn/bridge will be ----

type sshIssuer struct {
	t      *testing.T
	signer ssh.Signer
	mu     sync.Mutex
	raw    []byte
	sig    []byte
	tamper func([]byte) []byte // what a hostile mirror does to the list
}

func newSSHIssuer(t *testing.T) *sshIssuer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	return &sshIssuer{t: t, signer: s}
}

// issue publishes version v revoking serials, valid for valid from at.
func (is *sshIssuer) issue(v uint64, at time.Time, valid time.Duration, serials ...uint64) {
	is.t.Helper()
	b := krl.NewBuilder(v, "issuer")
	for _, s := range serials {
		b.RevokeSerial(is.signer.PublicKey(), s)
	}
	b.SetExpires(at.Add(valid))
	raw, err := b.Marshal(at)
	if err != nil {
		is.t.Fatal(err)
	}
	sig, err := revocation.SignKRL(raw, is.signer)
	if err != nil {
		is.t.Fatal(err)
	}
	is.mu.Lock()
	is.raw, is.sig = raw, sig
	is.mu.Unlock()
}

func (is *sshIssuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	is.mu.Lock()
	raw, sig, tamper := is.raw, is.sig, is.tamper
	is.mu.Unlock()
	if strings.HasSuffix(r.URL.Path, ".sig") {
		w.Write(sig)
		return
	}
	if tamper != nil {
		raw = tamper(raw)
	}
	w.Write(raw)
}

func (is *sshIssuer) caFile(t *testing.T, dir, name string) string {
	return write(t, dir, name, ssh.MarshalAuthorizedKey(is.signer.PublicKey()))
}

func (is *sshIssuer) cert(t *testing.T, serial uint64) *ssh.Certificate {
	t.Helper()
	upub, _, _ := ed25519.GenerateKey(rand.Reader)
	u, _ := ssh.NewPublicKey(upub)
	c := &ssh.Certificate{Key: u, Serial: serial, CertType: ssh.UserCert, KeyId: "u",
		ValidPrincipals: []string{"u"}, ValidBefore: ssh.CertTimeInfinity}
	if err := c.SignCert(rand.Reader, is.signer); err != nil {
		t.Fatal(err)
	}
	return c
}

func write(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func agentFor(t *testing.T, dir, body string, client ...*http.Client) *agent {
	t.Helper()
	p := write(t, dir, "revokd.hcl", []byte(body))
	cfg, err := loadConfig(p)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	var c *http.Client
	if len(client) > 0 {
		c = client[0]
	}
	a, err := newAgent(cfg, &safeBuffer{}, c)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// revokedBy asks the KRL at path whether each certificate is revoked: the
// go-authn/krl answer, which ssh-keygen judges in that package, and here
// too when ssh-keygen is present.
func revokedBy(t *testing.T, path string, certs ...*ssh.Certificate) []bool {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	k, err := krl.Parse(raw)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	var ours []bool
	var files []string
	dir := t.TempDir()
	for i, c := range certs {
		ours = append(ours, k.IsRevoked(c))
		files = append(files, write(t, dir, fmt.Sprintf("c%d-cert.pub", i), ssh.MarshalAuthorizedKey(c)))
	}
	if bin, err := exec.LookPath("ssh-keygen"); err == nil && runtime.GOOS != "windows" {
		out, _ := exec.Command(bin, append([]string{"-Q", "-f", path}, files...)...).CombinedOutput()
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) != len(certs) {
			t.Fatalf("ssh-keygen -Q: %s", out)
		}
		for i, l := range lines {
			if theirs := strings.HasSuffix(l, ": REVOKED"); theirs != ours[i] {
				t.Errorf("certificate %d: go-authn/krl says revoked=%v, ssh-keygen %q", i, ours[i], l)
			}
		}
	} else if os.Getenv("REVOCATION_REQUIRE_OPENSSH") == "1" {
		t.Fatal("ssh-keygen is required on this lane")
	}
	return ours
}

// ---- sshd ----

// Two CAs, one output for sshd: the merged list revokes what each CA's list
// revokes; when one CA's list lapses, every certificate of that CA is
// refused and the other CA's are untouched; when it comes back, so do its
// certificates.
func TestSSHDOutputMergesAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	a1, b1 := newSSHIssuer(t), newSSHIssuer(t)
	now := time.Now()
	a1.issue(1, now, time.Hour, 10)
	b1.issue(1, now, time.Hour, 20)
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
	ctx := context.Background()
	if err := a.syncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	certs := []*ssh.Certificate{a1.cert(t, 10), a1.cert(t, 11), b1.cert(t, 20), b1.cert(t, 21)}
	if got := revokedBy(t, out, certs...); fmt.Sprint(got) != "[true false true false]" {
		t.Fatalf("merged: %v", got)
	}

	// A's issuer stops; its list lapses an hour on.
	sa.Close()
	a.now = func() time.Time { return now.Add(61 * time.Minute) }
	b1.issue(2, now.Add(60*time.Minute), time.Hour, 20, 22) // B carries on
	if err := a.syncOnce(ctx); err == nil || !strings.Contains(err.Error(), "a") {
		t.Errorf("a lapsed source is not reported: %v", err)
	}
	if got := revokedBy(t, out, append(certs, b1.cert(t, 22))...); fmt.Sprint(got) != "[true true true false true]" {
		t.Errorf("after A lapsed: %v, want every A certificate refused and B's list applied", got)
	}
	raw, _ := os.ReadFile(out)
	if k, _ := krl.Parse(raw); !strings.Contains(k.Comment, "FAIL CLOSED") || !strings.Contains(k.Comment, "a") {
		t.Errorf("the fail-closed list does not say so: %q", k.Comment)
	}
}

// Nothing ever fetched: the output is the fail-closed list from the start,
// not an empty one.
func TestSSHDOutputFailsClosedFromTheStart(t *testing.T) {
	dir := t.TempDir()
	is := newSSHIssuer(t)
	out := filepath.Join(dir, "revoked.krl")
	a := agentFor(t, dir, fmt.Sprintf(`
state_dir = %q
source "a" {
  url    = "https://127.0.0.1:1/krl"
  ssh_ca = %q
}
output "sshd" {
  path    = %q
  sources = ["a"]
}
`, filepath.Join(dir, "state"), is.caFile(t, dir, "a.pub"), out))
	if err := a.syncOnce(context.Background()); err == nil {
		t.Error("no list, no error")
	}
	if got := revokedBy(t, out, is.cert(t, 1), is.cert(t, 2)); fmt.Sprint(got) != "[true true]" {
		t.Errorf("with no list ever fetched: %v", got)
	}
}

// A hostile mirror or a compromised web server: an empty list, a list from
// another CA, a list rolled back. The agent keeps what it had.
func TestAgentRefusesWhatTheTransportMakesUp(t *testing.T) {
	dir := t.TempDir()
	is, other := newSSHIssuer(t), newSSHIssuer(t)
	now := time.Now()
	is.issue(5, now, time.Hour, 10)
	srv := httptest.NewTLSServer(is)
	defer srv.Close()
	out := filepath.Join(dir, "revoked.krl")
	a := agentFor(t, dir, fmt.Sprintf(`
state_dir = %q
source "a" {
  url    = %q
  ssh_ca = %q
}
output "sshd" {
  path    = %q
  sources = ["a"]
}
`, filepath.Join(dir, "state"), srv.URL+"/krl", is.caFile(t, dir, "a.pub"), out), srv.Client())
	ctx := context.Background()
	if err := a.syncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	empty := krl.NewBuilder(6, "")
	empty.SetExpires(now.Add(time.Hour))
	emptyRaw, _ := empty.Marshal(now)
	other.issue(6, now, time.Hour)
	for name, tamper := range map[string]func([]byte) []byte{
		"an empty unsigned list": func([]byte) []byte { return emptyRaw },
		"another CA's list":      func([]byte) []byte { return other.raw },
	} {
		is.mu.Lock()
		is.tamper = tamper
		is.mu.Unlock()
		a.syncOnce(ctx)
		if got := revokedBy(t, out, is.cert(t, 10)); !got[0] {
			t.Errorf("%s: serial 10 is no longer revoked", name)
		}
	}
	is.mu.Lock()
	is.tamper = nil
	is.mu.Unlock()
	is.issue(4, now, time.Hour) // a rollback, properly signed
	a.syncOnce(ctx)
	if got := revokedBy(t, out, is.cert(t, 10)); !got[0] {
		t.Error("a signed older list un-revoked serial 10")
	}
}

// The copy in the state directory orders what comes after a restart.
func TestAgentRestartKeepsOrder(t *testing.T) {
	dir := t.TempDir()
	is := newSSHIssuer(t)
	now := time.Now()
	is.issue(5, now, time.Hour, 10)
	srv := httptest.NewTLSServer(is)
	defer srv.Close()
	body := fmt.Sprintf(`
state_dir = %q
source "a" {
  url    = %q
  ssh_ca = %q
}
`, filepath.Join(dir, "state"), srv.URL+"/krl", is.caFile(t, dir, "a.pub"))
	a := agentFor(t, dir, body, srv.Client())
	if err := a.syncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	is.issue(4, now, time.Hour)
	again := agentFor(t, dir, body, srv.Client())
	held := again.fetchers[0].Held()
	if held == nil || held.Version.Uint64() != 5 {
		t.Fatalf("the copy kept was not read back: %+v", held)
	}
	if err := again.syncOnce(context.Background()); err == nil {
		t.Error("a rolled-back list after a restart: no error")
	}
	if again.fetchers[0].Held().Version.Uint64() != 5 {
		t.Error("the rolled-back list replaced the copy kept")
	}
	// A copy tampered with on disk is not trusted.
	p := filepath.Join(dir, "state", "a")
	raw, _ := os.ReadFile(p)
	raw[len(raw)-1] ^= 1
	os.WriteFile(p, raw, 0o644)
	log := &safeBuffer{}
	cfg, _ := loadConfig(filepath.Join(dir, "revokd.hcl"))
	b, err := newAgent(cfg, log, nil)
	if err != nil || b.fetchers[0].Held() != nil || !strings.Contains(log.String(), "not used") {
		t.Errorf("a tampered copy: held=%v log=%q err=%v", b.fetchers[0].Held(), log, err)
	}
}

// ---- mirrors ----

// An agent serves its verified copies; another agent, pointed at it, gets
// the same lists, verified again -- and a mirror that tampers is caught.
func TestMirrorChain(t *testing.T) {
	dir := t.TempDir()
	is := newSSHIssuer(t)
	now := time.Now()
	is.issue(3, now, time.Hour, 10)
	origin := httptest.NewTLSServer(is)
	defer origin.Close()
	ca := is.caFile(t, dir, "a.pub")
	up := agentFor(t, filepath.Join(mkdir(t, dir, "up")), fmt.Sprintf(`
state_dir = %q
source "a" {
  url    = %q
  ssh_ca = %q
}
`, filepath.Join(dir, "up", "state"), origin.URL+"/krl", ca), origin.Client())
	if err := up.syncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	var tamper bool
	h := up.handler()
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tamper && !strings.HasSuffix(r.URL.Path, ".sig") {
			b := krl.NewBuilder(9, "")
			b.SetExpires(now.Add(time.Hour))
			raw, _ := b.Marshal(now)
			w.Write(raw)
			return
		}
		h.ServeHTTP(w, r)
	}))
	defer mirror.Close()
	out := filepath.Join(dir, "down.krl")
	down := agentFor(t, mkdir(t, dir, "down"), fmt.Sprintf(`
state_dir = %q
source "a" {
  url    = %q
  ssh_ca = %q
}
output "sshd" {
  path    = %q
  sources = ["a"]
}
`, filepath.Join(dir, "down", "state"), mirror.URL+"/a", ca, out))
	if err := down.syncOnce(context.Background()); err != nil {
		t.Fatalf("through the mirror, over plain http: %v", err)
	}
	if got := revokedBy(t, out, is.cert(t, 10), is.cert(t, 11)); fmt.Sprint(got) != "[true false]" {
		t.Errorf("through the mirror: %v", got)
	}
	tamper = true
	if err := down.syncOnce(context.Background()); err == nil {
		t.Error("a tampering mirror: no error")
	}
	if got := revokedBy(t, out, is.cert(t, 10)); !got[0] {
		t.Error("a tampering mirror un-revoked serial 10")
	}
}

func mkdir(t *testing.T, parts ...string) string {
	p := filepath.Join(parts...)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMirrorAnswers(t *testing.T) {
	dir := t.TempDir()
	is := newSSHIssuer(t)
	now := time.Now()
	is.issue(3, now, time.Hour, 10)
	origin := httptest.NewTLSServer(is)
	defer origin.Close()
	a := agentFor(t, dir, fmt.Sprintf(`
state_dir = %q
source "a" {
  url    = %q
  ssh_ca = %q
}
`, filepath.Join(dir, "state"), origin.URL+"/krl", is.caFile(t, dir, "a.pub")), origin.Client())
	srv := httptest.NewServer(a.handler())
	defer srv.Close()
	get := func(path string, hdr ...string) (int, string, http.Header) {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var b bytes.Buffer
		b.ReadFrom(res.Body)
		return res.StatusCode, b.String(), res.Header
	}
	if c, _, _ := get("/healthz"); c != http.StatusServiceUnavailable {
		t.Errorf("healthz before any list: %d", c)
	}
	if c, _, _ := get("/a"); c != http.StatusNotFound {
		t.Errorf("a list before any fetch: %d", c)
	}
	a.syncOnce(context.Background())
	c, body, h := get("/a")
	if c != 200 || body != string(is.raw) || h.Get("ETag") == "" {
		t.Fatalf("GET /a: %d", c)
	}
	tag := h.Get("ETag")
	if c, _, _ := get("/a", "If-None-Match", tag); c != http.StatusNotModified {
		t.Errorf("If-None-Match: %d", c)
	}
	if c, body, _ := get("/a.sig", "If-Match", tag); c != 200 || body != string(is.sig) {
		t.Errorf("the signature: %d", c)
	}
	if c, _, _ := get("/a.sig", "If-Match", `"other"`); c != http.StatusPreconditionFailed {
		t.Errorf("If-Match another list: %d", c)
	}
	for _, p := range []string{"/b", "/b.sig", "/a/b", "/"} {
		if c, _, _ := get(p); c != http.StatusNotFound {
			t.Errorf("GET %s: %d", p, c)
		}
	}
	if c, _, _ := get("/healthz"); c != 200 {
		t.Errorf("healthz: %d", c)
	}
}

// ---- X.509 ----

type x509Issuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	mu   sync.Mutex
	crl  []byte
}

func newX509Issuer(t *testing.T) *x509Issuer {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	return &x509Issuer{cert: c, key: key}
}

func (x *x509Issuer) issue(t *testing.T, n int64, this, next time.Time, serials ...int64) {
	var es []x509.RevocationListEntry
	for _, s := range serials {
		es = append(es, x509.RevocationListEntry{SerialNumber: big.NewInt(s), RevocationTime: this})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(n),
		ThisUpdate: this, NextUpdate: next, RevokedCertificateEntries: es}, x.cert, x.key)
	if err != nil {
		t.Fatal(err)
	}
	x.mu.Lock()
	x.crl = der
	x.mu.Unlock()
}

func (x *x509Issuer) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	x.mu.Lock()
	defer x.mu.Unlock()
	w.Write(x.crl)
}

// A CRL output for a TLS server, in PEM, and the reload run when it
// changes -- and run again at the next sync when it failed.
func TestCRLOutputAndOnChange(t *testing.T) {
	dir := t.TempDir()
	x := newX509Issuer(t)
	now := time.Now()
	x.issue(t, 1, now.Add(-time.Minute), now.Add(time.Hour), 7)
	srv := httptest.NewTLSServer(x)
	defer srv.Close()
	ca := write(t, dir, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x.cert.Raw}))
	out := filepath.Join(dir, "ca.crl")
	a := agentFor(t, dir, fmt.Sprintf(`
state_dir = %q
source "x" {
  url     = %q
  x509_ca = %q
}
output "nginx" {
  path      = %q
  sources   = ["x"]
  format    = "pem"
  on_change = ["reload", "nginx"]
}
`, filepath.Join(dir, "state"), srv.URL+"/crl", ca, out), srv.Client())
	var calls [][]string
	fail := errors.New("nginx: [emerg] something")
	failing := true
	a.exec = func(argv []string) error {
		calls = append(calls, argv)
		if failing {
			return fail
		}
		return nil
	}
	ctx := context.Background()
	if err := a.syncOnce(ctx); err == nil || !strings.Contains(err.Error(), "output nginx") {
		t.Errorf("a failed reload is not reported: %v", err)
	}
	data, _ := os.ReadFile(out)
	if blk, _ := pem.Decode(data); blk == nil || blk.Type != "X509 CRL" {
		t.Fatalf("the output is not a PEM CRL: %q", data)
	}
	failing = false
	if err := a.syncOnce(ctx); err != nil {
		t.Errorf("the reload retried: %v", err)
	}
	if err := a.syncOnce(ctx); err != nil {
		t.Error(err)
	}
	if len(calls) != 2 || strings.Join(calls[1], " ") != "reload nginx" {
		t.Errorf("on_change calls: %v, want one failure then one success, and nothing for an unchanged list", calls)
	}
	// The CRL is judged by OpenSSL, when present: a certificate it lists is
	// refused.
	if bin, err := exec.LookPath("openssl"); err == nil {
		leaf := leafOf(t, x, 7)
		lp := write(t, dir, "leaf.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
		res, _ := exec.Command(bin, "verify", "-crl_check", "-CAfile", ca, "-CRLfile", out, lp).CombinedOutput()
		if !strings.Contains(string(res), "revoked") {
			t.Errorf("openssl on the written CRL: %s", res)
		}
	}
}

func leafOf(t *testing.T, x *x509Issuer, serial int64) *x509.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "u"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, x.cert, &k.PublicKey, x.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}
