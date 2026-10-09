// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/revocation"
	"golang.org/x/crypto/ssh"
)

func TestConfigRefusals(t *testing.T) {
	dir := t.TempDir()
	is := newSSHIssuer(t)
	sshCA := is.caFile(t, dir, "ca.pub")
	x := newX509Issuer(t)
	x509CA := write(t, dir, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x.cert.Raw}))
	cert := is.cert(t, 1)
	certFile := write(t, dir, "c-cert.pub", ssh.MarshalAuthorizedKey(cert))
	keyPEM := write(t, dir, "k.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}))
	state := fmt.Sprintf("state_dir = %q\n", filepath.Join(dir, "s"))
	abs := func(n string) string { return filepath.Join(dir, "out", n) }
	krlSrc := func(name string) string {
		return fmt.Sprintf("source %q {\n  url = \"https://x/krl\"\n  ssh_ca = %q\n}\n", name, sshCA)
	}
	crlSrc := func(name string) string {
		return fmt.Sprintf("source %q {\n  url = \"https://x/crl\"\n  x509_ca = %q\n}\n", name, x509CA)
	}
	out := func(name, path string, sources ...string) string {
		return fmt.Sprintf("output %q {\n  path = %q\n  sources = [%s]\n}\n", name, path, `"`+strings.Join(sources, `", "`)+`"`)
	}
	for name, c := range map[string]struct{ body, want string }{
		"relative state":       {`state_dir = "s"` + "\n" + krlSrc("a"), "absolute"},
		"no source":            {state, "no source"},
		"bad refresh":          {state + `refresh = "1ms"` + "\n" + krlSrc("a"), "refresh"},
		"bad name":             {state + krlSrc(".hidden"), "a name"},
		"name with slash":      {state + krlSrc("a/b"), "a name"},
		"twice":                {state + krlSrc("a") + krlSrc("a"), "twice"},
		"no url":               {state + "source \"a\" {\n  url = \"\"\n  ssh_ca = " + strconv.Quote(sshCA) + "\n}\n", "no url"},
		"no CA":                {state + "source \"a\" {\n  url = \"https://x\"\n}\n", "ssh_ca or x509_ca"},
		"both CAs":             {state + "source \"a\" {\n  url = \"https://x\"\n  ssh_ca = " + strconv.Quote(sshCA) + "\n  x509_ca = " + strconv.Quote(x509CA) + "\n}\n", "together"},
		"missing ssh_ca":       {state + "source \"a\" {\n  url = \"https://x\"\n  ssh_ca = \"/nonexistent\"\n}\n", "nonexistent"},
		"ssh_ca not a key":     {state + "source \"a\" {\n  url = \"https://x\"\n  ssh_ca = " + strconv.Quote(x509CA) + "\n}\n", "ssh_ca"},
		"ssh_ca a cert":        {state + "source \"a\" {\n  url = \"https://x\"\n  ssh_ca = " + strconv.Quote(certFile) + "\n}\n", "certificate"},
		"missing x509_ca":      {state + "source \"a\" {\n  url = \"https://x\"\n  x509_ca = \"/nonexistent\"\n}\n", "nonexistent"},
		"x509_ca not PEM":      {state + "source \"a\" {\n  url = \"https://x\"\n  x509_ca = " + strconv.Quote(sshCA) + "\n}\n", "no PEM certificate"},
		"x509_ca bad cert":     {state + "source \"a\" {\n  url = \"https://x\"\n  x509_ca = " + strconv.Quote(badCert(t, dir)) + "\n}\n", "x509_ca"},
		"x509_ca a key":        {state + "source \"a\" {\n  url = \"https://x\"\n  x509_ca = " + strconv.Quote(keyPEM) + "\n}\n", "no PEM certificate"},
		"bad max_age":          {state + "source \"a\" {\n  url = \"https://x\"\n  ssh_ca = " + strconv.Quote(sshCA) + "\n  max_age = \"-1h\"\n}\n", "max_age"},
		"revoke_keys on a CRL": {state + "source \"a\" {\n  url = \"https://x\"\n  x509_ca = " + strconv.Quote(x509CA) + "\n  revoke_keys = true\n}\n", "revoke_keys is for a KRL source"},
		"relative output":      {state + krlSrc("a") + out("o", "rel", "a"), "not absolute"},
		"same output twice":    {state + krlSrc("a") + out("o", abs("o"), "a") + out("p", abs("o"), "a"), "same file"},
		"no output source":     {state + krlSrc("a") + "output \"o\" {\n  path = " + strconv.Quote(abs("x")) + "\n  sources = []\n}\n", "names no source"},
		"unknown source":       {state + krlSrc("a") + out("o", abs("x"), "b"), "no source \"b\""},
		"mixed kinds":          {state + krlSrc("a") + crlSrc("b") + out("o", abs("x"), "a", "b"), "mixes"},
		"two CRLs":             {state + crlSrc("a") + crlSrc("b") + out("o", abs("x"), "a", "b"), "one source"},
		"format on a KRL":      {state + krlSrc("a") + "output \"o\" {\n  path = " + strconv.Quote(abs("x")) + "\n  sources = [\"a\"]\n  format = \"pem\"\n}\n", "format is for CRL"},
		"unknown format":       {state + crlSrc("a") + "output \"o\" {\n  path = " + strconv.Quote(abs("x")) + "\n  sources = [\"a\"]\n  format = \"p12\"\n}\n", "der or pem"},
		"not HCL":              {"{", ""},
		"unknown attribute":    {state + krlSrc("a") + "bogus = 1\n", ""},
	} {
		p := write(t, dir, "c.hcl", []byte(c.body))
		_, err := loadConfig(p)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error saying %q", name, err, c.want)
		}
	}
	if _, err := loadConfig(filepath.Join(dir, "absent.hcl")); err == nil {
		t.Error("a missing file: no error")
	}
	// Controls: each kind alone, and an output of each.
	ok := state + `refresh = "30s"` + "\n" + krlSrc("a") + krlSrc("b") + crlSrc("c") +
		out("sshd", abs("revoked.krl"), "a", "b") + out("nginx", abs("c.crl"), "c") +
		"source \"d\" {\n  url = \"https://x\"\n  ssh_ca = " + strconv.Quote(sshCA) + "\n  max_age = \"2h\"\n}\n"
	c, err := loadConfig(write(t, dir, "ok.hcl", []byte(ok)))
	if err != nil || c.refresh != 30*time.Second || c.Sources[3].maxAge != 2*time.Hour {
		t.Errorf("control: %v", err)
	}
}

func badCert(t *testing.T, dir string) string {
	return write(t, dir, "bad.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0}}))
}

func TestRunOnce(t *testing.T) {
	dir := t.TempDir()
	is := newSSHIssuer(t)
	now := time.Now()
	is.issue(1, now, time.Hour, 3)
	src := write(t, dir, "src.krl", is.raw)
	write(t, dir, "src.krl.sig", is.sig)
	out := filepath.Join(dir, "revoked.krl")
	cfg := write(t, dir, "revokd.hcl", []byte(fmt.Sprintf(`
state_dir = %q
source "a" {
  url    = %q
  ssh_ca = %q
}
output "sshd" {
  path    = %q
  sources = ["a"]
}
`, filepath.Join(dir, "state"), revocation.FileURL(src), is.caFile(t, dir, "ca.pub"), out)))
	var log bytes.Buffer
	if c := run([]string{"-config", cfg, "-once"}, io.Discard, &log); c != 0 {
		t.Fatalf("exit %d: %s", c, log.String())
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("no output: %v", err)
	}
	os.Remove(src)
	os.RemoveAll(filepath.Join(dir, "state"))
	if c := run([]string{"-config", cfg, "-once"}, io.Discard, &log); c != 1 {
		t.Errorf("no list: exit %d, want 1", c)
	}
	if c := run([]string{"-config", filepath.Join(dir, "absent.hcl")}, io.Discard, &log); c != 2 {
		t.Errorf("a missing config: exit %d", c)
	}
	if c := run([]string{"-bogus"}, io.Discard, &log); c != 2 {
		t.Errorf("a bad flag: exit %d", c)
	}
	// A state directory that cannot be made.
	blocked := write(t, dir, "blocked", nil)
	bad := write(t, dir, "bad.hcl", []byte(fmt.Sprintf("state_dir = %q\nsource \"a\" {\n  url = %q\n  ssh_ca = %q\n}\n",
		filepath.Join(blocked, "s"), revocation.FileURL(filepath.Join(dir, "x")), filepath.Join(dir, "ca.pub"))))
	if c := run([]string{"-config", bad}, io.Discard, &log); c != 1 {
		t.Errorf("an unusable state_dir: exit %d", c)
	}
}

// serve runs the agent and the mirror until its context ends.
func TestServe(t *testing.T) {
	dir := t.TempDir()
	is := newSSHIssuer(t)
	is.issue(1, time.Now(), time.Hour)
	src := write(t, dir, "src.krl", is.raw)
	write(t, dir, "src.krl.sig", is.sig)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	a := agentFor(t, dir, fmt.Sprintf(`
state_dir = %q
refresh   = "1s"
listen    = %q
source "a" {
  url    = %q
  ssh_ca = %q
}
`, filepath.Join(dir, "state"), addr, revocation.FileURL(src), is.caFile(t, dir, "ca.pub")))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, a, addr, &safeBuffer{}) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		res, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the mirror never became healthy: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("serve: %v", err)
	}
	// Without listen: the agent alone, until the context ends.
	ctx, cancel = context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	if err := serve(ctx, a, "", &safeBuffer{}); err != nil {
		t.Error(err)
	}
	// An address that cannot be listened on.
	if err := serve(context.Background(), a, "256.0.0.1:1", &safeBuffer{}); err == nil {
		t.Error("a bad address: no error")
	}
}

func TestRunCommand(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	if err := runCommand([]string{"/bin/sh", "-c", "exit 0"}); err != nil {
		t.Error(err)
	}
	if err := runCommand([]string{"/bin/sh", "-c", "echo nope; exit 3"}); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("a failing command: %v", err)
	}
}

func TestWriteAtomicFailures(t *testing.T) {
	dir := t.TempDir()
	if err := writeAtomic(filepath.Join(dir, "absent", "f"), []byte("x"), 0o644); err == nil {
		t.Error("a missing directory: no error")
	}
	p := filepath.Join(dir, "f")
	if err := writeAtomic(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "x" {
		t.Errorf("%q", b)
	}
	// Nothing left behind.
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("%d entries, want 1", len(ents))
	}
	_ = rand.Reader
}
