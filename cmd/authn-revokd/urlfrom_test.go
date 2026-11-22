// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-authn/secretsource"
)

func secretFile(t *testing.T, content string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("secretsource's file: checks an ACL there")
	}
	p := filepath.Join(t.TempDir(), "url")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestURLFromResolves(t *testing.T) {
	const u = "https://reader:s3cret@idp.example/ssh/krl"
	s := &sourceBlock{URLFrom: "file:" + secretFile(t, u+"\n")}
	if err := s.resolveURL(); err != nil || s.URL != u {
		t.Fatalf("url %q, err %v", s.URL, err)
	}
}

func TestURLFromResolvesFromACredential(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("systemd-creds: resolves on Linux only")
	}
	dir := filepath.Join(t.TempDir(), "creds")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	const u = "https://idp.example/crl?token=abc"
	if err := os.WriteFile(filepath.Join(dir, "univ-a"), []byte(u), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	s := &sourceBlock{URLFrom: "systemd-creds:univ-a"}
	if err := s.resolveURL(); err != nil || s.URL != u {
		t.Fatalf("url %q, err %v", s.URL, err)
	}
}

func TestURLAndURLFromTogetherAreRefused(t *testing.T) {
	s := &sourceBlock{URL: "https://idp.example/krl", URLFrom: "systemd-creds:x"}
	err := s.resolveURL()
	if err == nil || !strings.Contains(err.Error(), "both set") {
		t.Fatalf("got %v", err)
	}
}

func TestNoURLIsRefused(t *testing.T) {
	err := (&sourceBlock{}).resolveURL()
	if err == nil || !strings.Contains(err.Error(), "no url") {
		t.Fatalf("got %v", err)
	}
}

func TestAURLWithACredentialIsRefused(t *testing.T) {
	for _, u := range []string{
		"https://reader:s3cret@idp.example/krl",
		"https://idp.example/krl?token=abc",
		"https://idp.example/krl?Access_Token=abc",
		"https://idp.example/krl?a=1&api_key=abc",
	} {
		err := (&sourceBlock{URL: u}).resolveURL()
		if err == nil || !strings.Contains(err.Error(), "url_from") {
			t.Errorf("%s: got %v", u, err)
		}
		if err != nil && (strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "abc")) {
			t.Errorf("%s: the refusal repeats the secret: %v", u, err)
		}
	}
	// The control: a plain URL, and a user name alone (no secret), are not refused.
	for _, u := range []string{"https://idp.example/krl", "https://reader@idp.example/krl?v=2", "file:///var/krl"} {
		if err := (&sourceBlock{URL: u}).resolveURL(); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}

func TestOversizedURLFromIsRefused(t *testing.T) {
	s := &sourceBlock{URLFrom: "file:" + secretFile(t, "https://idp.example/"+strings.Repeat("a", secretsource.MaxSize))}
	if err := s.resolveURL(); !errors.Is(err, secretsource.ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func TestURLFromWithNoSchemeIsRefused(t *testing.T) {
	s := &sourceBlock{URLFrom: "/etc/revokd/url"}
	if err := s.resolveURL(); err == nil {
		t.Fatal("a bare path was taken for a reference")
	}
}

func TestURLFromHoldingNothingIsRefused(t *testing.T) {
	s := &sourceBlock{URLFrom: "file:" + secretFile(t, "  \n")}
	if err := s.resolveURL(); err == nil {
		t.Fatal("a blank URL was accepted")
	}
}
