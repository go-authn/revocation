// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// -version answers without reading a configuration: an authn-revokd found
// on a server must say what it is before anything else about it is known.
// It says authn-revokd: the name it is installed and released under, which
// the release workflow checks the tag against.
func TestVersionNeedsNoConfiguration(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"-config", "/nonexistent/revokd.hcl", "-version"}, &out); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if !strings.HasPrefix(out.String(), "authn-revokd ") || strings.TrimSpace(out.String()) == "authn-revokd" {
		t.Errorf("printed %q", out.String())
	}
}

// Errors name the command as it is installed, not as it was called before
// v0.6.0: a journal grepped for authn-revokd must find them.
func TestErrorsNameTheCommand(t *testing.T) {
	var out bytes.Buffer
	missing := filepath.Join(t.TempDir(), "absent.hcl")
	if code := run([]string{"-config", missing}, &out); code != 2 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if !strings.HasPrefix(out.String(), "authn-revokd: "+missing+": ") {
		t.Errorf("printed %q", out.String())
	}
}

// The default configuration moved in v0.6.0. A host upgraded without moving
// it is told where the old one is, and only then: not when -config was
// given, not when the new one exists, not when there is no old one.
func TestTheOldDefaultConfigurationIsPointedAt(t *testing.T) {
	dir := t.TempDir()
	newPath, oldPath := filepath.Join(dir, "new.hcl"), filepath.Join(dir, "old.hcl")
	if h := migrationHint(false, newPath, oldPath); h != "" {
		t.Errorf("no old file, hint %q", h)
	}
	write(t, dir, "old.hcl", []byte("state_dir = \"/x\"\n"))
	h := migrationHint(false, newPath, oldPath)
	if !strings.Contains(h, oldPath) || !strings.Contains(h, newPath) {
		t.Errorf("old file there, hint %q", h)
	}
	if h := migrationHint(true, newPath, oldPath); h != "" {
		t.Errorf("-config given, hint %q", h)
	}
	write(t, dir, "new.hcl", []byte("state_dir = \"/x\"\n"))
	if h := migrationHint(false, newPath, oldPath); h != "" {
		t.Errorf("new file there, hint %q", h)
	}
}
