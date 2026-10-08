// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"strings"
	"testing"
)

// -version answers without reading a configuration: a revokd found on a
// server must say what it is before anything else about it is known.
func TestVersionNeedsNoConfiguration(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"-config", "/nonexistent/revokd.hcl", "-version"}, &out); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if !strings.HasPrefix(out.String(), "revokd ") || strings.TrimSpace(out.String()) == "revokd" {
		t.Errorf("printed %q", out.String())
	}
}
