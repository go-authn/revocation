// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The state file is read back at start-up from a directory only the daemon's
// user may write to, but a truncated or damaged one (a full disk, a restore
// from a backup) must be refused, never panic or slice out of range.
func FuzzDecodeState(f *testing.F) {
	f.Add([]byte(stateMagic))
	f.Add(append([]byte(stateMagic), 0, 0, 0, 0, 0, 0, 0, 3, 'a', 'b', 'c', 's', 'i', 'g'))
	f.Add(append([]byte(stateMagic), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		raw, sig, err := decodeState(b)
		if err != nil {
			return
		}
		if len(raw)+len(sig) > len(b) {
			t.Fatalf("decoded %d+%d bytes out of %d", len(raw), len(sig), len(b))
		}
	})
}

// The configuration is read as root-owned input but is hand-written: it must
// be refused with an error, whatever it holds.
func FuzzLoadConfig(f *testing.F) {
	f.Add(`state_dir = "/var/lib/x"
source "a" {
  url    = "https://h/x"
  ssh_ca = "/nonexistent"
}
output "o" {
  path    = "/tmp/o"
  sources = ["a"]
}`)
	f.Add(`refresh = "1s"`)
	f.Add(`source "a" { url = 1 }`)
	f.Add("\x00\xff{")
	dir := f.TempDir()
	p := filepath.Join(dir, "c.hcl")
	f.Fuzz(func(t *testing.T, body string) {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Skip(err)
		}
		if c, err := loadConfig(p); err == nil && (len(c.Sources) == 0 || c.refresh <= 0) {
			t.Fatalf("a configuration without a source or a refresh was accepted: %+v", c)
		}
	})
}
