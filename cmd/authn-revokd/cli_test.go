// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/revocation"
)

// cliFixture writes a configuration with one current SSH list and returns its
// path and the output it writes.
func cliFixture(t *testing.T) (cfg, out string) {
	t.Helper()
	dir := t.TempDir()
	is := newSSHIssuer(t)
	is.issue(1, time.Now(), time.Hour, 3)
	src := write(t, dir, "src.krl", is.raw)
	write(t, dir, "src.krl.sig", is.sig)
	out = filepath.Join(dir, "revoked.krl")
	cfg = write(t, dir, "revokd.hcl", []byte(fmt.Sprintf(`
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
	return cfg, out
}

// Every spelling the README, docs/install.md and the systemd units ever showed
// still works, and so do the POSIX ones: same exit status, same effect.
func TestEverySpellingOfTheFlagsWorks(t *testing.T) {
	cfg, out := cliFixture(t)
	for _, tc := range []struct {
		name string
		args []string
		warn string // expected deprecation, "" for none
	}{
		{"legacy -config -once", []string{"-config", cfg, "-once"}, "-once is deprecated, use --once"},
		{"legacy -config=PATH -once", []string{"-config=" + cfg, "-once"}, "-config is deprecated, use --config"},
		{"POSIX --config --once", []string{"--config", cfg, "--once"}, ""},
		{"POSIX --config=PATH --once", []string{"--config=" + cfg, "--once"}, ""},
		{"short -c -o", []string{"-c", cfg, "-o"}, ""},
		{"once first", []string{"-once", "--config", cfg}, "-once is deprecated"},
	} {
		os.Remove(out)
		var o, log safeBuffer
		if c := run(tc.args, &o, &log); c != 0 {
			t.Errorf("%s: exit %d: %s", tc.name, c, log.String())
			continue
		}
		if _, err := os.Stat(out); err != nil {
			t.Errorf("%s: no output written: %v", tc.name, err)
		}
		got := log.String()
		if tc.warn == "" && strings.Contains(got, "deprecated") {
			t.Errorf("%s: unexpected deprecation: %q", tc.name, got)
		}
		if tc.warn != "" && !strings.Contains(got, tc.warn) {
			t.Errorf("%s: no deprecation line %q in %q", tc.name, tc.warn, got)
		}
	}
}

// -version and --version answer the same, without reading the configuration.
func TestVersionBothSpellings(t *testing.T) {
	for _, arg := range []string{"-version", "--version", "-v"} {
		var out, log safeBuffer
		if c := run([]string{"--config", "/nonexistent/revokd.hcl", arg}, &out, &log); c != 0 {
			t.Fatalf("%s: exit %d: %s", arg, c, log.String())
		}
		if want := cmdName + " " + version() + "\n"; out.String() != want {
			t.Errorf("%s printed %q, want %q", arg, out.String(), want)
		}
	}
}

// -help, --help and -h are a question answered: exit 0, the flags on stdout.
func TestHelpSpellings(t *testing.T) {
	for _, arg := range []string{"-help", "--help", "-h"} {
		var out, log safeBuffer
		if c := run([]string{arg}, &out, &log); c != 0 {
			t.Errorf("%s: exit %d", arg, c)
		}
		for _, want := range []string{"--config", "--once", "--version", "-help"} {
			if want == "-help" {
				want = "--help"
			}
			if !strings.Contains(out.String(), want) {
				t.Errorf("%s: help lacks %s: %q", arg, want, out.String())
			}
		}
	}
}

// The exit statuses of the flag-package version are unchanged, reached through
// the replaceable osExit of main as well.
func TestExitStatuses(t *testing.T) {
	cfg, _ := cliFixture(t)
	missing := filepath.Join(t.TempDir(), "absent.hcl")
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"ok", []string{"-config", cfg, "-once"}, 0},
		{"missing config", []string{"-config", missing}, 2},
		{"missing config, POSIX", []string{"--config", missing}, 2},
		{"unknown flag", []string{"-bogus"}, 2},
		{"unknown POSIX flag", []string{"--bogus"}, 2},
		{"unexpected argument", []string{"extra"}, 2},
		{"flag without value", []string{"--config"}, 2},
	} {
		var out, log bytes.Buffer
		if c := run(tc.args, &out, &log); c != tc.want {
			t.Errorf("%s: exit %d, want %d (%s)", tc.name, c, tc.want, log.String())
		}
	}

	oldExit, oldArgs := osExit, os.Args
	defer func() { osExit, os.Args = oldExit, oldArgs }()
	got := -1
	osExit = func(c int) { got = c }
	os.Args = []string{cmdName, "--config", missing}
	main()
	if got != 2 {
		t.Errorf("main with a missing configuration: osExit(%d), want 2", got)
	}
}

// What follows -- and the value of --config are never rewritten.
func TestNormalizeArgsLeavesValuesAlone(t *testing.T) {
	var log bytes.Buffer
	got := normalizeArgs([]string{"--config", "-once", "--", "-version"}, &log)
	if want := "--config -once -- -version"; strings.Join(got, " ") != want {
		t.Errorf("got %q, want %q", strings.Join(got, " "), want)
	}
	if log.Len() != 0 {
		t.Errorf("warned: %q", log.String())
	}
}

// The systemd units shipped in packaging/ run through RootCmd with the
// arguments they carry (the configuration swapped for the fixture's).
func TestShippedUnitsStillParse(t *testing.T) {
	cfg, _ := cliFixture(t)
	for _, unit := range []string{"authn-revokd.service", "authn-revokd-once.service"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "packaging", "systemd", unit))
		if err != nil {
			t.Fatal(err)
		}
		var args []string
		for _, line := range strings.Split(string(b), "\n") {
			if rest, ok := strings.CutPrefix(line, "ExecStart=/usr/local/bin/"+cmdName); ok {
				args = strings.Fields(rest)
			}
		}
		if args == nil {
			t.Fatalf("%s: no ExecStart", unit)
		}
		once := false
		for i, a := range args {
			if a == "-config" || a == "--config" {
				args[i+1] = cfg
			}
			once = once || a == "-once" || a == "--once"
		}
		if !once {
			continue // the daemon would run until a signal; its flags were parsed by the cases above
		}
		var out, log safeBuffer
		if c := run(args, &out, &log); c != 0 {
			t.Errorf("%s: %v exited %d: %s", unit, args, c, log.String())
		}
	}
}
