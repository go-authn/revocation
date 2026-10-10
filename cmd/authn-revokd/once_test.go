// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// -once exits 1 both when a list is not current and when a fetch failed --
// the timer exists to say so before the list lapses -- but the two are said
// apart. v0.6.1 called a source "not current" while the list it held was
// current until an hour later, which is what the outputs carried.
func TestOnceSaysAFailedFetchApartFromALapsedList(t *testing.T) {
	dir := t.TempDir()
	is := newSSHIssuer(t)
	now := time.Now()
	is.issue(1, now, time.Hour, 10)
	srv := httptest.NewTLSServer(is)
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
`, filepath.Join(dir, "state"), srv.URL+"/krl", is.caFile(t, dir, "a.pub"), filepath.Join(dir, "out.krl")), srv.Client())
	ctx := context.Background()
	if err := a.syncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	// The issuer stops; the list held is still current.
	srv.Close()
	err := a.syncOnce(ctx)
	if err == nil {
		t.Fatal("a failed fetch went unreported")
	}
	if strings.Contains(err.Error(), "not current") {
		t.Errorf("a source holding a current list is called not current: %v", err)
	}
	if !strings.Contains(err.Error(), "not fetched: a (the list held is current until ") {
		t.Errorf("does not say the fetch failed and until when the list holds: %v", err)
	}

	// An hour later the list has lapsed: now it is not current.
	a.now = func() time.Time { return now.Add(61 * time.Minute) }
	err = a.syncOnce(ctx)
	if err == nil || !strings.Contains(err.Error(), "not current: a") || strings.Contains(err.Error(), "not fetched") {
		t.Errorf("a lapsed list: %v", err)
	}
}

// -help is a question answered, not a usage error.
func TestHelpExitsZero(t *testing.T) {
	var out, log safeBuffer
	if code := run([]string{"-help"}, &out, &log); code != 0 {
		t.Errorf("-help exited %d", code)
	}
	if !strings.Contains(log.String(), "-once") {
		t.Errorf("-help did not print the flags: %q", log.String())
	}
}

// A missing configuration says so plainly, without hclparse's "<nil>:".
func TestAMissingConfigurationSaysSoPlainly(t *testing.T) {
	var out, log safeBuffer
	missing := filepath.Join(t.TempDir(), "absent.hcl")
	if code := run([]string{"-config", missing}, &out, &log); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if got := log.String(); strings.Contains(got, "<nil>") || !strings.Contains(got, missing+": no such file or directory") {
		t.Errorf("printed %q", got)
	}
}
