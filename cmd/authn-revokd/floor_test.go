// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-authn/revocation"
)

// ⛔ A state copy that does not verify (damaged, or written under another CA
// key) must not take the rollback guard with it (PROTOCOL.md rule 2). Its
// content is not trusted, but its version and issue time still order what
// comes next: a replayed older list, signed and unexpired, is refused until
// a list that verifies and follows arrives.
//
// On v0.6.7 the copy was dropped, the guard with it, and the replayed v1
// un-revoked serial 10.
func TestUnverifiableStateCopyKeepsTheRollbackGuard(t *testing.T) {
	dir := t.TempDir()
	is := newSSHIssuer(t)
	now := time.Now()
	is.issue(1, now.Add(-3*time.Minute), time.Hour) // v1 revokes nothing
	v1raw, v1sig := is.raw, is.sig
	srv := httptest.NewTLSServer(is)
	defer srv.Close()
	out := filepath.Join(dir, "revoked.krl")
	body := oneSource(dir, srv.URL+"/krl", is.caFile(t, dir, "a.pub"), out)
	a := agentFor(t, dir, body, srv.Client())
	if err := a.syncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	is.issue(2, now.Add(-2*time.Minute), time.Hour, 10) // v2 revokes serial 10
	if err := a.syncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The state copy is replaced by one that does not verify: v2's list with
	// v1's signature.
	state := filepath.Join(dir, "state", "a.state")
	if err := os.WriteFile(state, encodeState(&revocation.List{Raw: is.raw, Sig: v1sig}), 0o600); err != nil {
		t.Fatal(err)
	}

	// A hostile mirror replays v1, properly signed and unexpired.
	is.mu.Lock()
	is.raw, is.sig = v1raw, v1sig
	is.mu.Unlock()
	again := agentFor(t, dir, body, srv.Client())
	err := again.syncOnce(context.Background())
	if held := again.fetchers[0].Held(); held != nil {
		t.Errorf("an unverifiable state copy dropped the rollback guard: the replayed v1 was accepted (sync err=%v, held v%v)", err, held.Version)
	}
	if err == nil {
		t.Error("the replayed v1 was refused silently: sync reported no error")
	}

	// Fail closed is not a lockout: a newer list that verifies is taken.
	is.issue(3, now.Add(-time.Minute), time.Hour, 10, 11)
	if err := again.syncOnce(context.Background()); err != nil {
		t.Errorf("a list newer than the unverifiable copy was refused: %v", err)
	}
	if held := again.fetchers[0].Held(); held == nil || held.Version.Int64() != 3 {
		t.Errorf("held after v3: %v", held)
	}
}
