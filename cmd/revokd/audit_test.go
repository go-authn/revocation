// SPDX-License-Identifier: BSD-3-Clause

// The tests in this file were proofs of concept of a security audit of
// revokd v0.2.1; each failed before its fix and stays as its regression
// test.

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/krl"
	"github.com/go-authn/revocation"
	"golang.org/x/crypto/ssh"
)

// twoSources is a configuration with sources a and b merged into one sshd
// output; extraA goes into source a's block.
func twoSources(dir, ua, ca, ub, cb, out, extraA string) string {
	return fmt.Sprintf(`
state_dir = %q
source "a" {
  url    = %q
  ssh_ca = %q
  %s
}
source "b" {
  url    = %q
  ssh_ca = %q
}
output "sshd" {
  path    = %q
  sources = ["a", "b"]
}
`, filepath.Join(dir, "state"), ua, ca, extraA, ub, cb, out)
}

// A user's public key, revoked by one CA's list, locks that user out under
// every CA of the merged file: sshd checks a certificate's own key against
// it, whoever signed the certificate. In an output with several sources, a
// source's key revocations are left out unless it has revoke_keys; with it
// (the control), or alone in its output, they are kept.
func TestOneCAsListCannotRevokeAnotherCAsUserKeyUnlessTrustedWithKeys(t *testing.T) {
	for _, c := range []struct {
		name, extraA string
		alone        bool
		wantRevoked  bool
	}{
		{"shared output", "", false, false},
		{"shared output, revoke_keys", "revoke_keys = true", false, true},
		{"alone in its output", "", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			ia, ib := newSSHIssuer(t), newSSHIssuer(t)
			now := time.Now()
			ib.issue(1, now, time.Hour) // B revokes nothing
			bcert := ib.cert(t, 5)      // a user of B
			bld := krl.NewBuilder(1, "a")
			bld.RevokeKey(bcert.Key)                   // A names B's user's key
			bld.RevokeSerial(ia.signer.PublicKey(), 7) // and one of its own serials
			bld.SetExpires(now.Add(time.Hour))
			raw, _ := bld.Marshal(now)
			sig, _ := revocation.SignKRL(raw, ia.signer)
			ia.raw, ia.sig = raw, sig
			sa, sb := httptest.NewTLSServer(ia), httptest.NewTLSServer(ib)
			defer sa.Close()
			defer sb.Close()
			out := filepath.Join(dir, "revoked.krl")
			body := twoSources(dir, sa.URL+"/krl", ia.caFile(t, dir, "a.pub"), sb.URL+"/krl", ib.caFile(t, dir, "b.pub"), out, c.extraA)
			if c.alone {
				body = oneSource(dir, sa.URL+"/krl", ia.caFile(t, dir, "a.pub"), out)
			}
			a := agentFor(t, dir, body, sa.Client())
			if err := a.syncOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			got := revokedBy(t, out, bcert, ia.cert(t, 7))
			if got[0] != c.wantRevoked {
				t.Errorf("B's user's certificate (B revokes nothing) revoked = %v, want %v: A's list names the user's key", got[0], c.wantRevoked)
			}
			if !got[1] {
				t.Error("A's own serial 7 was lost")
			}
			if said := strings.Contains(a.log.(*safeBuffer).String(), "left out"); said == c.wantRevoked {
				t.Errorf("logged that revocations were left out: %v, want %v:\n%s", said, !c.wantRevoked, a.log.(*safeBuffer).String())
			}
		})
	}
}

// rawKRL writes a KRL by hand: n alternating 2 KB serial bitmaps under ca,
// ~8000 ranges each. ssh-keygen and krl.Parse read it; merged, 600 of them
// are past what krl's Builder keeps.
func rawKRL(ca ssh.PublicKey, n int, now time.Time, exp time.Time) []byte {
	var w bytes.Buffer
	u32 := func(v uint32) { binary.Write(&w, binary.BigEndian, v) }
	u64 := func(v uint64) { binary.Write(&w, binary.BigEndian, v) }
	str := func(b []byte) { u32(uint32(len(b))); w.Write(b) }
	w.WriteString("SSHKRL\n\x00")
	u32(1)
	u64(1)
	u64(uint64(now.Unix()))
	u64(0)
	str(nil)
	str([]byte("a"))
	var sect bytes.Buffer
	s32 := func(b *bytes.Buffer, v uint32) { binary.Write(b, binary.BigEndian, v) }
	s32(&sect, uint32(len(ca.Marshal())))
	sect.Write(ca.Marshal())
	s32(&sect, 0)
	bm := bytes.Repeat([]byte{0x55}, 2048)
	for i := 0; i < n; i++ {
		var sub bytes.Buffer
		binary.Write(&sub, binary.BigEndian, uint64(1+i*20000))
		s32(&sub, uint32(len(bm)))
		sub.Write(bm)
		sect.WriteByte(0x22) // KRL_SECTION_CERT_SERIAL_BITMAP
		s32(&sect, uint32(sub.Len()))
		sect.Write(sub.Bytes())
	}
	w.WriteByte(1) // KRL_SECTION_CERTIFICATES
	str(sect.Bytes())
	var ext, body bytes.Buffer
	binary.Write(&body, binary.BigEndian, uint64(exp.Unix()))
	s32(&ext, uint32(len(krl.ExtensionExpires)))
	ext.WriteString(krl.ExtensionExpires)
	ext.WriteByte(0)
	s32(&ext, uint32(body.Len()))
	ext.Write(body.Bytes())
	w.WriteByte(255) // KRL_SECTION_EXTENSION
	str(ext.Bytes())
	return w.Bytes()
}

// One CA's list that cannot be merged (~4.9M serial ranges, signed by that
// CA) fails closed for that CA alone: its certificates are refused, the
// other CA's are judged by the other CA's list, and /healthz names the
// source. Before, the whole output failed closed and every CA's users were
// locked out.
func TestAListThatCannotBeMergedFailsClosedForItsOwnCAOnly(t *testing.T) {
	dir := t.TempDir()
	ia, ib := newSSHIssuer(t), newSSHIssuer(t)
	now := time.Now()
	ib.issue(1, now, time.Hour, 9) // B revokes its serial 9
	raw := rawKRL(ia.signer.PublicKey(), 600, now, now.Add(time.Hour))
	sig, err := revocation.SignKRL(raw, ia.signer)
	if err != nil {
		t.Fatal(err)
	}
	ia.raw, ia.sig = raw, sig
	sa, sb := httptest.NewTLSServer(ia), httptest.NewTLSServer(ib)
	defer sa.Close()
	defer sb.Close()
	out := filepath.Join(dir, "revoked.krl")
	a := agentFor(t, dir, twoSources(dir, sa.URL+"/krl", ia.caFile(t, dir, "a.pub"), sb.URL+"/krl", ib.caFile(t, dir, "b.pub"), out, ""), sa.Client())
	err = a.syncOnce(context.Background())
	if err == nil {
		t.Error("sync: no error, while A's list could not be merged")
	}
	got := revokedBy(t, out, ib.cert(t, 5), ib.cert(t, 9), ia.cert(t, 2))
	if got[0] {
		t.Error("CA B's unrevoked certificate 5 is refused because of CA A's list")
	}
	if !got[1] {
		t.Error("CA B's revoked serial 9 is accepted: B's list was not merged")
	}
	if !got[2] {
		t.Error("CA A's certificate is accepted: A's list could not be merged, and A did not fail closed")
	}
	h := httptest.NewRecorder()
	a.health(h, nil)
	if body := h.Body.String(); h.Code != 503 || !strings.Contains(body, "source a: its list cannot be merged") || strings.Contains(body, "source b") {
		t.Errorf("healthz %d %q: want 503 naming source a alone", h.Code, body)
	}
	// The trial is made once per issue of the list, not at every sync.
	a.syncOnce(context.Background())
	if c := a.trials["sshd\x00a"]; c.l == nil || c.err == nil {
		t.Errorf("trial of a: %+v", c)
	}
	// An output that cannot be written says so too, beside the source.
	a.cfg.Outputs[0].Path = filepath.Join(dir, "missing", "revoked.krl")
	clear(a.written)
	a.syncOnce(context.Background())
	if err := a.outErrs["sshd"]; err == nil || !strings.Contains(err.Error(), "source a") || !strings.Contains(err.Error(), "missing") {
		t.Errorf("an unwritable output: %v", err)
	}
}

// Lists that merge alone but not together (each ~2.5M serial ranges) fail
// the whole output closed: no one source is at fault, and keeping the old
// file would let a later lapse go unseen.
func TestListsThatMergeAloneButNotTogetherFailTheOutputClosed(t *testing.T) {
	dir := t.TempDir()
	ia, ib := newSSHIssuer(t), newSSHIssuer(t)
	now := time.Now()
	for _, is := range []*sshIssuer{ia, ib} {
		raw := rawKRL(is.signer.PublicKey(), 300, now, now.Add(time.Hour))
		sig, err := revocation.SignKRL(raw, is.signer)
		if err != nil {
			t.Fatal(err)
		}
		is.raw, is.sig = raw, sig
	}
	sa, sb := httptest.NewTLSServer(ia), httptest.NewTLSServer(ib)
	defer sa.Close()
	defer sb.Close()
	out := filepath.Join(dir, "revoked.krl")
	a := agentFor(t, dir, twoSources(dir, sa.URL+"/krl", ia.caFile(t, dir, "a.pub"), sb.URL+"/krl", ib.caFile(t, dir, "b.pub"), out, ""), sa.Client())
	if err := a.syncOnce(context.Background()); err == nil {
		t.Error("sync: no error")
	}
	if got := revokedBy(t, out, ia.cert(t, 2), ib.cert(t, 2)); !got[0] || !got[1] {
		t.Errorf("revoked %v, want both CAs refused", got)
	}
	if err := a.outErrs["sshd"]; err == nil || !strings.Contains(err.Error(), "every certificate of its CAs is refused") {
		t.Errorf("output error: %v", err)
	}
	// And when even the fail-closed list cannot be written, both are said.
	a.cfg.Outputs[0].Path = filepath.Join(dir, "missing", "revoked.krl")
	clear(a.written)
	a.syncOnce(context.Background())
	if err := a.outErrs["sshd"]; err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("an unwritable output: %v", err)
	}
}

// The state directory is refused when it is a symbolic link (whoever owns
// the link re-points it), or when it belongs to a user other than revokd's
// own or root, as sshd's StrictModes does. A directory of revokd's own user
// is the control.
func TestStateDirMustNotBeASymlinkNorAnotherUsersDirectory(t *testing.T) {
	target := t.TempDir()
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkStateDir(target); err != nil {
		t.Fatalf("control: revokd's own directory: %v", err)
	}
	link := filepath.Join(t.TempDir(), "state")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("no symbolic link here: %v", err)
	}
	if err := checkStateDir(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("a symbolic link to a good directory: %v", err)
	}
	if runtime.GOOS == "windows" {
		return // no owner in fs.FileInfo: ACLs decide
	}
	me := os.Geteuid()
	if me == 0 {
		return // every directory is root's to replace
	}
	defer func(f func() int) { geteuid = f }(geteuid)
	geteuid = func() int { return me + 4242 } // the directory is now another user's
	if err := checkStateDir(target); err == nil || !strings.Contains(err.Error(), "belongs to uid") {
		t.Errorf("a directory another user owns: %v", err)
	}
	// Root's directory is accepted: root can replace anything anyway.
	if fi, err := os.Stat("/"); err == nil && fi.Mode().Perm()&0o022 == 0 {
		if err := checkStateDir("/"); err != nil {
			t.Errorf("root's directory: %v", err)
		}
	}
}
