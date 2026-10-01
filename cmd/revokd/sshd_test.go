// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/go-authn/krl"
	"github.com/go-authn/revocation"
	"golang.org/x/crypto/ssh"
)

// A real sshd, run as the test's own user on a loopback port, with
// RevokedKeys pointing at what revokd writes: what it refuses is judged by
// sshd itself, through a real ssh login, and it is never restarted.
//
//  1. nothing revoked: the certificate logs in;
//  2. its serial revoked: refused;
//  3. a list revoking nothing that then lapses: refused -- the fail-closed
//     list -- although nothing revokes it;
//  4. a fresh list: logs in again.
//
// It needs sshd and ssh; REVOCATION_REQUIRE_SSHD=1 makes their absence a
// failure (the linux CI lane), and it is skipped otherwise.
func TestSSHDJudgesWhatRevokdWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sshd is not run on Windows here")
	}
	sshd, err1 := lookSSHD()
	sshBin, err2 := exec.LookPath("ssh")
	keygen, err3 := exec.LookPath("ssh-keygen")
	if err1 != nil || err2 != nil || err3 != nil {
		if os.Getenv("REVOCATION_REQUIRE_SSHD") == "1" {
			t.Fatalf("sshd, ssh and ssh-keygen are required on this lane: %v %v %v", err1, err2, err3)
		}
		t.Skip("no sshd here")
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	// A short path: sshd and ssh are fussy about long ones (control
	// sockets, and the 108-byte limit some platforms put on them).
	dir, err := os.MkdirTemp("", "revokd-sshd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	at := func(n string) string { return filepath.Join(dir, n) }
	for _, k := range []string{"host", "ca", "user"} {
		if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-f", at(k)).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v %s", err, out)
		}
	}
	if out, err := exec.Command(keygen, "-q", "-s", at("ca"), "-I", "e2e", "-n", me.Username, "-z", "10", at("user.pub")).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -s: %v %s", err, out)
	}
	caKey, _ := os.ReadFile(at("ca"))
	ca, err := ssh.ParsePrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}

	issue := func(v uint64, ttl time.Duration, serials ...uint64) {
		t.Helper()
		b := krl.NewBuilder(v, "e2e")
		for _, s := range serials {
			b.RevokeSerial(ca.PublicKey(), s)
		}
		now := time.Now()
		b.SetExpires(now.Add(ttl))
		raw, err := b.Marshal(now)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := revocation.SignKRL(raw, ca)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(at("issued.krl.sig"), sig, 0o644)
		os.WriteFile(at("issued.krl"), raw, 0o644)
	}
	issue(1, time.Hour)
	a := agentFor(t, dir, fmt.Sprintf(`
state_dir = %q
source "e2e" {
  url    = %q
  ssh_ca = %q
}
output "sshd" {
  path    = %q
  sources = ["e2e"]
}
`, at("state"), revocation.FileURL(at("issued.krl")), at("ca.pub"), at("revoked.krl")))
	sync := func() { a.syncOnce(context.Background()) }
	sync()

	port := freePort(t)
	cfg := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
PidFile %s
TrustedUserCAKeys %s
RevokedKeys %s
AuthorizedKeysFile none
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
StrictModes no
UsePAM no
`, port, at("host"), at("sshd.pid"), at("ca.pub"), at("revoked.krl"))
	write(t, dir, "sshd_config", []byte(cfg))
	daemon := exec.Command(sshd, "-D", "-e", "-f", at("sshd_config"))
	logf, _ := os.Create(at("sshd.log"))
	daemon.Stderr = logf
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { daemon.Process.Kill(); daemon.Wait() })
	waitPort(t, port)

	login := func() bool {
		cmd := exec.Command(sshBin, "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=10",
			"-i", at("user"), "-o", "CertificateFile="+at("user-cert.pub"),
			"-p", fmt.Sprint(port), "-l", me.Username, "127.0.0.1", "true")
		return cmd.Run() == nil
	}
	steps := []struct {
		name string
		do   func()
		want bool
	}{
		{"nothing revoked", func() {}, true},
		{"its serial revoked", func() { issue(2, time.Hour, 10); sync() }, false},
		{"a list revoking nothing, current", func() { issue(3, 3*time.Second); sync() }, true},
		{"the same list, lapsed", func() { time.Sleep(4 * time.Second); sync() }, false},
		{"a fresh list", func() { issue(4, time.Hour); sync() }, true},
	}
	for i, s := range steps {
		s.do()
		if got := login(); got != s.want {
			log, _ := os.ReadFile(at("sshd.log"))
			t.Fatalf("step %d, %s: login = %v, want %v\nsshd:\n%s", i+1, s.name, got, s.want, log)
		}
	}
	if daemon.ProcessState != nil {
		t.Error("sshd exited: it was meant to read every change without a restart")
	}
}

func lookSSHD() (string, error) {
	if p, err := exec.LookPath("sshd"); err == nil {
		return p, nil
	}
	for _, p := range []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", os.ErrNotExist
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitPort(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("sshd never listened")
}
