// SPDX-License-Identifier: BSD-3-Clause

package revocation

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/krl"
	"golang.org/x/crypto/ssh"
)

// sshKeygen is the judge of what OpenSSH accepts. It is required where
// REVOCATION_REQUIRE_OPENSSH=1 (the linux and macOS CI lanes) and skipped
// elsewhere.
func sshKeygen(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the OpenSSH judge runs on the linux and darwin lanes")
	}
	p, err := exec.LookPath("ssh-keygen")
	if err != nil {
		if os.Getenv("REVOCATION_REQUIRE_OPENSSH") == "1" {
			t.Fatalf("ssh-keygen is required on this lane: %v", err)
		}
		t.Skip(err)
	}
	return p
}

// run runs a command in dir and returns its combined output and exit code.
func run(t *testing.T, dir string, name string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &ee):
		return string(out), ee.ExitCode()
	}
	t.Fatalf("%s %v: %v", name, args, err)
	return "", -1
}

func write(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// sshCA is an ed25519 SSH CA in Go.
type sshCA struct {
	signer ssh.Signer
	pub    ssh.PublicKey
}

func newSSHCA(t *testing.T) sshCA {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return sshCA{signer: s, pub: s.PublicKey()}
}

// krlOf is a KRL of version v revoking serials, issued at issued and
// expiring at expires (none when zero).
func krlOf(t *testing.T, ca sshCA, v uint64, issued, expires time.Time, serials ...uint64) []byte {
	t.Helper()
	b := krl.NewBuilder(v, "test")
	for _, s := range serials {
		b.RevokeSerial(ca.pub, s)
	}
	if !expires.IsZero() {
		b.SetExpires(expires)
	}
	raw, err := b.Marshal(issued)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// signedKRL is a KRL and its signature.
func signedKRL(t *testing.T, ca sshCA, v uint64, issued, expires time.Time, serials ...uint64) ([]byte, []byte) {
	t.Helper()
	raw := krlOf(t, ca, v, issued, expires, serials...)
	sig, err := SignKRL(raw, ca.signer)
	if err != nil {
		t.Fatal(err)
	}
	return raw, sig
}

// x509CA is an ECDSA CA.
type x509CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newX509CA(t *testing.T, cn string) x509CA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return x509CA{cert: c, key: key}
}

func (c x509CA) crl(t *testing.T, num int64, this, next time.Time, ext []pkix.Extension, serials ...int64) []byte {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: big.NewInt(s), RevocationTime: this})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(num),
		ThisUpdate: this, NextUpdate: next, RevokedCertificateEntries: entries, ExtraExtensions: ext}, c.cert, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pemOf(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func authorized(k ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

// x509CreateSelfSigned signs tpl with key, as its own issuer.
func x509CreateSelfSigned(tpl *x509.Certificate, key *ecdsa.PrivateKey) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func cmdIn(dir, bin string, args ...string) *exec.Cmd {
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	return cmd
}

// certOf is a user certificate with this serial signed by ca.
func certOf(t *testing.T, ca sshCA, serial uint64) *ssh.Certificate {
	t.Helper()
	upub, _, _ := ed25519.GenerateKey(rand.Reader)
	u, _ := ssh.NewPublicKey(upub)
	c := &ssh.Certificate{Key: u, Serial: serial, CertType: ssh.UserCert, KeyId: "u",
		ValidPrincipals: []string{"u"}, ValidBefore: ssh.CertTimeInfinity}
	if err := c.SignCert(rand.Reader, ca.signer); err != nil {
		t.Fatal(err)
	}
	return c
}
