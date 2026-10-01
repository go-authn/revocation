// SPDX-License-Identifier: BSD-3-Clause

package revocation

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/krl"
	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

// What SignKRL writes, ssh-keygen -Y verify accepts; what ssh-keygen -Y sign
// writes, VerifyKRL accepts. Each side refuses the other's signature in the
// wrong namespace -- the control that shows the namespace is checked.
func TestKRLSignatureJudgedBySshKeygen(t *testing.T) {
	bin := sshKeygen(t)
	dir := t.TempDir()
	run(t, dir, bin, "-q", "-t", "ed25519", "-N", "", "-C", "ca", "-f", "ca")
	pubData, _ := os.ReadFile(filepath.Join(dir, "ca.pub"))
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubData)
	if err != nil {
		t.Fatal(err)
	}
	privData, _ := os.ReadFile(filepath.Join(dir, "ca"))
	signer, err := ssh.ParsePrivateKey(privData)
	if err != nil {
		t.Fatal(err)
	}
	ca := sshCA{signer: signer, pub: pub}
	now := time.Now()
	raw, sig := signedKRL(t, ca, 3, now, now.Add(time.Hour), 5, 6)
	write(t, dir, "l.krl", raw)
	write(t, dir, "l.krl.sig", sig)
	write(t, dir, "allowed", []byte(`ca@test namespaces="`+Namespace+`" `+authorized(pub)+"\n"))
	verify := func(ns, sigFile string) int {
		cmd := []string{"-Y", "verify", "-f", "allowed", "-I", "ca@test", "-n", ns, "-s", sigFile}
		c := execIn(t, dir, bin, cmd, raw)
		return c
	}
	if c := verify(Namespace, "l.krl.sig"); c != 0 {
		t.Errorf("ssh-keygen -Y verify refuses SignKRL's signature (exit %d)", c)
	}
	if c := verify("file", "l.krl.sig"); c == 0 {
		t.Error("control: ssh-keygen accepted the signature in another namespace")
	}

	// The other way: ssh-keygen signs, VerifyKRL checks. (It will not
	// overwrite a signature file.)
	os.Remove(filepath.Join(dir, "l.krl.sig"))
	run(t, dir, bin, "-Y", "sign", "-f", "ca", "-n", Namespace, "l.krl")
	theirs, _ := os.ReadFile(filepath.Join(dir, "l.krl.sig"))
	if bytes.Equal(theirs, sig) {
		t.Fatal("ssh-keygen did not write its own signature")
	}
	if _, err := VerifyKRL(raw, theirs, pub); err != nil {
		t.Errorf("VerifyKRL refuses ssh-keygen's signature: %v", err)
	}
	os.Remove(filepath.Join(dir, "l.krl.sig"))
	run(t, dir, bin, "-Y", "sign", "-f", "ca", "-n", "file", "l.krl")
	other, _ := os.ReadFile(filepath.Join(dir, "l.krl.sig"))
	if _, err := VerifyKRL(raw, other, pub); err == nil {
		t.Error("VerifyKRL accepted ssh-keygen's signature in the namespace \"file\"")
	}
}

func execIn(t *testing.T, dir, bin string, args []string, stdin []byte) int {
	t.Helper()
	p := write(t, dir, "stdin", stdin)
	f, _ := os.Open(p)
	defer f.Close()
	cmd := cmdIn(dir, bin, args...)
	cmd.Stdin = f
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("%s %v: %s", bin, args, out)
		return 1
	}
	return 0
}

func TestVerifyKRLRefusals(t *testing.T) {
	ca, other := newSSHCA(t), newSSHCA(t)
	now := time.Now()
	raw, sig := signedKRL(t, ca, 1, now, now.Add(time.Hour), 7)
	if l, err := VerifyKRL(raw, sig, ca.pub); err != nil || l.Version.Uint64() != 1 || !l.Expires.Equal(now.Add(time.Hour).Truncate(time.Second).UTC()) {
		t.Fatalf("control: %v %+v", err, l)
	}
	tampered := bytes.Clone(raw)
	tampered[len(tampered)-1] ^= 1
	_, otherSig := signedKRL(t, other, 1, now, now.Add(time.Hour), 7)
	noExpiry := krlOf(t, ca, 1, now, time.Time{})
	noExpirySig, err := sshsig.Sign(bytes.NewReader(noExpiry), ca.signer, sshsig.HashSHA512, Namespace)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		raw, sig []byte
		ca       ssh.PublicKey
	}{
		"tampered list":       {tampered, sig, ca.pub},
		"another CA's list":   {raw, otherSig, ca.pub},
		"checked against B":   {raw, sig, other.pub},
		"no expiry":           {noExpiry, sshsig.Armor(noExpirySig), ca.pub},
		"no signature":        {raw, nil, ca.pub},
		"garbage signature":   {raw, []byte("-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"), ca.pub},
		"no CA":               {raw, sig, nil},
		"signed, not a KRL":   {[]byte("not a krl"), mustSign(t, ca, []byte("not a krl")), ca.pub},
		"wrong namespace sig": {raw, mustSignNS(t, ca, raw, "file"), ca.pub},
	} {
		if _, err := VerifyKRL(c.raw, c.sig, c.ca); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// SignKRL refuses to sign what a verifier would refuse.
	if _, err := SignKRL(noExpiry, ca.signer); err == nil {
		t.Error("SignKRL signed a KRL with no expiry")
	}
	if _, err := SignKRL([]byte("x"), ca.signer); err == nil {
		t.Error("SignKRL signed something that is not a KRL")
	}
}

func mustSign(t *testing.T, ca sshCA, b []byte) []byte { return mustSignNS(t, ca, b, Namespace) }

func mustSignNS(t *testing.T, ca sshCA, b []byte, ns string) []byte {
	t.Helper()
	s, err := sshsig.Sign(bytes.NewReader(b), ca.signer, sshsig.HashSHA512, ns)
	if err != nil {
		t.Fatal(err)
	}
	return sshsig.Armor(s)
}

// A KRL carrying the old signature section: OpenSSH from 9.4 refuses to
// load it, so a distributor must not hand it to sshd, however well signed.
func TestVerifyKRLRefusesASignatureSection(t *testing.T) {
	ca := newSSHCA(t)
	now := time.Now()
	raw := krlOf(t, ca, 1, now, now.Add(time.Hour))
	// Section 4 (PROTOCOL.krl 6): the type, then two strings, the signing
	// key and the signature.
	raw = append(append(raw, 4), ssh.Marshal(struct{ K, S []byte }{ca.pub.Marshal(), []byte("sig")})...)
	if k, err := krl.Parse(raw); err != nil || !k.Signed {
		t.Fatalf("control: the crafted section is not read as one: %v", err)
	}
	if _, err := VerifyKRL(raw, mustSign(t, ca, raw), ca.pub); err == nil || !strings.Contains(err.Error(), "9.4") {
		t.Errorf("a KRL with a signature section: %v", err)
	}
	if _, err := SignKRL(raw, ca.signer); err == nil {
		t.Error("SignKRL signed a KRL with a signature section")
	}
}

// PROTOCOL.sshsig: an RSA signature "must be rsa-sha2-512 or rsa-sha2-256
// (i.e. not the legacy RSA-SHA1 ssh-rsa)". Measured: x/crypto's Verify and
// hiddeco/sshsig's Verify both accept one; hiddeco/sshsig's Unarmor refuses
// it when it reads the format. This holds that dependency to it. The control
// is the same key signing with rsa-sha2-512.
func TestVerifyKRLRefusesRSASHA1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := ssh.NewSignerFromKey(key)
	as := s.(ssh.AlgorithmSigner)
	ca := sshCA{signer: s, pub: s.PublicKey()}
	now := time.Now()
	raw := krlOf(t, ca, 1, now, now.Add(time.Hour))
	h := sha512.Sum512(raw)
	signed := append([]byte("SSHSIG"), ssh.Marshal(struct {
		NS, R, H, M string
	}{Namespace, "", "sha512", string(h[:])})...)
	for _, c := range []struct {
		algo string
		ok   bool
	}{{ssh.KeyAlgoRSASHA512, true}, {ssh.KeyAlgoRSA, false}} {
		sig, err := as.SignWithAlgorithm(rand.Reader, signed, c.algo)
		if err != nil {
			t.Fatal(err)
		}
		blob := &sshsig.Signature{Version: 1, PublicKey: ca.pub, Namespace: Namespace,
			HashAlgorithm: sshsig.HashSHA512, Signature: sig}
		_, err = VerifyKRL(raw, sshsig.Armor(blob), ca.pub)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want accepted = %v", c.algo, err, c.ok)
		}
	}
}

func TestVerifyCRL(t *testing.T) {
	ca, other := newX509CA(t, "ca"), newX509CA(t, "other")
	now := time.Now()
	good := ca.crl(t, 5, now.Add(-time.Minute), now.Add(time.Hour), nil, 42)
	l, err := VerifyCRL(good, ca.cert)
	if err != nil || l.Version.Int64() != 5 || len(l.CRL.RevokedCertificateEntries) != 1 {
		t.Fatalf("control: %v", err)
	}
	if _, err := VerifyCRL(pemOf("X509 CRL", good), ca.cert); err != nil {
		t.Errorf("PEM: %v", err)
	}
	// Same key, another name: the signature verifies, the issuer does not.
	twin := ca
	tpl := *ca.cert
	tpl.Subject = pkix.Name{CommonName: "twin"}
	tpl.RawSubject, tpl.RawIssuer = nil, nil
	tpl.SubjectKeyId = nil
	twinCert, err := x509CreateSelfSigned(&tpl, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	twin.cert = twinCert
	base, _ := asn1.Marshal(big.NewInt(1))
	for name, c := range map[string]struct {
		raw []byte
		ca  x509CA
	}{
		"another CA":            {other.crl(t, 5, now, now.Add(time.Hour), nil), ca},
		"same key, other name":  {good, twin},
		"delta":                 {ca.crl(t, 6, now, now.Add(time.Hour), []pkix.Extension{{Id: oidDeltaCRL, Critical: true, Value: base}}), ca},
		"unknown critical":      {ca.crl(t, 6, now, now.Add(time.Hour), []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Critical: true, Value: []byte{5, 0}}}), ca},
		"not a CRL":             {[]byte("x"), ca},
		"a certificate as PEM":  {pemOf("CERTIFICATE", ca.cert.Raw), ca},
		"larger than the limit": {make([]byte, maxCRL+1), ca},
	} {
		if _, err := VerifyCRL(c.raw, c.ca.cert); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := VerifyCRL(good, nil); err == nil {
		t.Error("no CA: accepted")
	}
	// An unknown extension that is not critical is fine.
	if _, err := VerifyCRL(ca.crl(t, 7, now, now.Add(time.Hour), []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2}, Value: []byte{5, 0}}}), ca.cert); err != nil {
		t.Errorf("a non-critical unknown extension: %v", err)
	}
}

func TestCurrent(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	l := &List{Issued: now.Add(-30 * time.Minute), Expires: now.Add(time.Hour)}
	for _, c := range []struct {
		at     time.Time
		maxAge time.Duration
		ok     bool
	}{
		{now, 0, true},
		{now, time.Hour, true},
		{now, 10 * time.Minute, false},         // older than the caller allows
		{now.Add(time.Hour), 0, false},         // at its expiry
		{now.Add(-40 * time.Minute), 0, false}, // issued 10 min in the future
		{now.Add(-34 * time.Minute), 0, true},  // 4 min: within the skew
		{now.Add(59 * time.Minute), 0, true},   // a second before... a minute
		{now.Add(2 * time.Hour), time.Hour, false},
	} {
		err := l.Current(c.at, c.maxAge)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrExpired)) {
			t.Errorf("at %v, max age %v: %v, want current = %v", c.at.Sub(now), c.maxAge, err, c.ok)
		}
	}
}

func TestFollows(t *testing.T) {
	t0 := time.Unix(1_790_000_000, 0)
	l := func(v int64, at time.Duration) *List {
		return &List{Kind: KRL, Version: big.NewInt(v), Issued: t0.Add(at)}
	}
	for _, c := range []struct {
		next, held *List
		ok         bool
	}{
		{l(5, 0), nil, true},
		{l(6, 0), l(5, time.Hour), true},  // higher version, whatever the date
		{l(5, time.Hour), l(5, 0), true},  // re-issued
		{l(5, 0), l(5, 0), true},          // the same
		{l(4, time.Hour), l(5, 0), false}, // rollback
		{l(5, 0), l(5, time.Hour), false}, // an older issue replayed
		{&List{Kind: CRL, Version: big.NewInt(9)}, l(5, 0), false},
	} {
		err := c.next.Follows(c.held)
		if (err == nil) != c.ok {
			t.Errorf("%+v after %+v: %v, want ok = %v", c.next, c.held, err, c.ok)
		}
	}
	if !errors.Is(l(4, 0).Follows(l(5, 0)), ErrRollback) {
		t.Error("a rollback is not ErrRollback")
	}
}

func TestKindString(t *testing.T) {
	if KRL.String() != "krl" || CRL.String() != "crl" || Kind(9).String() != "Kind(9)" {
		t.Error(KRL, CRL, Kind(9))
	}
}

// What a distributor writes for sshd when it has no current list: judged by
// ssh-keygen -Q, every certificate of that CA is revoked, and nothing else.
func TestFailClosedKRLJudgedBySshKeygen(t *testing.T) {
	bin := sshKeygen(t)
	dir := t.TempDir()
	ca, other := newSSHCA(t), newSSHCA(t)
	raw, err := FailClosedKRL(ca.pub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	write(t, dir, "fc.krl", raw)
	files := []string{
		write(t, dir, "a-cert.pub", ssh.MarshalAuthorizedKey(certOf(t, ca, 1))),
		write(t, dir, "b-cert.pub", ssh.MarshalAuthorizedKey(certOf(t, ca, 999))),
		write(t, dir, "c-cert.pub", ssh.MarshalAuthorizedKey(certOf(t, other, 1))),
	}
	out, _ := run(t, dir, bin, append([]string{"-Q", "-f", "fc.krl"}, files...)...)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	want := []string{"REVOKED", "REVOKED", "ok"}
	if len(lines) != 3 {
		t.Fatalf("ssh-keygen -Q: %q", out)
	}
	for i, l := range lines {
		if !strings.HasSuffix(l, ": "+want[i]) {
			t.Errorf("%s: %q, want %s", files[i], l, want[i])
		}
	}
}
