// SPDX-License-Identifier: BSD-3-Clause

package revocation

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/go-authn/krl"
	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/ssh"
)

// Namespace is the SSHSIG namespace a KRL's signature is made in
// (PROTOCOL.sshsig: it keeps a signature from being taken for another
// purpose). ssh-keygen -Y verify -n krl@go-authn.github.io checks it.
const Namespace = "krl@go-authn.github.io"

// Kind is what a list is.
type Kind int

const (
	// KRL is an OpenSSH key revocation list with its detached SSHSIG
	// signature.
	KRL Kind = iota + 1
	// CRL is an X.509 certificate revocation list, DER-encoded.
	CRL
)

func (k Kind) String() string {
	switch k {
	case KRL:
		return "krl"
	case CRL:
		return "crl"
	}
	return fmt.Sprintf("Kind(%d)", int(k))
}

// List is a revocation list that verified: its signature by the CA it was
// checked against, and its form. Whether it is still current is Current's
// question; whether it may replace another is Follows'.
type List struct {
	Kind Kind
	// Raw is the list as it was signed: what sshd, OpenSSL and every other
	// reader take.
	Raw []byte
	// Sig is a KRL's armored SSHSIG signature; nil for a CRL, which is
	// signed inside.
	Sig []byte
	// Version is the KRL's krl_version or the CRL Number: the order lists
	// of one issuer come in.
	Version *big.Int
	// Issued is the KRL's generation date or the CRL's thisUpdate.
	Issued time.Time
	// Expires is the KRL's expires@go-authn.github.io extension or the
	// CRL's nextUpdate: when the list stops being current.
	Expires time.Time

	// KRL is the parsed KRL, for a KRL.
	KRL *krl.KRL
	// CRL is the parsed CRL, for a CRL.
	CRL *x509.RevocationList
}

// Errors a caller tells apart.
var (
	// ErrExpired is a list past its expiry, or older than the caller's
	// max_age: not current.
	ErrExpired = errors.New("revocation: the list is no longer current")
	// ErrRollback is a list older than the one held.
	ErrRollback = errors.New("revocation: the list is older than the one held")
)

// maxCRL bounds a CRL: Let's Encrypt shards its CRLs to stay far below it,
// and a body past it is somebody filling the reader's memory.
const maxCRL = 64 << 20

// VerifyKRL checks a KRL and its armored SSHSIG signature against the SSH CA
// key ca. It refuses: a signature by any other key, in another namespace, or
// in the RSA SHA-1 form PROTOCOL.sshsig forbids (hiddeco/sshsig refuses it
// when it reads the signature; x/crypto alone would verify it); a KRL sshd would not load
// (go-authn/krl refuses what OpenSSH refuses), or one with the old
// signature section, which OpenSSH never verifies and which PROTOCOL.krl
// says 9.4 and later refuse -- measured, 9.6p1 and 10.3p1 load it, so
// whether a given sshd does is not something to rely on; and a KRL that does not say when it
// expires, which a reader could never tell from a stale one.
func VerifyKRL(raw, sig []byte, ca ssh.PublicKey) (*List, error) {
	if ca == nil {
		return nil, errors.New("revocation: no CA key to verify the KRL against")
	}
	s, err := sshsig.Unarmor(sig)
	if err != nil {
		return nil, fmt.Errorf("revocation: the KRL's signature: %w", err)
	}
	if err := sshsig.Verify(bytes.NewReader(raw), s, ca, s.HashAlgorithm, Namespace); err != nil {
		return nil, fmt.Errorf("revocation: the KRL's signature does not verify by %s: %w", ssh.FingerprintSHA256(ca), err)
	}
	k, err := krl.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("revocation: %w", err)
	}
	if k.Signed {
		return nil, errors.New("revocation: the KRL has a signature section, which OpenSSH never verifies and PROTOCOL.krl says it refuses from 9.4: an SSHSIG signature is the one to give")
	}
	if k.Expires.IsZero() {
		return nil, fmt.Errorf("revocation: the KRL does not say when it expires (no %s extension)", krl.ExtensionExpires)
	}
	return &List{Kind: KRL, Raw: raw, Sig: sig, Version: new(big.Int).SetUint64(k.Version),
		Issued: k.GeneratedDate, Expires: k.Expires, KRL: k}, nil
}

// Object identifiers of the CRL extensions a reader of complete lists
// understands (RFC 5280 5.2).
var (
	oidCRLNumber      = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidAuthorityKeyID = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidDeltaCRL       = asn1.ObjectIdentifier{2, 5, 29, 27}
)

// VerifyCRL checks a CRL, DER or PEM, against the CA certificate ca. It
// refuses: a signature by anything else, or an issuer that is not ca's
// subject; a CRL with no number or no nextUpdate, which could be neither
// ordered nor aged; a delta CRL, which only means something with its base
// (RFC 5280 5.2.4); and a critical extension it does not understand, nor any
// critical entry extension.
func VerifyCRL(raw []byte, ca *x509.Certificate) (*List, error) {
	if ca == nil {
		return nil, errors.New("revocation: no CA certificate to verify the CRL against")
	}
	if len(raw) > maxCRL {
		return nil, fmt.Errorf("revocation: a CRL of %d bytes, past %d", len(raw), maxCRL)
	}
	der := raw
	if b, _ := pem.Decode(raw); b != nil {
		if b.Type != "X509 CRL" {
			return nil, fmt.Errorf("revocation: a PEM %q block, not an X509 CRL", b.Type)
		}
		der = b.Bytes
	}
	// ⛔ The signature first, on the raw bytes, then the parse: parsed
	// first, a 63 MB CRL signed by anybody cost 3 GB allocated and 1.4 GB
	// live before being refused (found by a security audit).
	if err := checkCRLSignature(der, ca); err != nil {
		return nil, fmt.Errorf("revocation: the CRL is not signed by %s: %w", ca.Subject, err)
	}
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("revocation: %w", err)
	}
	if err := rl.CheckSignatureFrom(ca); err != nil {
		return nil, fmt.Errorf("revocation: the CRL is not signed by %s: %w", ca.Subject, err)
	}
	if !bytes.Equal(rl.RawIssuer, ca.RawSubject) {
		return nil, fmt.Errorf("revocation: the CRL is issued by %s, not %s", rl.Issuer, ca.Subject)
	}
	switch {
	case rl.Number == nil:
		return nil, errors.New("revocation: the CRL has no CRL number, so it cannot be ordered")
	case rl.NextUpdate.IsZero():
		return nil, errors.New("revocation: the CRL has no nextUpdate, so it never stops being current")
	case !rl.NextUpdate.After(rl.ThisUpdate):
		return nil, errors.New("revocation: the CRL's nextUpdate is not after its thisUpdate")
	}
	for _, e := range rl.Extensions {
		switch {
		case e.Id.Equal(oidDeltaCRL):
			return nil, errors.New("revocation: a delta CRL, which means nothing without its base")
		case e.Critical && !e.Id.Equal(oidCRLNumber) && !e.Id.Equal(oidAuthorityKeyID):
			return nil, fmt.Errorf("revocation: the CRL has a critical extension %v this reader does not understand", e.Id)
		}
	}
	for _, r := range rl.RevokedCertificateEntries {
		for _, e := range r.Extensions {
			if e.Critical {
				return nil, fmt.Errorf("revocation: the CRL entry for %v has a critical extension %v", r.SerialNumber, e.Id)
			}
		}
	}
	return &List{Kind: CRL, Raw: der, Version: rl.Number, Issued: rl.ThisUpdate, Expires: rl.NextUpdate, CRL: rl}, nil
}

// Current reports whether l may be used at now: not past its expiry, and,
// when maxAge is not zero, issued no more than maxAge before now. A list
// issued in the future -- an issuer's clock ahead by more than skew -- is not
// current either: its age cannot be known.
func (l *List) Current(now time.Time, maxAge time.Duration) error {
	const skew = 5 * time.Minute
	switch {
	case !now.Before(l.Expires):
		return fmt.Errorf("%w: it expired at %s", ErrExpired, l.Expires.UTC().Format(time.RFC3339))
	case l.Issued.After(now.Add(skew)):
		return fmt.Errorf("%w: it was issued at %s, in the future", ErrExpired, l.Issued.UTC().Format(time.RFC3339))
	case maxAge > 0 && now.Sub(l.Issued) > maxAge:
		return fmt.Errorf("%w: it was issued at %s, more than %s ago", ErrExpired, l.Issued.UTC().Format(time.RFC3339), maxAge)
	}
	return nil
}

// Follows reports whether l may replace held, a list of the same issuer: a
// higher version, or the same version issued later (the same revocations,
// re-issued with a new expiry). Anything else is a rollback -- a replayed or
// restored older list, which would un-revoke what the newer one revoked.
// A nil held is followed by anything.
func (l *List) Follows(held *List) error {
	if held == nil {
		return nil
	}
	if l.Kind != held.Kind {
		return fmt.Errorf("revocation: a %s cannot replace a %s", l.Kind, held.Kind)
	}
	switch c := l.Version.Cmp(held.Version); {
	case c > 0:
		return nil
	case c < 0:
		return fmt.Errorf("%w: version %v, %v held", ErrRollback, l.Version, held.Version)
	case l.Issued.Before(held.Issued):
		return fmt.Errorf("%w: version %v issued at %s, the copy held at %s", ErrRollback, l.Version,
			l.Issued.UTC().Format(time.RFC3339), held.Issued.UTC().Format(time.RFC3339))
	}
	return nil
}

// Same reports whether l and o are the same issue of a list.
func (l *List) Same(o *List) bool {
	return o != nil && l.Kind == o.Kind && bytes.Equal(l.Raw, o.Raw)
}

// Signature algorithms a CRL may be signed with, by OID (crypto/x509's own
// list; RSASSA-PSS names its hash in parameters, so its three forms are
// tried).
var crlSignatureAlgorithms = map[string][]x509.SignatureAlgorithm{
	"1.2.840.113549.1.1.11": {x509.SHA256WithRSA},
	"1.2.840.113549.1.1.12": {x509.SHA384WithRSA},
	"1.2.840.113549.1.1.13": {x509.SHA512WithRSA},
	"1.2.840.113549.1.1.10": {x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS},
	"1.2.840.10045.4.3.2":   {x509.ECDSAWithSHA256},
	"1.2.840.10045.4.3.3":   {x509.ECDSAWithSHA384},
	"1.2.840.10045.4.3.4":   {x509.ECDSAWithSHA512},
	"1.3.101.112":           {x509.PureEd25519},
}

// checkCRLSignature verifies a DER CRL's signature by ca before anything
// else of it is read: CertificateList ::= SEQUENCE { tbsCertList,
// signatureAlgorithm, signatureValue } (RFC 5280 5.1), the signature over
// the tbsCertList's DER as it stands.
func checkCRLSignature(der []byte, ca *x509.Certificate) error {
	in := cryptobyte.String(der)
	var list, tbs, algo cryptobyte.String
	var oid asn1.ObjectIdentifier
	var sig asn1.BitString
	if !in.ReadASN1(&list, cbasn1.SEQUENCE) || !in.Empty() ||
		!list.ReadASN1Element(&tbs, cbasn1.SEQUENCE) ||
		!list.ReadASN1(&algo, cbasn1.SEQUENCE) || !algo.ReadASN1ObjectIdentifier(&oid) ||
		!list.ReadASN1BitString(&sig) || !list.Empty() || sig.BitLength%8 != 0 {
		return errors.New("not a CRL")
	}
	algs, ok := crlSignatureAlgorithms[oid.String()]
	if !ok {
		return fmt.Errorf("signature algorithm %v is not one this reader verifies", oid)
	}
	var err error
	for _, a := range algs {
		if err = ca.CheckSignature(a, tbs, sig.Bytes); err == nil {
			return nil
		}
	}
	return err
}
