// SPDX-License-Identifier: BSD-3-Clause

package revocation

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/go-authn/krl"
	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

// SignKRL signs a KRL for distribution: an armored SSHSIG signature by the
// CA key, in Namespace, hashed with SHA-512 (ssh-keygen -Y sign's default).
// The KRL must say when it expires (krl.Builder.SetExpires): a verifier
// refuses one that does not.
func SignKRL(raw []byte, ca ssh.Signer) ([]byte, error) {
	k, err := krl.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("revocation: %w", err)
	}
	if k.Expires.IsZero() {
		return nil, fmt.Errorf("revocation: the KRL does not say when it expires (no %s extension)", krl.ExtensionExpires)
	}
	if k.Signed {
		return nil, errors.New("revocation: the KRL has a signature section, which sshd refuses from OpenSSH 9.4")
	}
	s, err := sshsig.SignWithRand(bytes.NewReader(raw), rand.Reader, ca, sshsig.HashSHA512, Namespace)
	if err != nil {
		return nil, fmt.Errorf("revocation: signing the KRL: %w", err)
	}
	return sshsig.Armor(s), nil
}

// FailClosedKRL is the list a distributor writes for sshd when it has no
// current list from ca: ca's own key revoked, which sshd checks for every
// certificate ca signed (krl.c ssh_krl_check_key) -- so every one of them is
// refused, and nothing else. It is not signed: it is written locally, for
// the reader on this machine, never distributed.
func FailClosedKRL(ca ssh.PublicKey, now time.Time) ([]byte, error) {
	b := krl.NewBuilder(0, "fail closed: no current revocation list for "+ssh.FingerprintSHA256(ca))
	b.RevokeKey(ca)
	return b.Marshal(now)
}
