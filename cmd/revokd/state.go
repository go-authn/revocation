// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/go-authn/revocation"
)

// The state directory keeps, per source, the last list that verified: what
// orders the next one after a restart (PROTOCOL.md rule 2).
//
// ⛔ ONE file per source, the list and its signature together, written by
// one rename. v0.1 wrote them as two files, two renames: a crash between
// them left a pair that did not verify, which was then not trusted -- and
// the rollback guard went with it, so a replayed older list, still signed
// and unexpired, un-revoked what the newer one revoked (found by the
// adversarial review). The two-file layout is still read, once, to carry
// a v0.1 state over.

// stateMagic heads a state file; the version is in it.
const stateMagic = "revokd-state 1\n"

func (a *agent) stateFile(s *sourceBlock) string {
	return filepath.Join(a.cfg.StateDir, s.Name+".state")
}

// encodeState is a list and its signature (nil for a CRL) in one file.
func encodeState(l *revocation.List) []byte {
	b := make([]byte, 0, len(stateMagic)+8+len(l.Raw)+len(l.Sig))
	b = append(b, stateMagic...)
	b = binary.BigEndian.AppendUint64(b, uint64(len(l.Raw)))
	b = append(b, l.Raw...)
	return append(b, l.Sig...)
}

func decodeState(b []byte) (raw, sig []byte, err error) {
	rest, ok := bytes.CutPrefix(b, []byte(stateMagic))
	if !ok || len(rest) < 8 {
		return nil, nil, errors.New("not a revokd state file")
	}
	n := binary.BigEndian.Uint64(rest)
	rest = rest[8:]
	if n > uint64(len(rest)) {
		return nil, nil, errors.New("a truncated revokd state file")
	}
	return rest[:n], rest[n:], nil
}

// loadHeld reads back the copy kept from before. Expired or not, it orders
// what comes next: a restart must not let an older list in.
func (a *agent) loadHeld(s *sourceBlock) (*revocation.List, error) {
	data, err := os.ReadFile(a.stateFile(s))
	var raw, sig []byte
	switch {
	case err == nil:
		if raw, sig, err = decodeState(data); err != nil {
			return nil, err
		}
	case errors.Is(err, os.ErrNotExist):
		// A v0.1 state: the list, and a KRL's signature beside it.
		old := filepath.Join(a.cfg.StateDir, s.Name)
		if raw, err = os.ReadFile(old); errors.Is(err, os.ErrNotExist) {
			return nil, nil
		} else if err != nil {
			return nil, err
		}
		if s.kind == revocation.KRL {
			if sig, err = os.ReadFile(old + ".sig"); err != nil {
				return nil, err
			}
		}
	default:
		return nil, err
	}
	if s.kind == revocation.CRL {
		return revocation.VerifyCRL(raw, s.x509CA)
	}
	return revocation.VerifyKRL(raw, sig, s.sshCA)
}

// keep writes a verified list to the state directory, in one rename, and
// then removes a v0.1 state the new file supersedes.
func (a *agent) keep(s *sourceBlock, l *revocation.List) error {
	if err := writeAtomic(a.stateFile(s), encodeState(l), 0o600); err != nil {
		return err
	}
	old := filepath.Join(a.cfg.StateDir, s.Name)
	os.Remove(old)
	os.Remove(old + ".sig")
	return nil
}

// checkStateDir refuses a state directory others can write to: whoever can
// replace or remove its files decides what the next list must follow -- an
// emptied state lets a replayed older list in. As sshd's StrictModes does
// for authorized_keys: not a symbolic link (whoever owns the link re-points
// it), owned by revokd's user or by root, and, on systems where the mode
// bits mean that, writable by neither its group nor others.
//
// ⛔ It used os.Stat and checked the mode alone: a symbolic link, and a
// directory another user owns, passed (found by a security audit).
func checkStateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		// MkdirAll succeeded: what is there leads to a directory.
		return fmt.Errorf("state_dir %s is a symbolic link (%v): whoever owns it decides where the state is; name the directory itself", dir, fi.Mode().Type())
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("state_dir %s is writable by its group or by others (mode %v): "+
			"whoever can write there decides which list comes next", dir, fi.Mode().Perm())
	}
	return checkOwner(dir, fi, geteuid())
}

// geteuid is os.Geteuid; replaced in tests.
var geteuid = os.Geteuid
