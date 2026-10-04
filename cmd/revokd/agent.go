// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-authn/krl"
	"github.com/go-authn/revocation"
	"golang.org/x/crypto/ssh"
)

// agent fetches every source, keeps the verified copies in the state
// directory, and writes the outputs from them.
type agent struct {
	cfg *config
	log io.Writer
	now func() time.Time
	// exec runs an output's on_change command; replaced in tests.
	exec func(argv []string) error

	fetchers []*revocation.Fetcher

	mu      sync.RWMutex
	errs    []error // the last fetch of each source
	written map[string][]byte
	// due is the outputs whose on_change has not succeeded since they
	// were written: a reload that failed is tried again at the next sync.
	due map[string]bool
	// outErrs is each output's last failure, for /healthz.
	outErrs map[string]error
	// dropNoted is, per source, the issue already said to reach past its
	// CA.
	dropNoted map[string]*revocation.List

	// tags is the ETag of the list each source holds, computed once per
	// list: hashing it per request made an unchanged poll cost as much as
	// the list is long (measured: 122 us for 100 000 revocations).
	tagMu sync.Mutex
	tags  map[*revocation.List]string
}

// newAgent makes the agent; client fetches http and https sources, nil for
// the default.
func newAgent(cfg *config, log io.Writer, client *http.Client) (*agent, error) {
	if err := checkStateDir(cfg.StateDir); err != nil {
		return nil, err
	}
	a := &agent{cfg: cfg, log: log, now: time.Now, exec: runCommand,
		errs: make([]error, len(cfg.Sources)), written: map[string][]byte{}, due: map[string]bool{}, outErrs: map[string]error{}, dropNoted: map[string]*revocation.List{},
		tags: map[*revocation.List]string{}}
	for i := range cfg.Sources {
		s := &cfg.Sources[i]
		held, err := a.loadHeld(s)
		if err != nil {
			// A copy that no longer verifies is not trusted -- not even to
			// order the next one -- and is said out loud.
			fmt.Fprintf(a.log, "%s: the copy in %s is not used: %v\n", s.Name, cfg.StateDir, err)
		}
		f, err := revocation.NewFetcher(revocation.Source{URL: s.URL, Kind: s.kind, SSHCA: s.sshCA,
			X509CA: s.x509CA, MaxAge: s.maxAge, Client: client, Clock: a.clock}, held)
		if err != nil {
			return nil, fmt.Errorf("source %q: %w", s.Name, err)
		}
		a.fetchers = append(a.fetchers, f)
		if held == nil {
			a.errs[i] = errors.New("nothing fetched yet")
		}
	}
	return a, nil
}

// clock is the agent's time, which its fetchers share: a.now is replaced
// in tests.
func (a *agent) clock() time.Time { return a.now() }

// syncOnce fetches every source once and rewrites the outputs that changed.
// It returns an error naming every source with no current list.
func (a *agent) syncOnce(ctx context.Context) error {
	for i := range a.cfg.Sources {
		s := &a.cfg.Sources[i]
		l, changed, err := a.fetchers[i].Fetch(ctx)
		if err == nil && changed {
			if werr := a.keep(s, l); werr != nil {
				err = fmt.Errorf("keeping it: %w", werr)
			} else {
				fmt.Fprintf(a.log, "%s: version %v, issued %s, expires %s\n", s.Name, l.Version,
					l.Issued.UTC().Format(time.RFC3339), l.Expires.UTC().Format(time.RFC3339))
			}
		}
		if err == nil && l != nil {
			err = l.Current(a.now(), s.maxAge)
		}
		if err != nil {
			fmt.Fprintf(a.log, "%s: %v\n", s.Name, err)
		}
		a.mu.Lock()
		a.errs[i] = err
		a.mu.Unlock()
	}
	var failed []string
	for _, o := range a.cfg.Outputs {
		if err := a.writeOutput(o); err != nil {
			fmt.Fprintf(a.log, "output %s: %v\n", o.Name, err)
			failed = append(failed, "output "+o.Name)
		}
	}
	a.mu.RLock()
	for i, err := range a.errs {
		if err != nil {
			failed = append(failed, a.cfg.Sources[i].Name)
		}
	}
	a.mu.RUnlock()
	if len(failed) > 0 {
		return fmt.Errorf("not current: %s", strings.Join(failed, ", "))
	}
	return nil
}

// current is the source's list when it may be used now, or nil.
func (a *agent) current(i int) *revocation.List {
	l := a.fetchers[i].Held()
	if l == nil || l.Current(a.now(), a.cfg.Sources[i].maxAge) != nil {
		return nil
	}
	return l
}

// render is an output's content, or nil when there is nothing to write.
func (a *agent) render(o outputBlock) ([]byte, error) {
	first := &a.cfg.Sources[a.cfg.byName[o.Sources[0]]]
	if first.kind == revocation.CRL {
		// The list held, current or not: OpenSSL refuses an expired CRL by
		// itself ("CRL has expired"), which is the fail-closed behaviour.
		l := a.fetchers[a.cfg.byName[o.Sources[0]]].Held()
		switch {
		case l == nil:
			return nil, nil
		case o.Format == "pem":
			return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: l.Raw}), nil
		}
		return l.Raw, nil
	}
	// sshd: one KRL for every source, each source's own list while it is
	// current, and its CA revoked whole while it is not.
	var current []*revocation.List
	var lapsed []string
	for _, n := range o.Sources {
		l := a.current(a.cfg.byName[n])
		current = append(current, l)
		if l == nil {
			lapsed = append(lapsed, n)
		}
	}
	comment := "revokd " + o.Name
	if len(lapsed) > 0 {
		// What a person reading `ssh-keygen -Q -l` of the file must see.
		comment += ": FAIL CLOSED, every certificate refused from " + strings.Join(lapsed, ", ")
	}
	b := krl.NewBuilder(0, comment)
	var issued time.Time
	// The CA keys of this output's sources: what one source's list may not
	// revoke. Everything else it says keeps its effect, its own key and the
	// user keys it revokes included (krl v0.4.0; v0.3.0's MergeCA dropped
	// those -- a fail-open found by a security audit).
	var others []ssh.PublicKey
	for _, n := range o.Sources {
		others = append(others, a.cfg.Sources[a.cfg.byName[n]].sshCA)
	}
	var expires time.Time
	for j, n := range o.Sources {
		l, src := current[j], &a.cfg.Sources[a.cfg.byName[n]]
		if l == nil {
			b.RevokeKey(src.sshCA)
			continue
		}
		// ⛔ Each list for its own CA only: with Merge, one CA's signed
		// list could revoke another CA's key, or every serial of every
		// CA, and lock that CA's users out (found by the adversarial
		// review). What is left out is said, once per issue.
		if dropped := b.MergeCA(l.KRL, src.sshCA, others...); dropped > 0 && a.noteDropped(n, l) {
			fmt.Fprintf(a.log, "%s: %d revocation(s) in its list reach another CA of this output, and are left out\n", n, dropped)
		}
		if l.Issued.After(issued) {
			issued = l.Issued
		}
		if expires.IsZero() || l.Expires.Before(expires) {
			expires = l.Expires
		}
	}
	// The merged list's date is its newest input's, so that the same
	// inputs write the same bytes and nothing is rewritten for nothing;
	// 1970 when every source has lapsed. Its expiry is the first of its
	// inputs': a reader of this file that checks it (fileshare's
	// ssh_krl_file) sees revokd stop, as it would see the issuer stop.
	if issued.IsZero() {
		issued = time.Unix(0, 0)
	}
	if !expires.IsZero() && expires.After(issued.Truncate(time.Second)) {
		b.SetExpires(expires)
	}
	return b.Marshal(issued.Truncate(time.Second))
}

// noteDropped reports whether this issue of a source's list has not been
// said yet to hold revocations outside its CA.
func (a *agent) noteDropped(source string, l *revocation.List) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dropNoted[source] == l {
		return false
	}
	a.dropNoted[source] = l
	return true
}

// writeOutput writes an output when its content changed, and runs its
// on_change command then -- and again at every sync until it succeeds.
func (a *agent) writeOutput(o outputBlock) (err error) {
	defer func() {
		a.mu.Lock()
		a.outErrs[o.Name] = err
		a.mu.Unlock()
	}()
	data, rerr := a.render(o)
	if rerr != nil {
		// ⛔ Not "leave the file as it was": a list that cannot be
		// rendered would then freeze it, and a source lapsing after that
		// would never be refused (found by the adversarial review: one
		// CA's oversized list kept another CA's lapse from reaching sshd).
		// For sshd, every CA of the output is refused until the output
		// renders again; a CRL is never rendered, only copied.
		if data, err = a.failClosed(o); err != nil {
			return fmt.Errorf("%w; and the fail-closed list: %w", rerr, err)
		}
		if werr := a.store(o, data); werr != nil {
			return werr
		}
		return fmt.Errorf("%w: every certificate of its CAs is refused until it renders again", rerr)
	}
	if data == nil {
		return nil
	}
	return a.store(o, data)
}

// failClosed is an sshd output that refuses every certificate of every CA
// it serves.
func (a *agent) failClosed(o outputBlock) ([]byte, error) {
	b := krl.NewBuilder(0, "revokd "+o.Name+": FAIL CLOSED, the output could not be rendered")
	for _, n := range o.Sources {
		b.RevokeKey(a.cfg.Sources[a.cfg.byName[n]].sshCA)
	}
	return b.Marshal(time.Unix(0, 0))
}

// store writes an output's content when it changed, and runs its on_change
// command then -- and again at every sync until it succeeds.
func (a *agent) store(o outputBlock, data []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !bytes.Equal(a.written[o.Name], data) {
		if old, err := os.ReadFile(o.Path); err != nil || !bytes.Equal(old, data) {
			if err := writeAtomic(o.Path, data, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(a.log, "output %s: wrote %s\n", o.Name, o.Path)
			a.due[o.Name] = len(o.OnChange) > 0
		}
		a.written[o.Name] = data
	}
	if a.due[o.Name] {
		if err := a.exec(o.OnChange); err != nil {
			return fmt.Errorf("on_change %q: %w", o.OnChange, err)
		}
		a.due[o.Name] = false
	}
	return nil
}

// run syncs until ctx ends, every refresh give or take a tenth: a fleet of
// agents started together does not stay in step against the issuer.
func (a *agent) run(ctx context.Context) {
	for {
		a.syncOnce(ctx)
		jitter := time.Duration(rand.Int64N(int64(a.cfg.refresh)/5+1)) - a.cfg.refresh/10
		select {
		case <-ctx.Done():
			return
		case <-time.After(a.cfg.refresh + jitter):
		}
	}
}

// writeAtomic writes data beside path and renames it over: a reader sees
// the old file or the new one, never a part. sshd reads RevokedKeys at each
// authentication, so the rename is all it needs.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// The rename itself, made durable: without it a power loss can bring
	// back the file the rename replaced.
	if d, err := os.Open(dir); err == nil {
		d.Sync() // not supported on every system (Windows): best effort
		d.Close()
	}
	return nil
}

func runCommand(argv []string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}
