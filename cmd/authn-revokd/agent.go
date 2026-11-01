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

// fetchTimeout bounds one source's fetch (up to four requests), and
// onChangeTimeout one run of an output's on_change command.
var (
	fetchTimeout    = 2 * time.Minute
	onChangeTimeout = time.Minute
)

// maxParallelFetches bounds the sources fetched at once.
const maxParallelFetches = 16

// newMirror is the HTTP server of the mirror. ⛔ It had a header timeout and
// an idle timeout only: a client that opened a connection, asked for a 32 MiB
// list and never read it held the connection (and its goroutine) forever.
func newMirror(h http.Handler) *http.Server {
	return &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 2 * time.Minute, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10}
}

// agent fetches every source, keeps the verified copies in the state
// directory, and writes the outputs from them.
type agent struct {
	cfg *config
	log io.Writer
	now func() time.Time
	// exec runs an output's on_change command; replaced in tests.
	exec func(ctx context.Context, argv []string) error
	// wake, when it delivers, syncs now instead of at the next refresh:
	// SIGHUP (notifyHUP). nil never delivers.
	wake <-chan os.Signal

	fetchers []*revocation.Fetcher

	mu   sync.RWMutex
	errs []error // the last fetch of each source
	// due is the outputs whose on_change has not succeeded since they
	// were written: a reload that failed is tried again at the next sync.
	due map[string]bool
	// outErrs is each output's last failure, for /healthz.
	outErrs map[string]error
	// dropNoted is, per source, the issue already said to reach past its
	// CA.
	dropNoted map[string]*revocation.List
	// trials is, per output and source, the list last tried alone and
	// whether it could be merged: a list that cannot fails closed for its
	// own CA, not for the whole output.
	trials map[string]trial

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
		errs: make([]error, len(cfg.Sources)), due: map[string]bool{}, outErrs: map[string]error{}, dropNoted: map[string]*revocation.List{},
		trials: map[string]trial{}, tags: map[*revocation.List]string{}}
	// ⛔ A write killed between creating its temporary file and renaming it
	// left the file there for good, one more at each kill.
	for _, o := range cfg.Outputs {
		sweepTemps(filepath.Dir(o.Path), filepath.Base(o.Path))
	}
	for i := range cfg.Sources {
		s := &cfg.Sources[i]
		sweepTemps(cfg.StateDir, s.Name+".state")
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
	// ⛔ The sources are fetched together, each within fetchTimeout. One after
	// the other, one upstream that does not answer (a request waits a minute)
	// held every other source's refresh -- and the output's failing closed --
	// behind it.
	type fetched struct {
		l       *revocation.List
		changed bool
		err     error
	}
	results := make([]fetched, len(a.cfg.Sources))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxParallelFetches)
	for i := range a.cfg.Sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fctx, cancel := context.WithTimeout(ctx, fetchTimeout)
			defer cancel()
			l, changed, err := a.fetchers[i].Fetch(fctx)
			results[i] = fetched{l, changed, err}
		}()
	}
	wg.Wait()
	for i := range a.cfg.Sources {
		s := &a.cfg.Sources[i]
		l, changed, err := results[i].l, results[i].changed, results[i].err
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
		if err := a.writeOutput(ctx, o); err != nil {
			fmt.Fprintf(a.log, "output %s: %v\n", o.Name, err)
			failed = append(failed, "output "+o.Name)
		}
	}
	// Two different things go wrong here, and they used to be said with one
	// word. A source whose fetch failed while the list it holds is still
	// current is NOT "not current": the outputs carry that list, and sshd is
	// fine until it expires. It is still a failure -- the timer exists to say
	// so before the list lapses -- but it is said as what it is.
	var stale []string
	a.mu.RLock()
	for i, err := range a.errs {
		if err == nil {
			continue
		}
		if l := a.current(i); l != nil {
			stale = append(stale, fmt.Sprintf("%s (the list held is current until %s)",
				a.cfg.Sources[i].Name, l.Expires.UTC().Format(time.RFC3339)))
			continue
		}
		failed = append(failed, a.cfg.Sources[i].Name)
	}
	a.mu.RUnlock()
	var parts []string
	if len(failed) > 0 {
		parts = append(parts, "not current: "+strings.Join(failed, ", "))
	}
	if len(stale) > 0 {
		parts = append(parts, "not fetched: "+strings.Join(stale, ", "))
	}
	if len(parts) > 0 {
		return errors.New(strings.Join(parts, "; "))
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
	// current and can be merged, and its CA revoked whole while not.
	//
	// The CA keys of this output's sources: what one source's list may not
	// revoke. Its serials, key IDs and its own key keep their effect
	// (krl v0.4.0; v0.3.0's MergeCA dropped its key revocations -- a
	// fail-open found by a security audit). A user's public key it
	// revokes is kept only when it is the output's one source, or a
	// source trusted with every CA's users (revoke_keys): sshd checks a
	// certificate's own key against the file, whoever signed it, so a key
	// one CA names locks that user out under every CA of the output (found
	// by a security audit).
	var others []ssh.PublicKey
	for _, n := range o.Sources {
		others = append(others, a.cfg.Sources[a.cfg.byName[n]].sshCA)
	}
	opts := func(src *sourceBlock) krl.MergeOptions {
		return krl.MergeOptions{Others: others, DropKeys: len(o.Sources) > 1 && !src.RevokeKeys}
	}
	var current []*revocation.List
	var closed []string
	var unmerged []error
	for _, n := range o.Sources {
		src := &a.cfg.Sources[a.cfg.byName[n]]
		l := a.current(a.cfg.byName[n])
		if l != nil {
			// ⛔ Each list tried alone first: one CA's list that cannot be
			// merged (too many serial ranges) failed the whole output, and
			// the fail-closed list then refused every CA's users (found by
			// a security audit). It now fails closed for its own CA.
			if err := a.try(o.Name, n, l, src.sshCA, opts(src)); err != nil {
				unmerged = append(unmerged, fmt.Errorf("source %s: its list cannot be merged, every certificate of its CA is refused: %w", n, err))
				l = nil
			}
		}
		current = append(current, l)
		if l == nil {
			closed = append(closed, n)
		}
	}
	comment := cmdName + " " + o.Name
	if len(closed) > 0 {
		// What a person reading `ssh-keygen -Q -l` of the file must see.
		comment += ": FAIL CLOSED, every certificate refused from " + strings.Join(closed, ", ")
	}
	b := krl.NewBuilder(0, comment)
	var issued time.Time
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
		if dropped := b.MergeCAWith(l.KRL, src.sshCA, opts(src)); dropped > 0 && a.noteDropped(n, l) {
			fmt.Fprintf(a.log, "%s: %d revocation(s) in its list reach past its CA -- another CA's section or key, "+
				"or a user's public key, which only a source with revoke_keys may revoke in a shared output -- and are left out\n", n, dropped)
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
	// ssh_krl_file) sees authn-revokd stop, as it would see the issuer stop.
	if issued.IsZero() {
		issued = time.Unix(0, 0)
	}
	if !expires.IsZero() && expires.After(issued.Truncate(time.Second)) {
		b.SetExpires(expires)
	}
	data, err := b.Marshal(issued.Truncate(time.Second))
	if err != nil {
		return nil, err
	}
	// Written, and failing: /healthz names the source.
	return data, errors.Join(unmerged...)
}

// trial is a list tried alone for an output, and what came of it.
type trial struct {
	l   *revocation.List
	err error
}

// try merges l alone, as render would, and says whether it can be: once per
// issue of the list, since the list is as long as its CA made it.
func (a *agent) try(output, source string, l *revocation.List, ca ssh.PublicKey, opt krl.MergeOptions) error {
	key := output + "\x00" + source
	if t, ok := a.trials[key]; ok && t.l == l {
		return t.err
	}
	b := krl.NewBuilder(0, "")
	b.MergeCAWith(l.KRL, ca, opt)
	_, err := b.Marshal(l.Issued)
	a.trials[key] = trial{l, err}
	return err
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
func (a *agent) writeOutput(ctx context.Context, o outputBlock) (err error) {
	defer func() {
		a.mu.Lock()
		a.outErrs[o.Name] = err
		a.mu.Unlock()
	}()
	data, rerr := a.render(o)
	if rerr != nil && data != nil {
		// Some sources failed closed, each for its own CA; the others
		// keep their lists.
		if werr := a.store(ctx, o, data); werr != nil {
			return errors.Join(rerr, werr)
		}
		return rerr
	}
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
		if werr := a.store(ctx, o, data); werr != nil {
			return werr
		}
		return fmt.Errorf("%w: every certificate of its CAs is refused until it renders again", rerr)
	}
	if data == nil {
		return nil
	}
	return a.store(ctx, o, data)
}

// failClosed is an sshd output that refuses every certificate of every CA
// it serves.
func (a *agent) failClosed(o outputBlock) ([]byte, error) {
	b := krl.NewBuilder(0, cmdName+" "+o.Name+": FAIL CLOSED, the output could not be rendered")
	for _, n := range o.Sources {
		b.RevokeKey(a.cfg.Sources[a.cfg.byName[n]].sshCA)
	}
	return b.Marshal(time.Unix(0, 0))
}

// store writes an output's content when it changed, and runs its on_change
// command then -- and again at every sync until it succeeds.
//
// ⛔ The file is compared with what is on disk at every sync, not with what
// was last written: a file deleted, truncated or replaced behind the agent's
// back stayed so until the list changed (days), and sshd refuses every login
// when its RevokedKeys is unreadable. And a.mu is not held while the file is
// written or the command runs: a reload that hung held /healthz with it.
func (a *agent) store(ctx context.Context, o outputBlock, data []byte) error {
	if old, err := os.ReadFile(o.Path); err != nil || !bytes.Equal(old, data) {
		if err := writeAtomic(o.Path, data, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(a.log, "output %s: wrote %s\n", o.Name, o.Path)
		a.mu.Lock()
		a.due[o.Name] = len(o.OnChange) > 0
		a.mu.Unlock()
	}
	a.mu.RLock()
	due := a.due[o.Name]
	a.mu.RUnlock()
	if due {
		cctx, cancel := context.WithTimeout(ctx, onChangeTimeout)
		err := a.exec(cctx, o.OnChange)
		cancel()
		if err != nil {
			return fmt.Errorf("on_change %q: %w", o.OnChange, err)
		}
		a.mu.Lock()
		a.due[o.Name] = false
		a.mu.Unlock()
	}
	return nil
}

// untilLapse is how long until the first list that is current now stops being
// (its expiry, or its issue plus max_age), and false when none is current. The
// instant itself is not current (List.Current), so the sync is made a moment
// later; never sooner than a second from now, so that a list lapsing as it is
// fetched cannot spin the loop.
func (a *agent) untilLapse() (time.Duration, bool) {
	now := a.now()
	var first time.Time
	for i := range a.cfg.Sources {
		l := a.current(i)
		if l == nil {
			continue
		}
		end := l.Expires
		if m := a.cfg.Sources[i].maxAge; m > 0 && l.Issued.Add(m).Before(end) {
			end = l.Issued.Add(m)
		}
		if first.IsZero() || end.Before(first) {
			first = end
		}
	}
	if first.IsZero() {
		return 0, false
	}
	return max(first.Sub(now)+100*time.Millisecond, time.Second), true
}

// run syncs until ctx ends, every refresh give or take a tenth: a fleet of
// agents started together does not stay in step against the issuer.
func (a *agent) run(ctx context.Context) {
	for {
		a.syncOnce(ctx)
		jitter := time.Duration(rand.Int64N(int64(a.cfg.refresh)/5+1)) - a.cfg.refresh/10
		wait := a.cfg.refresh + jitter
		// ⛔ Not later than the first list to lapse: with refresh = 1h, a list
		// that lapsed was still on disk, current as far as sshd could tell,
		// until the next sync.
		if d, ok := a.untilLapse(); ok && d < wait {
			wait = d
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		case s := <-a.wake:
			timer.Stop()
			fmt.Fprintf(a.log, "%v: syncing now\n", s)
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

func runCommand(ctx context.Context, argv []string) error {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// ⛔ Without WaitDelay, killing the command at its deadline is not enough:
	// a child it started holds the output pipe, and Wait waits for that.
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}
