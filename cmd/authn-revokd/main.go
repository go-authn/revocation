// SPDX-License-Identifier: BSD-3-Clause

// Command authn-revokd distributes revocation lists: it fetches SSH KRLs and
// X.509 CRLs, keeps only those that verify (signed by the CA configured for
// them, current, never older than the copy held), writes them where sshd and
// TLS servers read them -- failing closed for sshd when a list lapses -- and,
// with listen, serves the verified copies to other agents as a mirror.
//
//	authn-revokd                                              # run: sync every refresh
//	authn-revokd -config /etc/authn-revokd/revokd.hcl -once   # one sync, for a timer; exit 1 when a list is not current
//
// It was called revokd until v0.6.0, and read /etc/revokd.hcl by default.
// docs/install.md says how to run it as a service; PROTOCOL.md says what is
// verified and why.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"
)

// cmdName is the command's name, in its messages, its -version and the
// comment of the KRL it writes. It was revokd until v0.6.0: a generic name
// that a host may already give to something else.
const cmdName = "authn-revokd"

// defaultConfig is read when -config is not given. Until v0.6.0 it was
// oldDefaultConfig: a configuration left there is not read, and saying so
// is the difference between a migration and a mystery.
const (
	defaultConfig    = "/etc/authn-revokd/revokd.hcl"
	oldDefaultConfig = "/etc/revokd.hcl"
)

// migrationHint is what to add to the error of a configuration that could
// not be read, when it is the default and the pre-v0.6.0 default is there
// instead: "" otherwise.
func migrationHint(explicit bool, path, old string) string {
	if explicit {
		return ""
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if _, err := os.Stat(old); err != nil {
		return ""
	}
	return fmt.Sprintf(" (%s exists: the default before v0.6.0. Move it to %s, or pass -config %s)", old, path, old)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, log io.Writer) int {
	fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
	fs.SetOutput(log)
	path := fs.String("config", defaultConfig, "the configuration file")
	once := fs.Bool("once", false, "sync once and exit: 1 when a list is not current")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(log, "%s %s\n", cmdName, version())
		return 0
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		explicit := false
		fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "config" })
		fmt.Fprintf(log, "%s: %s: %v%s\n", cmdName, *path, err, migrationHint(explicit, *path, oldDefaultConfig))
		return 2
	}
	a, err := newAgent(cfg, log, nil)
	if err != nil {
		fmt.Fprintf(log, "%s: %v\n", cmdName, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *once {
		if err := a.syncOnce(ctx); err != nil {
			fmt.Fprintf(log, "%s: %v\n", cmdName, err)
			return 1
		}
		return 0
	}
	if err := serve(ctx, a, cfg.Listen, log); err != nil {
		fmt.Fprintf(log, "%s: %v\n", cmdName, err)
		return 1
	}
	return 0
}

// serve runs the agent, and the mirror when listen is set, until ctx ends.
func serve(ctx context.Context, a *agent, listen string, log io.Writer) error {
	if listen == "" {
		a.run(ctx)
		return nil
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	fmt.Fprintf(log, "%s: serving the verified lists on %s\n", cmdName, ln.Addr())
	srv := &http.Server{Handler: a.handler(), ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	go a.run(ctx)
	select {
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shut)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// version is the module version Go stamped into the binary from the tag it
// was built at (debug.ReadBuildInfo), so that an authn-revokd found on a server can
// be matched to its release and to any advisory against it.
func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "(devel)"
}
