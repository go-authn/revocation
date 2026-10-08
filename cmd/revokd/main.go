// SPDX-License-Identifier: BSD-3-Clause

// Command revokd distributes revocation lists: it fetches SSH KRLs and X.509
// CRLs, keeps only those that verify (signed by the CA configured for them,
// current, never older than the copy held), writes them where sshd and TLS
// servers read them -- failing closed for sshd when a list lapses -- and,
// with listen, serves the verified copies to other revokd as a mirror.
//
//	revokd -config /etc/revokd.hcl          # run: sync every refresh
//	revokd -config /etc/revokd.hcl -once    # one sync, for cron; exit 1 when a list is not current
//
// PROTOCOL.md says what is verified and why.
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

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, log io.Writer) int {
	fs := flag.NewFlagSet("revokd", flag.ContinueOnError)
	fs.SetOutput(log)
	path := fs.String("config", "/etc/revokd.hcl", "the configuration file")
	once := fs.Bool("once", false, "sync once and exit: 1 when a list is not current")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(log, "revokd %s\n", version())
		return 0
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		fmt.Fprintf(log, "revokd: %s: %v\n", *path, err)
		return 2
	}
	a, err := newAgent(cfg, log, nil)
	if err != nil {
		fmt.Fprintf(log, "revokd: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *once {
		if err := a.syncOnce(ctx); err != nil {
			fmt.Fprintf(log, "revokd: %v\n", err)
			return 1
		}
		return 0
	}
	if err := serve(ctx, a, cfg.Listen, log); err != nil {
		fmt.Fprintf(log, "revokd: %v\n", err)
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
	fmt.Fprintf(log, "revokd: serving the verified lists on %s\n", ln.Addr())
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
// was built at (debug.ReadBuildInfo), so that a revokd found on a server can
// be matched to its release and to any advisory against it.
func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "(devel)"
}
