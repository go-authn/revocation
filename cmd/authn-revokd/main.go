// SPDX-License-Identifier: BSD-3-Clause

// Command authn-revokd distributes revocation lists: it fetches SSH KRLs and
// X.509 CRLs, keeps only those that verify (signed by the CA configured for
// them, current, never older than the copy held), writes them where sshd and
// TLS servers read them -- failing closed for sshd when a list lapses -- and,
// with listen, serves the verified copies to other agents as a mirror.
//
//	authn-revokd                                              # run: sync every refresh
//	authn-revokd --config /etc/authn-revokd/revokd.hcl --once # one sync, for a timer; exit 1 when a list is not current or could not be fetched
//
// It was called revokd until v0.6.0, and read /etc/revokd.hcl by default.
// docs/install.md says how to run it as a service; PROTOCOL.md says what is
// verified and why.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
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

// osExit allows tests to override os.Exit.
var osExit = os.Exit

func main() {
	osExit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// exitError carries the exit status of a failed run: 1 for a runtime failure,
// 2 for a usage or configuration error. It has already been printed.
type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// run executes the command with args and returns its exit status: 0, 1 (a
// runtime failure, or a list not current under --once) or 2 (a usage error or
// a configuration that could not be read). The status is unchanged since the
// flag package: only the flag spelling moved.
func run(args []string, out, log io.Writer) int {
	cmd := RootCmd()
	cmd.SetOut(out)
	cmd.SetErr(log)
	cmd.SetArgs(normalizeArgs(args, log))
	err := cmd.Execute()
	if err == nil {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	fmt.Fprintf(log, "%s: %v\n", cmdName, err)
	return 2 // what cobra refuses is a usage error
}

// legacyFlags are the single-dash long spellings the flag package accepted,
// documented in the README, docs/install.md and the systemd units of every
// release before v0.7.0. Each maps to its POSIX spelling.
var legacyFlags = map[string]string{
	"-config":  "--config",
	"-once":    "--once",
	"-version": "--version",
	"-help":    "--help",
}

// normalizeArgs rewrites the legacy single-dash long flags (-once,
// -config=PATH, -config PATH ...) to the POSIX form, so a deployed unit keeps
// working, and says so once per flag on log. Nothing after "--" is touched, nor
// the value that follows --config / -config.
func normalizeArgs(args []string, log io.Writer) []string {
	res := make([]string, 0, len(args))
	warned := map[string]bool{}
	valueNext := false
	for i, a := range args {
		if valueNext {
			valueNext = false
			res = append(res, a)
			continue
		}
		if a == "--" {
			return append(res, args[i:]...)
		}
		name, rest := a, ""
		if j := strings.IndexByte(a, '='); j >= 0 {
			name, rest = a[:j], a[j:]
		}
		if posix, ok := legacyFlags[name]; ok {
			if !warned[name] {
				warned[name] = true
				fmt.Fprintf(log, "%s: warning: %s is deprecated, use %s (the single-dash spelling will be removed in a later release)\n", cmdName, name, posix)
			}
			a, name = posix+rest, posix
		}
		if name == "--config" && rest == "" {
			valueNext = true
		}
		res = append(res, a)
	}
	return res
}

// RootCmd returns the top-level cobra command. Exported so tests drive it
// through SetArgs, SetOut and SetErr without spawning a process.
func RootCmd() *cobra.Command {
	var (
		path string
		once bool
	)
	cmd := &cobra.Command{
		Use:   cmdName + " [flags]",
		Short: "Distribute SSH KRLs and X.509 CRLs",
		Long: `authn-revokd fetches revocation lists, keeps only those that verify, writes
them where sshd and TLS servers read them (failing closed for sshd when a list
lapses) and, with listen, serves the verified copies as a mirror. SIGHUP syncs now.

The single-dash spellings -config, -once, -version and -help of earlier
releases are still accepted, with a deprecation warning on stderr.`,
		Version:       version(),
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAgent(cmd, path, cmd.Flags().Changed("config"), once)
		},
	}
	cmd.SetVersionTemplate(cmdName + " {{.Version}}\n")
	cmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		fmt.Fprintf(c.ErrOrStderr(), "%s: %v\n", cmdName, err)
		return &exitError{2}
	})
	cmd.Flags().StringVarP(&path, "config", "c", defaultConfig, "the configuration file")
	cmd.Flags().BoolVarP(&once, "once", "o", false, "sync once and exit: 1 when a list is not current, or could not be fetched")
	return cmd
}

func runAgent(cmd *cobra.Command, path string, explicit, once bool) error {
	log := cmd.ErrOrStderr()
	cfg, err := loadConfig(path)
	if err != nil {
		fmt.Fprintf(log, "%s: %s: %v%s\n", cmdName, path, err, migrationHint(explicit, path, oldDefaultConfig))
		return &exitError{2}
	}
	a, err := newAgent(cfg, log, nil)
	if err != nil {
		fmt.Fprintf(log, "%s: %v\n", cmdName, err)
		return &exitError{1}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hup, stopHUP := notifyHUP()
	defer stopHUP()
	a.wake = hup
	if once {
		if err := a.syncOnce(ctx); err != nil {
			fmt.Fprintf(log, "%s: %v\n", cmdName, err)
			return &exitError{1}
		}
		return nil
	}
	if err := serve(ctx, a, cfg.Listen, log); err != nil {
		fmt.Fprintf(log, "%s: %v\n", cmdName, err)
		return &exitError{1}
	}
	return nil
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
	srv := newMirror(a.handler())
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

// notifyHUP catches SIGHUP, which then asks the running agent to sync now
// (systemctl reload). The configuration is not re-read: restart for that.
//
// ⛔ Uncaught, SIGHUP killed the process (Go's default), and systemd counts
// a death by SIGHUP as a clean exit: a Restart=on-failure unit stayed down,
// and sshd kept reading the last KRL written, which nothing would fail
// closed any more (found in go-authn/authnd, measured there in a VM). With
// -once it is caught too, and changes nothing.
func notifyHUP() (<-chan os.Signal, func()) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	return c, func() { signal.Stop(c) }
}
