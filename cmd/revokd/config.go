// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/go-authn/revocation"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"golang.org/x/crypto/ssh"
)

// config is revokd's configuration:
//
//	state_dir = "/var/lib/revokd"     # the verified copies; what a mirror serves
//	refresh   = "1m"
//
//	source "univ-a-ssh" {
//	  url     = "https://idp.univ-a.fr/ssh/krl"
//	  ssh_ca  = "/etc/ssh/ca/univ-a.pub"
//	}
//	source "univ-a-x509" {
//	  url     = "https://idp.univ-a.fr/x509/crl"
//	  x509_ca = "/etc/ssl/univ-a-ca.pem"
//	  max_age = "2h"
//	}
//
//	output "sshd" {                   # RevokedKeys /etc/ssh/revoked.krl
//	  path    = "/etc/ssh/revoked.krl"
//	  sources = ["univ-a-ssh", "univ-b-ssh"]
//	}
//	output "nginx" {
//	  path      = "/etc/nginx/univ-a.crl"
//	  sources   = ["univ-a-x509"]
//	  format    = "pem"
//	  on_change = ["systemctl", "reload", "nginx"]
//	}
//
//	listen = ":8080"                  # serve the verified copies: a mirror
type config struct {
	StateDir string         `hcl:"state_dir"`
	Refresh  string         `hcl:"refresh,optional"`
	Listen   string         `hcl:"listen,optional"`
	Sources  []sourceBlock  `hcl:"source,block"`
	Outputs  []outputBlock  `hcl:"output,block"`
	refresh  time.Duration  // parsed
	byName   map[string]int // source name -> index
}

type sourceBlock struct {
	Name   string `hcl:"name,label"`
	URL    string `hcl:"url"`
	SSHCA  string `hcl:"ssh_ca,optional"`
	X509CA string `hcl:"x509_ca,optional"`
	MaxAge string `hcl:"max_age,optional"`

	kind   revocation.Kind
	sshCA  ssh.PublicKey
	x509CA *x509.Certificate
	maxAge time.Duration
}

type outputBlock struct {
	Name     string   `hcl:"name,label"`
	Path     string   `hcl:"path"`
	Sources  []string `hcl:"sources"`
	Format   string   `hcl:"format,optional"`
	OnChange []string `hcl:"on_change,optional"`
}

// names are file names in the state directory and paths of the mirror: no
// separator, no dot first, nothing a URL would have to escape.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func loadConfig(path string) (*config, error) {
	parser := hclparse.NewParser()
	f, diags := parser.ParseHCLFile(path)
	if diags.HasErrors() {
		return nil, errors.New(diags.Error())
	}
	var c config
	if diags := gohcl.DecodeBody(f.Body, nil, &c); diags.HasErrors() {
		return nil, errors.New(diags.Error())
	}
	return &c, c.check()
}

func (c *config) check() error {
	if !filepath.IsAbs(c.StateDir) {
		return fmt.Errorf("state_dir %q: an absolute path", c.StateDir)
	}
	c.refresh = time.Minute
	if c.Refresh != "" {
		d, err := time.ParseDuration(c.Refresh)
		if err != nil || d < time.Second {
			return fmt.Errorf("refresh %q: a duration of a second or more", c.Refresh)
		}
		c.refresh = d
	}
	if len(c.Sources) == 0 {
		return errors.New("no source: nothing to fetch")
	}
	c.byName = map[string]int{}
	for i := range c.Sources {
		s := &c.Sources[i]
		if !nameRE.MatchString(s.Name) {
			return fmt.Errorf("source %q: a name of letters, digits, '.', '_' and '-', not starting with a dot", s.Name)
		}
		if _, dup := c.byName[s.Name]; dup {
			return fmt.Errorf("source %q appears twice", s.Name)
		}
		c.byName[s.Name] = i
		if err := s.load(); err != nil {
			return fmt.Errorf("source %q: %w", s.Name, err)
		}
	}
	paths := map[string]string{}
	for i := range c.Outputs {
		o := &c.Outputs[i]
		if !filepath.IsAbs(o.Path) {
			return fmt.Errorf("output %q: path %q is not absolute", o.Name, o.Path)
		}
		if other, dup := paths[o.Path]; dup {
			return fmt.Errorf("outputs %q and %q write the same file", other, o.Name)
		}
		paths[o.Path] = o.Name
		if len(o.Sources) == 0 {
			return fmt.Errorf("output %q names no source", o.Name)
		}
		var kind revocation.Kind
		for _, n := range o.Sources {
			i, ok := c.byName[n]
			if !ok {
				return fmt.Errorf("output %q: no source %q", o.Name, n)
			}
			if kind != 0 && c.Sources[i].kind != kind {
				return fmt.Errorf("output %q mixes KRL and CRL sources", o.Name)
			}
			kind = c.Sources[i].kind
		}
		switch {
		case kind == revocation.CRL && len(o.Sources) > 1:
			// Several CAs' CRLs are several files: a TLS server reads them
			// one per issuer.
			return fmt.Errorf("output %q: a CRL output takes one source", o.Name)
		case kind == revocation.KRL && o.Format != "":
			return fmt.Errorf("output %q: format is for CRL outputs; a KRL is what sshd reads", o.Name)
		case kind == revocation.CRL && !slices.Contains([]string{"", "der", "pem"}, o.Format):
			return fmt.Errorf("output %q: format %q, want der or pem", o.Name, o.Format)
		}
	}
	return nil
}

func (s *sourceBlock) load() error {
	if s.URL == "" {
		return errors.New("no url")
	}
	switch {
	case s.SSHCA != "" && s.X509CA != "":
		return errors.New("ssh_ca and x509_ca together: one source is one list")
	case s.SSHCA != "":
		b, err := os.ReadFile(s.SSHCA)
		if err != nil {
			return err
		}
		k, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			return fmt.Errorf("ssh_ca %s: %w", s.SSHCA, err)
		}
		if _, isCert := k.(*ssh.Certificate); isCert {
			return fmt.Errorf("ssh_ca %s: a certificate, not the CA's key", s.SSHCA)
		}
		s.kind, s.sshCA = revocation.KRL, k
	case s.X509CA != "":
		b, err := os.ReadFile(s.X509CA)
		if err != nil {
			return err
		}
		blk, _ := pem.Decode(b)
		if blk == nil || blk.Type != "CERTIFICATE" {
			return fmt.Errorf("x509_ca %s: no PEM certificate", s.X509CA)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return fmt.Errorf("x509_ca %s: %w", s.X509CA, err)
		}
		s.kind, s.x509CA = revocation.CRL, c
	default:
		return errors.New("ssh_ca or x509_ca: what the list must be signed by")
	}
	if s.MaxAge != "" {
		d, err := time.ParseDuration(s.MaxAge)
		if err != nil || d <= 0 {
			return fmt.Errorf("max_age %q: a positive duration", s.MaxAge)
		}
		s.maxAge = d
	}
	return nil
}
