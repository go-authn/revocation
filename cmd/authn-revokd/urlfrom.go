// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-authn/secretsource"
)

// credentialParams are query parameters that carry a credential. Best effort:
// the control that holds whatever this misses is url_from, which the message
// names.
var credentialParams = []string{
	"token", "access_token", "auth_token", "api_token", "apikey", "api_key",
	"key", "secret", "client_secret", "password", "passwd", "pwd", "sig", "signature",
}

// resolveURL sets s.URL from url or url_from, exactly one of them. A url that
// carries a credential is refused: it would sit in the configuration, its
// backups and its process listing, and the configuration is not a secret.
func (s *sourceBlock) resolveURL() error {
	switch {
	case s.URL != "" && s.URLFrom != "":
		return errors.New("url and url_from are both set: name one")
	case s.URL == "" && s.URLFrom == "":
		return errors.New("no url (set url, or url_from for one that carries a credential)")
	case s.URL != "":
		return checkNoCredential(s.URL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), secretsource.Timeout)
	defer cancel()
	sec, err := secretsource.Open(ctx, s.URLFrom)
	if err != nil {
		return fmt.Errorf("url_from %s: %w", s.URLFrom, err)
	}
	defer sec.Close()
	s.URL = strings.TrimSpace(string(sec.Bytes()))
	if s.URL == "" {
		return fmt.Errorf("url_from %s: it holds no URL", s.URLFrom)
	}
	return nil
}

// checkNoCredential refuses a URL that carries a password or a token. It says
// what was found, never the value.
func checkNoCredential(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		// The parse error quotes the URL, which may carry a credential: not here.
		return errors.New("url does not parse")
	}
	const hint = "put the URL in a secretsource reference instead: url_from = \"systemd-creds:NAME\""
	if u.User != nil {
		if _, has := u.User.Password(); has {
			return fmt.Errorf("url carries a password: %s", hint)
		}
	}
	for k := range u.Query() {
		for _, c := range credentialParams {
			if strings.EqualFold(k, c) {
				return fmt.Errorf("url carries a %q query parameter, which looks like a credential: %s", c, hint)
			}
		}
	}
	return nil
}
