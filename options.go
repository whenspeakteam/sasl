// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"crypto/tls"
)

// An Option represents an input to a SASL state machine.
type Option func(*Config)

// Config is a SASL client or server configuration.
type Config struct {
	// The state of any TLS connections being used to negotiate SASL (for channel
	// binding).
	TLSState *tls.ConnectionState

	// A list of mechanisms as advertised by the other side of a SASL negotiation.
	RemoteMechanisms []string

	// An authorization identity, username, and password for the user that we're
	// negotiating auth for. Identity will normally be left empty to act as the
	// username.
	Identity, Username, Password []byte
}

func getOpts(o ...Option) (cfg Config) {
	for _, f := range o {
		f(&cfg)
	}
	return
}

// ConnState lets the state machine negotiate channel binding with a TLS session
// if supported by the underlying mechanism.
func ConnState(cs tls.ConnectionState) Option {
	return func(o *Config) {
		o.TLSState = &cs
	}
}

// RemoteMechanisms configures the mechanisms supported by the remote client or
// server with which the state machine will be negotiating.
// It is used to determine if the server supports channel binding and is
// required for proper support.
func RemoteMechanisms(m ...string) Option {
	return func(o *Config) {
		o.RemoteMechanisms = m
	}
}

// Credentials provides the negotiator with a username and password to
// authenticate with.
func Credentials(username, password string) Option {
	return func(o *Config) {
		o.Username = []byte(username)
		o.Password = []byte(password)
	}
}

// Authz is the identity of a user that we will act as. Generally it is left off
// to act as the user that is logging in.
func Authz(identity string) Option {
	return func(o *Config) {
		o.Identity = []byte(identity)
	}
}
