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

	// Returns a username, and password for authentication and optional identity
	// for authorization.
	Credentials func() (Username, Password, Identity []byte)
}

func getOpts(o ...Option) (cfg Config) {
	cfg.Credentials = func() (username, password, identity []byte) {
		return
	}
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
// authenticate with and (optionally) an authorization identity.
// Identity will normally be left empty to act as the username.
// The Credentials function is called lazily and may be called multiple times by
// the mechanism.
// It is not memoized by the negotiator.
func Credentials(f func() (Username, Password, Identity []byte)) Option {
	return func(o *Config) {
		o.Credentials = f
	}
}
