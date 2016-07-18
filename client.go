// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"crypto/tls"
)

// Credentials represent a set of client credentials that will be used by the
// SASL clients underlying mechanism.
type Credentials interface{}

type authz struct {
	Identity string
	Username string
	Password string

	ConnState  *tls.ConnectionState
	ServerPlus bool
}

// NewIdentity returns credentials for SASL mechanisms that take a username and
// password (and an optional authorization identity).
func NewIdentity(identity, username, password string) Credentials {
	return authz{
		Identity: identity,
		Username: username,
		Password: password,
	}
}

// NewChannelBinding returns credentials for SASL mechanisms that require
// a TLS channel binding.
func NewChannelBinding(plus bool, connstate *tls.ConnectionState, creds Credentials) Credentials {
	return authz{
		Identity: identity,
		Username: username,
		Password: password,

		ConnState:  connstate,
		ServerPlus: plus,
	}
}

// A Client represents a stateful SASL client that can attempt to negotiate auth
// using its underlying Mechanism. Client's should not be used from multiple
// goroutines, and must be reset between negotiation attempts.
type Client struct {
	Mechanism   Mechanism
	Credentials Credentials

	state State
	err   error
}

// Step attempts to transition the SASL mechanism to its next state. If Step is
// called after a previous invocation generates an error (and the Client has not
// been reset to its initial state), Step panics.
func (c *Client) Step(challenge []byte) (more bool, resp []byte, err error) {
	if c.Err() != nil {
		panic(c.Err())
	}

	switch c.state {
	case Initial:
		more, resp, c.err = c.Mechanism.Start(c.Credentials)
		c.state = AuthTextSent
		return more, resp, c.err
	case AuthTextSent:
		more, resp, c.err = c.Mechanism.Next(c.state, c.Credentials, challenge)
		c.state = ResponseSent
		return more, resp, c.err
	case ResponseSent:
		more, resp, c.err = c.Mechanism.Next(c.state, c.Credentials, challenge)
		c.state = ValidServerResponse
		return more, resp, c.err
	case ValidServerResponse:
		more, resp, c.err = c.Mechanism.Next(c.state, c.Credentials, challenge)
		return more, resp, c.err
	}

	return false, nil, ErrInvalidState
}

// Err returns any errors generated by the SASL Client.
func (c *Client) Err() error {
	return c.err
}

// State returns the internal state of the SASL Client.
func (c *Client) State() State {
	return c.state
}

// Reset resets the Client to its initial state so that it can be reused in
// another SASL exchange.
func (c *Client) Reset() {
	c.state = State(0)
	c.err = nil
}
