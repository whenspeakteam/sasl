// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"strings"
)

// A Negotiator represents a SASL client or server state machine that can
// attempt to negotiate auth. Machines should not be used from multiple
// goroutines, and must be reset between negotiation attempts.
type Negotiator interface {
	Step(challenge []byte) (more bool, resp []byte, err error)
	State() State
	Config() Config
	Reset()
}

type client struct {
	config    Config
	mechanism Mechanism
	state     State
}

// NewClient creates a new SASL client that supports the given mechanism.
func NewClient(m Mechanism, opts ...Option) Negotiator {
	machine := &client{
		config:    getOpts(opts...),
		mechanism: m,
	}
	for _, lname := range m.Names {
		for _, rname := range machine.config.RemoteMechanisms {
			if lname == rname && strings.HasSuffix(lname, "-PLUS") {
				machine.state |= RemoteCB
				return machine
			}
		}
	}
	return machine
}

// Step attempts to transition the state machine to its next state. If Step is
// called after a previous invocation generates an error (and the Machine has
// not been reset to its initial state), Step panics.
func (c *client) Step(challenge []byte) (more bool, resp []byte, err error) {
	if c.state&Errored == Errored {
		panic("sasl: Step called on a SASL state machine that has errored")
	}

	switch c.state & stateMask {
	case Initial:
		more, resp, err = c.mechanism.Start(c)
		c.state = AuthTextSent
	case AuthTextSent:
		more, resp, err = c.mechanism.Next(c, challenge)
		c.state = ResponseSent
	case ResponseSent:
		more, resp, err = c.mechanism.Next(c, challenge)
		c.state = ValidServerResponse
	case ValidServerResponse:
		more, resp, err = c.mechanism.Next(c, challenge)
	}

	if err != nil {
		c.state = c.state | Errored
	}

	return more, resp, err
}

// State returns the internal state of the SASL state machine.
func (c *client) State() State {
	return c.state
}

// Reset resets the state machine to its initial state so that it can be reused
// in another SASL exchange.
func (c *client) Reset() {
	c.state = c.state & (Receiving | RemoteCB)
}

// Config returns the clients configuration.
func (c *client) Config() Config {
	return c.config
}
