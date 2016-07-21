// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"crypto/tls"
)

// A Machine represents a SASL client or server state machine that can attempt
// to negotiate auth using its underlying Mechanism. Machines should not be used
// from multiple goroutines, and must be reset between negotiation attempts.
type Machine struct {
	// The state of any TLS connections being used to negotiate SASL (for channel
	// binding).
	TLSState *tls.ConnectionState

	RemoteMechanisms []string

	mechanism Mechanism
	state     State
}

// NewServer creates a new SASL server that supports the given mechanism.
func NewServer(m Mechanism, opts ...Option) *Machine {
	machine := &Machine{
		mechanism: m,
		state:     Receiving,
	}
	getOpts(machine, opts...)
	return machine
}

// NewClient creates a new SASL client that supports the given mechanism.
func NewClient(m Mechanism, opts ...Option) *Machine {
	machine := &Machine{
		mechanism: m,
	}
	getOpts(machine, opts...)
	return machine
}

// Step attempts to transition the state machine to its next state. If Step is
// called after a previous invocation generates an error (and the Machine has
// not been reset to its initial state), Step panics.
func (c *Machine) Step(challenge []byte) (more bool, resp []byte, err error) {
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
func (c *Machine) State() State {
	return c.state
}

// Reset resets the state machine to its initial state so that it can be reused
// in another SASL exchange.
func (c *Machine) Reset() {
	c.state = c.state & Receiving
}
