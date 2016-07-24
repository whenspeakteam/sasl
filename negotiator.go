// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"strings"
)

// State represents the current state of a client or server's underlying state
// machine. The first two bits represent the current state of the client or
// server and the last 3 bits are a bitmask that represent global properties of
// the state machine.
type State uint8

const (
	// The current step of the Server or Client (represented by the first two bits
	// of the state byte).
	Initial State = iota
	AuthTextSent
	ResponseSent
	ValidServerResponse

	// Bitmask used for extracting the step from the state byte.
	StepMask = 0x3
)

const (
	// Bit is on if the Negotiator supports channel binding, regardless of whether
	// the underlying mechanism actually supports it.
	LocalCB State = 1 << (iota + 4)

	// Bit is on if the remote client or server supports channel binding.
	RemoteCB

	// Bit is on if the machine has errored.
	Errored

	// Bit is on if the machine is a server.
	Receiving
)

// A Negotiator represents a SASL client or server state machine that can
// attempt to negotiate auth. Negotiators should not be used from multiple
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
// called after a previous invocation generates an error (and the state machine
// has not been reset to its initial state), Step panics.
func (c *client) Step(challenge []byte) (more bool, resp []byte, err error) {
	if c.state&Errored == Errored {
		panic("sasl: Step called on a SASL state machine that has errored")
	}

	switch c.state & StepMask {
	case Initial:
		more, resp, err = c.mechanism.Start(c)
		c.state = c.state&^StepMask | AuthTextSent
	case AuthTextSent:
		more, resp, err = c.mechanism.Next(c, challenge)
		c.state = c.state&^StepMask | ResponseSent
	case ResponseSent:
		more, resp, err = c.mechanism.Next(c, challenge)
		c.state = c.state&^StepMask | ValidServerResponse
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

	// Skip the start step for servers
	if c.state&Receiving == Receiving {
		c.state = c.state&^StepMask | AuthTextSent
	}
}

// Config returns the clients configuration.
func (c *client) Config() Config {
	return c.config
}
