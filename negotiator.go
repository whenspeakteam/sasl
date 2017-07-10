// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
)

// State represents the current state of a Negotiator. The first two bits
// represent the actual state of the state machine and the last 3 bits are a
// bitmask that define the machines behavior. The remaining bits should not be
// used.
type State uint8

// The current step of the Server or Client (represented by the first two bits
// of the state byte).
const (
	Initial State = iota
	AuthTextSent
	ResponseSent
	ValidServerResponse

	// Bitmask used for extracting the step from the state byte.
	StepMask = 0x3
)

const (
	// RemoteCB bit is on if the remote client or server supports channel binding.
	RemoteCB State = 1 << (iota + 3)

	// Errored bit is on if the machine has errored.
	Errored

	// Receiving bit is on if the machine is a server.
	Receiving
)

// NewClient creates a new SASL Negotiator that supports creating authentication
// requests using the given mechanism.
func NewClient(m Mechanism, opts ...Option) *Negotiator {
	machine := &Negotiator{
		config:    getOpts(opts...),
		mechanism: m,
		nonce:     nonce(noncerandlen, rand.Reader),
	}
	for _, rname := range machine.config.RemoteMechanisms {
		lname := m.Name
		if lname == rname && strings.HasSuffix(lname, "-PLUS") {
			machine.state |= RemoteCB
			return machine
		}
	}
	return machine
}

// A Negotiator represents a SASL client or server state machine that can
// attempt to negotiate auth. Negotiators should not be used from multiple
// goroutines, and must be reset between negotiation attempts.
type Negotiator struct {
	config    Config
	mechanism Mechanism
	state     State
	nonce     []byte
	cache     interface{}
}

// Nonce returns a unique nonce that is reset for each negotiation attempt. It
// is used by SASL Mechanisms and should generally not be called directly.
func (c *Negotiator) Nonce() []byte {
	return c.nonce
}

// Step attempts to transition the state machine to its next state. If Step is
// called after a previous invocation generates an error (and the state machine
// has not been reset to its initial state), Step panics.
func (c *Negotiator) Step(rw io.ReadWriter) (more bool, err error) {
	if c.state&Errored == Errored {
		panic("sasl: Step called on a SASL state machine that has errored")
	}
	defer func() {
		if err != nil {
			c.state |= Errored
		}
	}()

	decodeChallenge := base64.NewDecoder(base64.StdEncoding, rw)
	encodeResp := base64.NewEncoder(base64.StdEncoding, rw)
	rw = struct {
		io.Reader
		io.Writer
	}{
		Reader: decodeChallenge,
		Writer: encodeResp,
	}

	switch c.state & StepMask {
	case Initial:
		more, c.cache, err = c.mechanism.Start(c, encodeResp)
		c.state = c.state&^StepMask | AuthTextSent
	case AuthTextSent:
		more, c.cache, err = c.mechanism.Next(c, rw, c.cache)
		c.state = c.state&^StepMask | ResponseSent
	case ResponseSent:
		more, c.cache, err = c.mechanism.Next(c, rw, c.cache)
		c.state = c.state&^StepMask | ValidServerResponse
	case ValidServerResponse:
		more, c.cache, err = c.mechanism.Next(c, rw, c.cache)
	}

	if err != nil {
		return more, err
	}

	return more, encodeResp.Close()
}

// State returns the internal state of the SASL state machine.
func (c *Negotiator) State() State {
	return c.state
}

// Reset resets the state machine to its initial state so that it can be reused
// in another SASL exchange.
func (c *Negotiator) Reset() {
	c.state = c.state & (Receiving | RemoteCB)

	// Skip the start step for servers
	if c.state&Receiving == Receiving {
		c.state = c.state&^StepMask | AuthTextSent
	}

	c.nonce = nonce(noncerandlen, rand.Reader)
	c.cache = nil
}

// Config returns the Negotiators configuration.
func (c *Negotiator) Config() Config {
	return c.config
}
