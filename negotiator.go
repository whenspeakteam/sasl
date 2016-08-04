// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"encoding/base64"
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

// A Negotiator represents a SASL client or server state machine that can
// attempt to negotiate auth. Negotiators should not be used from multiple
// goroutines, and must be reset between negotiation attempts.
type Negotiator interface {
	// Step is responsible for advancing the state machine and using the
	// underlying mechanism. It should base64 decode the challenge (using the
	// standard base64 encoding) and base64 encode the response generated from the
	// underlying mechanism before returning it.
	Step(challenge []byte) (more bool, resp []byte, err error)
	State() State
	Config() Config
	Nonce() []byte
	Reset()
}

type client struct {
	config    Config
	mechanism Mechanism
	state     State
	nonce     []byte
	cache     map[string]interface{}
}

// NewClient creates a new SASL client that supports the given mechanism.
func NewClient(m Mechanism, opts ...Option) Negotiator {
	machine := &client{
		config:    getOpts(opts...),
		mechanism: m,
		nonce:     nonce(noncerandlen, cryptoReader{}),
		cache:     make(map[string]interface{}),
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

func (c *client) Nonce() []byte {
	return c.nonce
}

// Step attempts to transition the state machine to its next state. If Step is
// called after a previous invocation generates an error (and the state machine
// has not been reset to its initial state), Step panics.
func (c *client) Step(challenge []byte) (more bool, resp []byte, err error) {
	if c.state&Errored == Errored {
		panic("sasl: Step called on a SASL state machine that has errored")
	}
	defer func() {
		if err != nil {
			c.state = c.state | Errored
		}
	}()

	decodedChallenge := make([]byte, base64.StdEncoding.DecodedLen(len(challenge)))
	n, err := base64.StdEncoding.Decode(decodedChallenge, challenge)
	if err != nil {
		return false, nil, err
	}
	decodedChallenge = decodedChallenge[:n]

	switch c.state & StepMask {
	case Initial:
		more, resp, c.cache[c.mechanism.Name], err = c.mechanism.Start(c)
		c.state = c.state&^StepMask | AuthTextSent
	case AuthTextSent:
		more, resp, c.cache[c.mechanism.Name], err = c.mechanism.Next(c, decodedChallenge, c.cache[c.mechanism.Name])
		c.state = c.state&^StepMask | ResponseSent
	case ResponseSent:
		more, resp, c.cache[c.mechanism.Name], err = c.mechanism.Next(c, decodedChallenge, c.cache[c.mechanism.Name])
		c.state = c.state&^StepMask | ValidServerResponse
	case ValidServerResponse:
		more, resp, c.cache[c.mechanism.Name], err = c.mechanism.Next(c, decodedChallenge, c.cache[c.mechanism.Name])
	}

	if err != nil {
		return false, nil, err
	}

	encodedResp := make([]byte, base64.StdEncoding.EncodedLen(len(resp)))
	base64.StdEncoding.Encode(encodedResp, resp)

	return more, encodedResp, err
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

	c.nonce = nonce(noncerandlen, cryptoReader{})
	c.cache = make(map[string]interface{})
}

// Config returns the clients configuration.
func (c *client) Config() Config {
	return c.config
}
