// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

// A Client represents a stateful SASL client that can attempt to negotiate auth
// using its underlying Mechanism. Client's should not be used from multiple
// goroutines, and must be reset between negotiation attempts.
type Client struct {
	Mechanism Mechanism

	state State
}

// Step attempts to transition the SASL client to its next state. If Step is
// called after a previous invocation generates an error (and the Client has not
// been reset to its initial state), Step panics.
func (c *Client) Step(challenge []byte) (more bool, resp []byte, err error) {
	if c.state&Errored == Errored {
		panic("sasl: Step called on a SASL client that has errored")
	}

	switch c.state & stateMask {
	case Initial:
		more, resp, err = c.Mechanism.Start()
		c.state = AuthTextSent
	case AuthTextSent:
		more, resp, err = c.Mechanism.Next(c.state, challenge)
		c.state = ResponseSent
	case ResponseSent:
		more, resp, err = c.Mechanism.Next(c.state, challenge)
		c.state = ValidServerResponse
	case ValidServerResponse:
		more, resp, err = c.Mechanism.Next(c.state, challenge)
	}

	if err != nil {
		c.state = c.state | Errored
	}

	return more, resp, err
}

// State returns the internal state of the SASL Client.
func (c *Client) State() State {
	return c.state
}

// Reset resets the Client to its initial state so that it can be reused in
// another SASL exchange.
func (c *Client) Reset() {
	c.state = State(0)
}
