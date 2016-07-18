// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

// A Server represents a stateful SASL server that can attempt to negotiate auth
// using its underlying Mechanism. Server's should not be used from multiple
// goroutines, and must be reset between negotiation attempts.
type Server struct {
	Mechanism Mechanism

	state State
}

// Step attempts to transition the SASL server to its next state. If Step is
// called after a previous invocation generates an error (and the Client has not
// been reset to its initial state), Step panics.
func (s *Server) Step(challenge []byte) (more bool, resp []byte, err error) {
	if s.state&Errored == Errored {
		panic("sasl: Step called on a SASL server that has errored")
	}

	switch s.state & stateMask {
	case Initial:
		more, resp, err = s.Mechanism.Next(s.state, challenge)
		s.state = AuthTextSent
	case AuthTextSent:
		more, resp, err = s.Mechanism.Next(s.state, challenge)
		s.state = ResponseSent
	case ResponseSent:
		more, resp, err = s.Mechanism.Next(s.state, challenge)
		s.state = ValidServerResponse
	case ValidServerResponse:
		more, resp, err = s.Mechanism.Next(s.state, challenge)
	}

	if err != nil {
		s.state = s.state | Errored
	}

	return more, resp, err
}

// State returns the internal state of the SASL Server.
func (s *Server) State() State {
	return s.state
}

// Reset resets the Client to its initial state so that it can be reused in
// another SASL exchange.
func (s *Server) Reset() {
	s.state = Receiving
}
