// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"errors"
)

var (
	ErrInvalidState     = errors.New("Invalid state")
	ErrInvalidChallenge = errors.New("Invalid or missing challenge")
	ErrAuthn            = errors.New("Authentication error")
	ErrTooManySteps     = errors.New("Step called too many times")
)

// State represents the current state of a client or server's underlying state
// machine. The first two bits represent the current state of the client or
// server and the last 3 bits are a bitmask that represent global properties of
// the state machine.
type State uint8

const (
	stateMask = 0x3
)

const (
	// The current step of the Server or Client (represented by the first two bits
	// of the state byte).
	Initial State = iota
	AuthTextSent
	ResponseSent
	ValidServerResponse

	// Bit is on if the remote client or server supports channel binding.
	RemoteCB State = 1 << 5

	// Bit is on if the machine has errored.
	Errored State = 1 << 6

	// Bit is on if the machine is a server.
	Receiving State = 1 << 7
)

// TODO(ssw): Consider the posibility of having Start return an interface{}
//            which will be remembered by the client or server and then passed
//            back in on calls to Next. This way Mechanisms can actually have
//            some state between calls, but they never have to store it so
//            they're still safe for concurrent use (the Client or Server
//            actually stores the state).

// Mechanism represents a SASL mechanism that can be used by a Client or Server
// to perform the actual negotiation.
//
// Mechanisms must be stateless and may be shared between goroutines.
type Mechanism struct {
	Names []string
	Start func(m *Machine) (more bool, resp []byte, err error)
	Next  func(m *Machine, challenge []byte) (more bool, resp []byte, err error)
}
