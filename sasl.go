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

// State represents the current state of a Mechanism's underlying state machine.
type State int8

const (
	Initial State = iota
	AuthTextSent
	ResponseSent
	ValidServerResponse
)

// Mechanism represents a SASL mechanism.
//
// Mechanisms must be stateless and may be shared between goroutines.
type Mechanism struct {
	Names []string
	Start func() (more bool, resp []byte, err error)
	Next  func(state State, challenge []byte) (more bool, resp []byte, err error)
}
