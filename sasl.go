// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"crypto/sha1"
	"crypto/sha256"
	"errors"
)

var (
	ErrInvalidState     = errors.New("Invalid state")
	ErrInvalidChallenge = errors.New("Invalid or missing challenge")
	ErrAuthn            = errors.New("Authentication error")
	ErrTooManySteps     = errors.New("Step called too many times")
)

var (
	// Plain is a Mechanism that implements the PLAIN authentication mechanism
	// as defined by RFC 4616.
	Plain Mechanism = plain

	// ScramSha256Plus is a Mechanism that implements the SCRAM-SHA-256-PLUS
	// authentication mechanism defined in RFC 7677. The only supported channel
	// binding type is tls-unique as defined in RFC 5929.
	ScramSha256Plus Mechanism = scram("SCRAM-SHA-256-PLUS", sha256.New)

	// ScramSha256 is a Mechanism that implements the SCRAM-SHA-256
	// authentication mechanism defined in RFC 7677.
	ScramSha256 Mechanism = scram("SCRAM-SHA-256", sha256.New)

	// ScramSha1Plus is a Mechanism that implements the SCRAM-SHA-1-PLUS
	// authentication mechanism defined in RFC 5802. The only supported channel
	// binding type is tls-unique as defined in RFC 5929.
	ScramSha1Plus Mechanism = scram("SCRAM-SHA-1-PLUS", sha1.New)

	// ScramSha1 is a Mechanism that implements the SCRAM-SHA-1 authentication
	// mechanism defined in RFC 5802.
	ScramSha1 Mechanism = scram("SCRAM-SHA-1", sha1.New)
)

// TODO(ssw): Consider the posibility of having Start return an interface{}
//            which will be remembered by the client or server and then passed
//            back in on calls to Next. This way Mechanisms can actually have
//            some state between calls, but they never have to store it so
//            they're still safe for concurrent use (the Client or Server
//            actually stores the state).

// Mechanism represents a SASL mechanism that can be used by a Client or Server
// to perform the actual negotiation. Base64 encoding the final challenges and
// responses should not be performed by the mechanism.
//
// Mechanisms must be stateless and may be shared between goroutines.
type Mechanism struct {
	Name  string
	Start func(n Negotiator) (more bool, resp []byte, err error)
	Next  func(n Negotiator, challenge []byte) (more bool, resp []byte, err error)
}
