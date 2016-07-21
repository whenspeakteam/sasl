// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"bytes"
	"crypto/subtle"
)

var plainSep = []byte{0}

// Plain returns a Mechanism that implements the PLAIN authentication mechanism
// as defined by RFC 4616. Usually identity will be left blank to act as
// username.
func Plain(identity, username, password string) Mechanism {
	return Mechanism{
		Names: []string{"PLAIN"},
		Start: func(m *Machine) (bool, []byte, error) {
			return false, []byte(identity + "\x00" + username + "\x00" + password), nil
		},
		Next: func(m *Machine, challenge []byte) (bool, []byte, error) {
			if m.State()&Receiving != Receiving || m.State()&stateMask != AuthTextSent {
				return false, nil, ErrTooManySteps
			}

			// Split "Identity\x00Username\x00Password"
			parts := bytes.Split(challenge, plainSep)
			if len(parts) != 3 {
				return false, nil, ErrInvalidChallenge
			}

			// TODO: See the BUG comment in doc.go. This is only for testing and MUST
			// be removed later.
			if subtle.ConstantTimeCompare(parts[0], []byte(identity)) != 1 ||
				subtle.ConstantTimeCompare(parts[1], []byte(username)) != 1 ||
				subtle.ConstantTimeCompare(parts[2], []byte(password)) != 1 {
				return false, nil, ErrAuthn
			}

			// Everything checks out and the user is authenticated.
			return false, nil, nil
		},
	}
}
