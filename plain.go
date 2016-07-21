// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

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
			if m.State()&Receiving == Receiving {
				panic("sasl: Server side of PLAIN not yet implemented")
			} else {
				return false, nil, ErrTooManySteps
			}
		},
	}
}
