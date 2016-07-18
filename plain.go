// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

// Plain implements the PLAIN authentication mechanism as defined by RFC 4616.
var Plain = Mechanism{
	Names: []string{"PLAIN"},
	Start: func(creds Credentials) (bool, []byte, error) {
		c := creds.(authz)
		return false, []byte(c.Identity + "\x00" + c.Username + "\x00" + c.Password), nil
	},
	Next: func(state State, creds Credentials, challenge []byte) (bool, []byte, error) {
		return false, nil, ErrTooManySteps
	},
}
