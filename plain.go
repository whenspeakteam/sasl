// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"bytes"
)

var plainSep = []byte{0}

var plain = Mechanism{
	Name: "PLAIN",
	Start: func(m Negotiator) (more bool, resp []byte, _ interface{}, err error) {
		c := m.Config()
		ilen, ulen, plen := len(c.Identity), len(c.Username), len(c.Password)
		payload := make([]byte, ilen+ulen+plen+2)
		copy(payload, c.Identity)
		payload[ilen] = '\x00'
		copy(payload[ilen+1:], c.Username)
		payload[ilen+ulen+1] = '\x00'
		copy(payload[ilen+ulen+2:], c.Password)
		return false, payload, nil, nil
	},
	Next: func(m Negotiator, challenge []byte, _ interface{}) (more bool, resp []byte, _ interface{}, err error) {
		// If we're a client or a server that's past the AuthTextSent step, we
		// should never actually hit this step.
		if m.State()&Receiving != Receiving || m.State()&StepMask != AuthTextSent {
			err = ErrTooManySteps
			return
		}

		// If we're a server, validate that the challenge looks like:
		// "Identity\x00Username\x00Password"
		parts := bytes.Split(challenge, plainSep)
		if len(parts) != 3 {
			err = ErrInvalidChallenge
			return
		}

		// Everything checks out as far as we know and the server should continue
		// to authenticate the user.
		resp = challenge
		return
	},
}
