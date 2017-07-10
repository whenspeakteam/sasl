// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"bytes"
	"io"
	"io/ioutil"
)

// BUG(ssw): Builtin mechanisms perform unnecessary heap allocations.

var plainSep = []byte{0}

var plain = Mechanism{
	Name: "PLAIN",
	Start: func(m *Negotiator, w io.Writer) (more bool, _ interface{}, err error) {
		c := m.Config()
		_, err = w.Write(c.Identity)
		if err != nil {
			return
		}
		_, err = w.Write(plainSep)
		if err != nil {
			return
		}
		_, err = w.Write(c.Username)
		if err != nil {
			return
		}
		_, err = w.Write(plainSep)
		if err != nil {
			return
		}
		_, err = w.Write(c.Password)
		return
	},
	Next: func(m *Negotiator, rw io.ReadWriter, _ interface{}) (more bool, _ interface{}, err error) {
		// If we're a client, or we're a server that's past the AuthTextSent step,
		// we should never actually hit this step.
		if m.State()&Receiving != Receiving || m.State()&StepMask != AuthTextSent {
			err = ErrTooManySteps
			return
		}

		challenge, err := ioutil.ReadAll(rw)
		if err != nil {
			return more, nil, err
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
		_, err = rw.Write(challenge)
		return
	},
}
