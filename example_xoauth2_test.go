// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl_test

import (
	"fmt"

	"mellium.im/sasl"
)

// A custom SASL Mechanism that implements XOAUTH2:
// https://developers.google.com/gmail/xoauth2_protocol
var xoauth2 = sasl.Mechanism{
	Name: "XOAUTH2",
	Start: func(m *sasl.Negotiator) (bool, []byte, interface{}, error) {
		// Start is called only by clients and returns the client first message.

		username, password, _ := m.Credentials()

		payload := []byte(`user=`)
		payload = append(payload, username...)
		payload = append(payload, '\x01')
		payload = append(payload, []byte(`auth=Bearer `)...)
		payload = append(payload, password...)
		payload = append(payload, '\x01', '\x01')

		// We do not need to Base64 encode the payload; the sasl.Negotiator will do
		// that for us.
		return false, payload, nil, nil
	},
	Next: func(m *sasl.Negotiator, challenge []byte, _ interface{}) (bool, []byte, interface{}, error) {
		// Next is called by both clients and servers and must be able to generate
		// and handle every challenge except for the client first message which is
		// generated (but not handled by) by Start.

		state := m.State()

		// If we're a client or a server that's past the AuthTextSent step, we
		// should never actually hit this step for the XOAUTH2 mechanism so return
		// an error.
		if state&sasl.Receiving != sasl.Receiving || state&sasl.StepMask != sasl.AuthTextSent {
			return false, nil, nil, sasl.ErrTooManySteps
		}

		if m.Permissions(m) {
			return false, nil, nil, nil
		}
		return false, nil, nil, sasl.ErrAuthn
	},
}

func Example_xOAUTH2() {
	c := sasl.NewClient(
		xoauth2,
		sasl.Credentials(func() ([]byte, []byte, []byte) {
			return []byte("someuser@example.com"), []byte("vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg=="), []byte{}
		}),
	)

	// This is the first step and we haven't received any challenge from the
	// server yet.
	more, resp, _ := c.Step(nil)
	fmt.Printf("%v %s", more, resp)

	// Output: false dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB2RjlkZnQ0cW1UYzJOdmIzUmxja0JoZEhSaGRtbHpkR0V1WTI5dENnPT0BAQ==
}
