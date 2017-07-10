// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl_test

import (
	"io"
	"os"

	"mellium.im/sasl"
)

// A custom SASL Mechanism that implements XOAUTH2:
// https://developers.google.com/gmail/xoauth2_protocol
var xoauth2 = sasl.Mechanism{
	Name: "XOAUTH2",
	Start: func(m *sasl.Negotiator, resp io.Writer) (bool, interface{}, error) {
		// Start is called only by clients and returns the client first message.

		c := m.Config()

		_, err := resp.Write([]byte(`user=`))
		if err != nil {
			return false, nil, err
		}
		_, err = resp.Write(c.Username)
		if err != nil {
			return false, nil, err
		}
		_, err = resp.Write([]byte{'\x01'})
		if err != nil {
			return false, nil, err
		}
		_, err = resp.Write([]byte(`auth=Bearer `))
		if err != nil {
			return false, nil, err
		}
		_, err = resp.Write(c.Password)
		if err != nil {
			return false, nil, err
		}
		_, err = resp.Write([]byte{'\x01', '\x01'})
		if err != nil {
			return false, nil, err
		}

		// We do not need to Base64 encode the payload; the sasl.Negotiator will do
		// that for us.
		return false, nil, nil
	},
	Next: func(m *sasl.Negotiator, rw io.ReadWriter, _ interface{}) (bool, interface{}, error) {
		// Next is called by both clients and servers and must be able to generate
		// and handle every challenge except for the client first message which is
		// generated (but not handled by) by Start.

		// If we're a client or a server that's past the AuthTextSent step, we
		// should never actually hit this step for the XOAUTH2 mechanism so return
		// an error.
		if m.State()&sasl.Receiving != sasl.Receiving || m.State()&sasl.StepMask != sasl.AuthTextSent {
			return false, nil, sasl.ErrTooManySteps
		}

		// The server will take the auth from here. We don't really do much with
		// this mechanism since there is only one step.
		return false, nil, nil
	},
}

func Example_xOAUTH2() {
	c := sasl.NewClient(xoauth2, sasl.Credentials(
		"someuser@example.com", "vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg=="),
	)

	// This is the first step and we haven't received any challenge from the
	// server yet.
	c.Step(struct {
		io.Reader
		io.Writer
	}{
		Reader: nil,
		Writer: os.Stdout,
	})

	// Output: dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB2RjlkZnQ0cW1UYzJOdmIzUmxja0JoZEhSaGRtbHpkR0V1WTI5dENnPT0BAQ==
}
