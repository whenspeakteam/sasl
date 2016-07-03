// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"testing"
)

type saslStep struct {
	challenge []byte
	resp      []byte
	more      bool
	err       bool
}

type saslTest struct {
	mech  *Mechanism
	steps []saslStep
}

func TestPlain(t *testing.T) {
	tests := []saslTest{{
		mech: Plain("Ursel", "Kurt", "xipj3plmq"),
		steps: []saslStep{
			saslStep{challenge: []byte{}, resp: []byte("Ursel\x00Kurt\x00xipj3plmq"), err: false, more: false},
			saslStep{challenge: nil, resp: nil, err: true, more: false},
		},
	}}

	for _, test := range tests {
		for _, step := range test.steps {
			more, err := test.mech.Step(step.challenge)
			switch {
			case test.mech.Err() != err:
				t.Errorf("Mechanism internal error state was not set, got error: %v", err)
			case (test.mech.Err() != nil) != step.err:
				t.Errorf("Unexpected error during SASL PLAIN: %v", test.mech.Err())
			case string(step.resp) != string(test.mech.resp):
				t.Errorf("Got invalid challenge text during SASL PLAIN: %s expected %s", test.mech.resp, step.resp)
			case more != step.more:
				t.Errorf("Got unexpected value for more: %v", more)
			}
		}
	}

}
