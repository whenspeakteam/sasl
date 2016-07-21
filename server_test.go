// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

func newServer(m Mechanism) Negotiator {
	s := NewClient(m)
	c := s.(*client)
	c.state = AuthTextSent
	c.state |= Receiving
	return c
}

var serverTestCases = testCases{
	name: "Server",
	cases: []saslTest{{
		machine: newServer(Plain("", "", "")),
		steps: []saslStep{
			saslStep{challenge: []byte("Ursel\x00Kurt\x00xipj3plmq\x00"), resp: nil, err: true, more: false},
		},
	}, {
		machine: newServer(Plain("", "", "")),
		steps: []saslStep{
			saslStep{challenge: []byte("\x00Ursel\x00Kurt\x00xipj3plmq"), resp: nil, err: true, more: false},
		},
	}, {
		machine: newServer(Plain("", "", "")),
		steps: []saslStep{
			saslStep{challenge: []byte("Ursel\x00Kurt\x00xipj3plmq"), resp: nil, err: false, more: false},
		},
	}},
}
