// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"testing"
)

func TestNewServerSetsState(t *testing.T) {
	s := NewServer(Plain("", "", ""))
	if s.state&Receiving != Receiving {
		t.Error("Expected Server's created with NewServer to have Receiving state bit set")
	}
}

var serverTestCases = testCases{
	name: "Server",
	cases: []saslTest{{
		machine: NewServer(Plain("Ursel", "Kurt", "xipj3plmq")),
		steps: []saslStep{
			saslStep{challenge: []byte("Ursel\x00Kurt\x00xipj3plmq"), resp: nil, err: false, more: false},
			saslStep{challenge: nil, resp: nil, err: true, more: false},
		},
	}},
}
