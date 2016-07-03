// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"testing"
)

type saslStep struct {
	c []byte
	r []byte
	e bool
}

type saslTest []saslStep

func TestPlain(t *testing.T) {
	tests := saslTest{
		saslStep{},
		saslStep{c: nil, r: nil, e: true},
	}
	p := Plain("Ursel", "Kurt", "xipj3plmq")
	b, e := p.Step([]byte{})
	switch {
	case e != nil:
		t.Error("Unexpected error during SASL PLAIN:", e)
	case string(b) != "Ursel\x00Kurt\x00xipj3plmq":
		t.Errorf("Got invalid challenge text during SASL PLAIN: %s", b)
	}
	b, e = p.Step([]byte{})

}
