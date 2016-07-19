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
