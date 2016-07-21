// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"crypto/sha1"
	"testing"
)

type saslStep struct {
	challenge []byte
	resp      []byte
	more      bool
	err       bool
}

type saslTest struct {
	machine Negotiator
	steps   []saslStep
}

type testCases struct {
	name  string
	cases []saslTest
}

func TestSASL(t *testing.T) {
	doTests(t, []testCases{clientTestCases, serverTestCases}, func(t *testing.T, test saslTest) {
		// Run each test twice to make srue that Reset actually sets the state back
		// to the initial state.
		for run := 1; run < 3; run++ {
			for i, step := range test.steps {
				more, resp, err := test.machine.Step(step.challenge)
				switch {
				case err != nil && test.machine.State()&Errored != Errored:
					t.Fatalf("Run %d: State machine internal error state was not set, got error: %v", run, err)
				case err == nil && test.machine.State()&Errored == Errored:
					t.Fatalf("Run %d: State machine internal error state was set, but no error was returned", run)
				case string(step.resp) != string(resp):
					t.Fatalf("Run %d: Got invalid challenge text during step %d:\nexpected %s\n     got %s", run, i+1, step.resp, resp)
				case more != step.more:
					t.Fatalf("Run %d: Got unexpected value for more: %v", run, more)
				}
			}
			test.machine.Reset()
		}
	})
}

func BenchmarkScram(b *testing.B) {
	for n := 0; n < b.N; n++ {
		c := NewClient(scram("", "user", "pencil", []string{"SCRAM-SHA-1"}, []byte("fyko+d2lbbFgONRv9qkxdawL"), sha1.New))
		for _, step := range clientTestCases.cases[0].steps {
			more, _, _ := c.Step(step.challenge)
			if !more {
				break
			}
		}
	}
}
