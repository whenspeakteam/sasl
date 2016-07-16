// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
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

var testCases = []struct {
	name  string
	cases []saslTest
}{{
	name: "PLAIN",
	cases: []saslTest{{
		mech: Plain("Ursel", "Kurt", "xipj3plmq"),
		steps: []saslStep{
			saslStep{challenge: []byte{}, resp: []byte("Ursel\x00Kurt\x00xipj3plmq"), err: false, more: false},
			saslStep{challenge: nil, resp: nil, err: true, more: false},
		},
	}},
}, {
	name: "SCRAM",
	cases: []saslTest{{
		mech: scram("", "user", "pencil", []string{"SCRAM-SHA-1"}, []byte("fyko+d2lbbFgONRv9qkxdawL"), sha1.New, false, nil),
		steps: []saslStep{
			saslStep{
				challenge: nil,
				resp:      []byte(base64.StdEncoding.EncodeToString([]byte(`n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL`))),
				err:       false, more: true,
			},
			saslStep{
				challenge: []byte(base64.StdEncoding.EncodeToString([]byte(`r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096`))),
				resp:      []byte(base64.StdEncoding.EncodeToString([]byte(`c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=`))),
				err:       false, more: true,
			},
			saslStep{
				challenge: []byte(base64.StdEncoding.EncodeToString([]byte(`v=rmF9pqV8S7suAoZWja4dJRkFsKQ=`))),
				resp:      nil,
				err:       false, more: false,
			},
		},
	}, {
		mech: scram("", "user", "pencil", []string{"SCRAM-SHA-256"}, []byte("rOprNGfwEbeRWgbNEkqO"), sha256.New, false, nil),
		steps: []saslStep{
			saslStep{
				challenge: []byte{},
				resp:      []byte(base64.StdEncoding.EncodeToString([]byte("n,,n=user,r=rOprNGfwEbeRWgbNEkqO"))),
				err:       false, more: true,
			},
			saslStep{
				challenge: []byte(base64.StdEncoding.EncodeToString([]byte(`r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096`))),
				resp:      []byte(base64.StdEncoding.EncodeToString([]byte(`c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=`))),
				err:       false, more: true,
			},
			saslStep{
				challenge: []byte(base64.StdEncoding.EncodeToString([]byte(`v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=`))),
				resp:      nil,
				err:       false, more: false,
			},
		},
	}},
}}

func TestSasl(t *testing.T) {
	doTests(t, func(t *testing.T, test saslTest) {
		for i, step := range test.steps {
			more, resp, err := test.mech.Step(step.challenge)
			switch {
			case test.mech.Err() != err:
				t.Fatalf("Mechanism internal error state was not set, got error: %v", err)
			case (test.mech.Err() != nil) != step.err:
				t.Fatalf("Unexpected error: %v", test.mech.Err())
			case string(step.resp) != string(resp):
				t.Fatalf("Got invalid challenge text during step %d:\nexpected %s\n     got %s", i+1, step.resp, resp)
			case more != step.more:
				t.Fatalf("Got unexpected value for more: %v", more)
			}
		}
	})
}

func BenchmarkScram(b *testing.B) {
	for n := 0; n < b.N; n++ {
		m := scram("", "user", "pencil", []string{"SCRAM-SHA-1"}, []byte("fyko+d2lbbFgONRv9qkxdawL"), sha1.New, false, nil)
		for _, step := range testCases[1].cases[0].steps {
			more, _, _ := m.Step(step.challenge)
			if !more {
				break
			}
		}
	}
}
