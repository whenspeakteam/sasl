// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

// +build go1.7

package sasl

import (
	"fmt"
	"testing"
)

func doTests(t *testing.T, cases []testCases, fn func(t *testing.T, tc saslTest)) {
	for _, g := range cases {
		for i, tc := range g.cases {
			name := fmt.Sprintf("%s:%d", g.name, i)
			t.Run(name, func(t *testing.T) {
				fn(t, tc)
			})
		}
	}
}
