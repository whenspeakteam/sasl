// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"errors"
	"flag"
	"os"
	"testing"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := 0; i < cap(p); i++ {
		p[i] = 0
	}
	return cap(p), nil
}

func TestMain(m *testing.M) {
	flag.Parse()
	noncesrc = zeroReader{}
	os.Exit(m.Run())
}

func TestNoncePanicsIfLenZero(t *testing.T) {
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected nonce() to panic if given zero length")
			}
		}()

		nonce(0)
	}()
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected nonce() to panic if given negative length")
			}
		}()

		nonce(-1)
	}()
}

func TestNonceLength(t *testing.T) {
	for _, l := range []int{1, 2, 3, 16} {
		if n := nonce(l); len(n) != l {
			t.Errorf("Invalid length for nonce; expected %d but got %d", l, len(n))
		}
	}
}

type errReader struct{}

func (errReader) Read(p []byte) (int, error) {
	return 0, errors.New("Expected errReader error")
}

func TestNoncePanicsOnErrorReadingRand(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected nonce to panic if generating randomness fails")
		}
		noncesrc = zeroReader{}
	}()

	noncesrc = errReader{}
	nonce(1)
}

func BenchmarkNonce(b *testing.B) {
	for i := 0; i < b.N; i++ {
		nonce(16)
	}
}
