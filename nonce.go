// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"crypto/rand"
	"encoding/base64"
	"io"
)

type cryptoReader struct{}

func (cryptoReader) Read(p []byte) (int, error) {
	return rand.Read(p)
}

var noncesrc io.Reader = cryptoReader{}

// Generates a nonce with n random bytes base64 encoded to ensure that it meets
// the criteria for inclusion in a SCRAM message.
func nonce(n int) []byte {
	if n < 1 {
		panic("Cannot generate zero or negative length nonce")
	}
	b := make([]byte, n)
	if _, err := noncesrc.Read(b); err != nil {
		panic(err)
	}
	val := make([]byte, base64.RawStdEncoding.EncodedLen(n))
	base64.RawStdEncoding.Encode(val, b)

	return val
}
