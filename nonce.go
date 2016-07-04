// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"crypto/rand"
	"fmt"
	"io"
)

type cryptoReader struct{}

func (cryptoReader) Read(p []byte) (int, error) {
	return rand.Read(p)
}

var noncesrc io.Reader = cryptoReader{}

// TODO(ssw): nonce generation should actually use the ranges 0x21–0x2B,
//            0x2D–0x7E (printable ASCII). Also, Sprintf is slow.
func nonce(n int) string {
	if n < 1 {
		panic("Cannot generate zero or negative length nonce")
	}
	b := make([]byte, (n/2)+(n&1))
	if _, err := noncesrc.Read(b); err != nil {
		panic(err)
	}

	return fmt.Sprintf("%x", b)[:n]
}
