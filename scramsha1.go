// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"crypto/rand"
	"fmt"
)

const ascii = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

const n = 16

func nonce() string {
	b := make([]byte, (n/2)+(n&1))
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return fmt.Sprintf("%x", b)[:n]
}

// ScramSha1 returns a Mechanism that implements SCRAM-SHA-1. Each call to the
// function returns a new Mechanism with its own internal state.
// func ScramSha1(user string) Mechanism {
// 	clientFirstMessageBare := []byte{}
// 	nonce := nonce()
//
// 	return Mechanism{
// 		Start: func(state State) {
// 			if len(clientFirstMessageBare) == 0 && state == Initial {
// 				clientFirstMessageBare = []byte("n=" + user + ",r=" + nonce)
// 			}
// 		},
// 		Next: func() {
// 		},
// 	}
// }
