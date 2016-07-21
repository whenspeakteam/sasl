// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

// Package sasl implements the Simple Authentication and Security Layer (SASL)
// as defined by RFC 4422.
//
// Be advised: This API is still unstable and is subject to change.
package sasl // import "mellium.im/sasl"

// BUG(ssw): The server implementation must take some sort of comparison
//           function that handles checking the credentials so that we can pass
//           in hashed credentials or delegate to another auth backend. Or maybe
//           I should just give up on finding an API that works for clients and
//           servers.
