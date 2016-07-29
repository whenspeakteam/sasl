// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"crypto/tls"
)

// Config is a SASL client or server configuration.
type Config struct {
	// The state of any TLS connections being used to negotiate SASL (for channel
	// binding).
	TLSState *tls.ConnectionState

	// A list of mechanisms as advertised by the other side of a SASL negotiation.
	RemoteMechanisms []string

	// An authorization identity, username, and password for the user that we're
	// negotiating auth for. Identity will normally be left empty to act as the
	// username.
	Identity, Username, Password string
}
