// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"crypto/tls"
	"strings"
)

// An Option represents an input to a SASL state machine.
type Option func(*Machine)

func getOpts(m *Machine, o ...Option) {
	for _, f := range o {
		f(m)
	}
}

// The ConnState option lets the state machine negotiate channel binding with a
// TLS session if supported by the underlying mechanism.
func ConnState(cs tls.ConnectionState) Option {
	return func(o *Machine) {
		o.TLSState = &cs
	}
}

// The RemoteMechanisms option configures the mechanisms supported by the remote
// client or server with which the state machine will be negotiating. It is used
// to determine if the server supports channel binding and is required for
// proper support.
func RemoteMechanisms(m []string) Option {
	return func(o *Machine) {
		o.RemoteMechanisms = m

		for _, lname := range o.mechanism.Names {
			for _, rname := range m {
				if lname == rname && strings.HasSuffix(lname, "-PLUS") {
					o.state |= RemoteCB
					return
				}
			}
		}
	}
}
