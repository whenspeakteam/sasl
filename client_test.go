// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
)

var plainResp = []byte("Ursel\x00Kurt\x00xipj3plmq")

var clientTestCases = testCases{
	name: "Client",
	cases: []saslTest{{
		machine: &client{mechanism: Plain("Ursel", "Kurt", "xipj3plmq")},
		steps: []saslStep{
			saslStep{challenge: []byte{}, resp: plainResp, err: false, more: false},
			saslStep{challenge: nil, resp: nil, err: true, more: false},
		},
	}, {
		machine: NewClient(scram("", "user", "pencil", []string{"SCRAM-SHA-1"}, []byte("fyko+d2lbbFgONRv9qkxdawL"), sha1.New)),
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
		machine: NewClient(
			scram("", "user", "pencil", []string{"SCRAM-SHA-1-PLUS"}, []byte("16090868851744577"), sha1.New),
			RemoteMechanisms("SCRAM-SHA-1-PLUS"),
			ConnState(tls.ConnectionState{TLSUnique: []byte{0, 1, 2, 3, 4}}),
		),
		steps: []saslStep{
			saslStep{
				challenge: nil,
				resp:      []byte(base64.StdEncoding.EncodeToString([]byte(`p=tls-unique,,n=user,r=16090868851744577`))),
				err:       false, more: true,
			},
			saslStep{
				challenge: []byte(base64.StdEncoding.EncodeToString([]byte(`r=1609086885174457716090868851744577,s=QSXCR+Q6sek8bf92,i=4096`))),
				resp:      []byte(base64.StdEncoding.EncodeToString([]byte(`c=cD10bHMtdW5pcXVlLCwAAQIDBA==,r=1609086885174457716090868851744577,p=TWsZ93ST7ELak285XIgun/ncmgc=`))),
				err:       false, more: true,
			},
			saslStep{
				challenge: []byte(base64.StdEncoding.EncodeToString([]byte(`v=yFVSsBQf4DA9XdMzpLeqS55KPbI=`))),
				resp:      nil,
				err:       false, more: false,
			},
		},
	}, {
		machine: NewClient(scram("", "user", "pencil", []string{"SCRAM-SHA-256"}, []byte("rOprNGfwEbeRWgbNEkqO"), sha256.New)),
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
	}, {
		machine: NewClient(
			scram("admin", "user", "pencil", []string{"SCRAM-SHA-256-PLUS"}, []byte("12249535949609558"), sha256.New),
			RemoteMechanisms("SCRAM-SOMETHING", "SCRAM-SHA-256-PLUS"),
			ConnState(tls.ConnectionState{TLSUnique: []byte{0, 1, 2, 3, 4}}),
		),
		steps: []saslStep{
			saslStep{
				challenge: []byte{},
				resp:      []byte(base64.StdEncoding.EncodeToString([]byte("p=tls-unique,a=admin,n=user,r=12249535949609558"))),
				err:       false, more: true,
			},
			saslStep{
				challenge: []byte(base64.StdEncoding.EncodeToString([]byte(`r=12249535949609558,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096`))),
				resp:      []byte(base64.StdEncoding.EncodeToString([]byte(`c=cD10bHMtdW5pcXVlLGE9YWRtaW4sAAECAwQ=,r=12249535949609558,p=b/zH2UdTIxrunMnuLu33ROzfCWxddLlbKbG5d/rIZYs=`))),
				err:       false, more: true,
			},
			saslStep{
				challenge: []byte(base64.StdEncoding.EncodeToString([]byte(`v=kpVveedJkum+8f/fuZpKCX2GfnUt3hUESXXriOsEcWY=`))),
				resp:      nil,
				err:       false, more: false,
			},
		},
	}, {
		machine: NewClient(
			scram("", ",=,=", "password", []string{"SCRAM-SHA-1-PLUS"}, []byte("ournonce"), sha1.New),
			RemoteMechanisms("SCRAM-SHA-1-PLUS"),
			ConnState(tls.ConnectionState{TLSUnique: []byte("finishedmessage")}),
		),
		steps: []saslStep{
			saslStep{
				challenge: []byte{},
				resp:      []byte(base64.StdEncoding.EncodeToString([]byte("p=tls-unique,,n==2C=3D=2C=3D,r=ournonce"))),
				err:       false, more: true,
			},
			saslStep{
				challenge: []byte(base64.StdEncoding.EncodeToString([]byte(`r=ournoncetheirnonce,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096`))),
				resp:      []byte(base64.StdEncoding.EncodeToString([]byte(`c=cD10bHMtdW5pcXVlLCxmaW5pc2hlZG1lc3NhZ2U=,r=ournoncetheirnonce,p=wm7YvWETYFwxXrOeobaAQtbOUn8=`))),
				err:       false, more: true,
			},
			saslStep{
				challenge: []byte(base64.StdEncoding.EncodeToString([]byte(`v=/pzR+ni/RpBjkYNtdH0mR+oMA4Y=`))),
				resp:      nil,
				err:       false, more: false,
			},
		},
	},
	},
}
