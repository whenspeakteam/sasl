// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"hash"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

const (
	gs2HeaderCBSupport         = "p=tls-unique,"
	gs2HeaderNoServerCBSupport = "y,"
	gs2HeaderNoCBSupport       = "n,"
)

var (
	clientKeyInput = []byte("Client Key")
	serverKeyInput = []byte("Server Key")
)

// The number of random bytes to generate for a nonce.
const noncerandlen = 16

func scram(authzid, username, password string, names []string, clientNonce []byte, fn func() hash.Hash, plus bool, connstate *tls.ConnectionState) *Mechanism {
	iter := -1
	var salt, nonce, clientFirstMessage, serverSignature []byte
	var gs2Header []byte

	switch {
	case connstate == nil:
		// We do not support channel binding
		gs2Header = []byte(gs2HeaderNoCBSupport + authzid + ",")
	case plus:
		// We support channel binding and the server does too
		gs2Header = []byte(gs2HeaderCBSupport + authzid + ",")
	case !plus:
		// We support channel binding but the server does not
		gs2Header = []byte(gs2HeaderNoServerCBSupport + authzid + ",")
	}
	var channelBinding []byte
	if connstate != nil {
		channelBinding = make(
			[]byte,
			2+base64.StdEncoding.EncodedLen(len(gs2Header)+len(connstate.TLSUnique)),
		)
		channelBinding[0] = 'c'
		channelBinding[1] = '='
		base64.StdEncoding.Encode(channelBinding[2:], append(gs2Header, connstate.TLSUnique...))
	} else {

		channelBinding = make(
			[]byte,
			2+base64.StdEncoding.EncodedLen(len(gs2Header)),
		)
		channelBinding[0] = 'c'
		channelBinding[1] = '='
		base64.StdEncoding.Encode(channelBinding[2:], gs2Header)

	}

	return &Mechanism{
		Names: names,
		Start: func() (bool, []byte, error) {
			// TODO(ssw): Use the correct PRECIS profile on username.
			clientFirstMessage = append([]byte("n="+username+",r="), clientNonce...)

			unencoded := append(gs2Header, clientFirstMessage...)
			b := make([]byte, base64.StdEncoding.EncodedLen(len(unencoded)))
			base64.StdEncoding.Encode(b, unencoded)
			return true, b, nil
		},
		Next: func(state State, challenge []byte) (bool, []byte, error) {
			if challenge == nil || len(challenge) == 0 {
				return false, nil, ErrInvalidChallenge
			}

			switch state {
			case AuthTextSent:
				serverFirstMessage := make([]byte, base64.StdEncoding.DecodedLen(len(challenge)))
				n, err := base64.StdEncoding.Decode(serverFirstMessage, challenge)
				serverFirstMessage = serverFirstMessage[:n]
				if err != nil {
					return false, nil, err
				}
				for _, field := range bytes.Split(serverFirstMessage, []byte{','}) {
					if len(field) < 3 && field[1] != '=' {
						continue
					}
					switch field[0] {
					case 'i':
						ival := string(bytes.TrimRight(field[2:], "\x00"))

						if iter, err = strconv.Atoi(ival); err != nil {
							return false, nil, err
						}
					case 's':
						salt = make([]byte, base64.StdEncoding.DecodedLen(len(field)-2))
						n, err := base64.StdEncoding.Decode(salt, field[2:])
						salt = salt[:n]
						if err != nil {
							return false, nil, err
						}
					case 'r':
						nonce = field[2:]
					case 'm':
						// RFC 5802:
						// m: This attribute is reserved for future extensibility.  In this
						// version of SCRAM, its presence in a client or a server message
						// MUST cause authentication failure when the attribute is parsed by
						// the other end.
						return false, nil, errors.New("Server sent reserved attribute `m`")
					}
				}

				switch {
				case iter <= 0:
					return false, nil, errors.New("Iteration count is missing or invalid")
				case nonce == nil || !bytes.HasPrefix(nonce, clientNonce):
					return false, nil, errors.New("Server nonce does not match client nonce")
				case salt == nil:
					return false, nil, errors.New("Server sent empty salt")
				}

				clientFinalMessageWithoutProof := append(channelBinding, []byte(",r=")...)
				clientFinalMessageWithoutProof = append(clientFinalMessageWithoutProof, nonce...)

				authMessage := append(clientFirstMessage, ',')
				authMessage = append(authMessage, serverFirstMessage...)
				authMessage = append(authMessage, ',')
				authMessage = append(authMessage, clientFinalMessageWithoutProof...)

				// TODO(ssw): Have a shared LRU cache for HMAC and hi calculations

				saltedPassword := pbkdf2.Key([]byte(password), salt, iter, fn().Size(), fn)

				h := hmac.New(fn, saltedPassword)
				h.Write(serverKeyInput)
				serverKey := h.Sum(nil)
				h.Reset()

				h.Write(clientKeyInput)
				clientKey := h.Sum(nil)

				h = hmac.New(fn, serverKey)
				h.Write(authMessage)
				serverSignature = h.Sum(nil)

				h = fn()
				h.Write(clientKey)
				storedKey := h.Sum(nil)
				h = hmac.New(fn, storedKey)
				h.Write(authMessage)
				clientSignature := h.Sum(nil)
				clientProof := make([]byte, len(clientKey))
				xorBytes(clientProof, clientKey, clientSignature)

				encodedClientProof := make([]byte, base64.StdEncoding.EncodedLen(len(clientProof)))
				base64.StdEncoding.Encode(encodedClientProof, clientProof)
				clientFinalMessage := append(clientFinalMessageWithoutProof, []byte(",p=")...)
				clientFinalMessage = append(clientFinalMessage, encodedClientProof...)

				encodedClientFinalMessage := make([]byte, base64.StdEncoding.EncodedLen(len(clientFinalMessage)))
				base64.StdEncoding.Encode(encodedClientFinalMessage, clientFinalMessage)
				return true, encodedClientFinalMessage, nil
			case ResponseSent:
				clientCalculatedServerFinalMessage := "v=" + base64.StdEncoding.EncodeToString(serverSignature)
				serverFinalMessage := make([]byte, base64.StdEncoding.DecodedLen(len(challenge)))
				n, err := base64.StdEncoding.Decode(serverFinalMessage, challenge)
				if err != nil {
					return false, nil, err
				}
				serverFinalMessage = serverFinalMessage[:n]
				if clientCalculatedServerFinalMessage != string(serverFinalMessage) {
					return false, nil, ErrAuthn
				}
				// Success!
				return false, nil, nil
			}
			return false, nil, ErrInvalidState
		},
	}
}

// ScramSha1 returns a Mechanism that implements the SCRAM-SHA-1 and
// SCRAM-SHA-1-PLUS authentication mechanisms defined in RFC 5802. The only
// supported channel binding type is tls-unique as defined in RFC 5929. The plus
// argument indicates that the server advertised support for channel binding and
// is used to help prevent downgrade attacks. Each call to the function returns
// a new Mechanism with its own internal state.
func ScramSha1(username, password string, plus bool, connstate *tls.ConnectionState) *Mechanism {
	return scram("", username, password, []string{
		"SCRAM-SHA-1",
		"SCRAM-SHA-1-PLUS",
	}, nonce(noncerandlen, cryptoReader{}), sha1.New, plus, connstate)
}

// ScramSha256 returns a Mechanism that implements the SCRAM-SHA-256 and
// SCRAM-SHA-256-PLUS authentication mechanisms defined in RFC 7677. The only
// supported channel binding type is tls-unique as defined in RFC 5929. The plus
// argument indicates that the server advertised support for channel binding and
// is used to help prevent downgrade attacks. Each call to the function returns
// a new Mechanism with its own internal state.
func ScramSha256(username, password string, plus bool, connstate *tls.ConnectionState) *Mechanism {
	return scram("", username, password, []string{
		"SCRAM-SHA-256",
		"SCRAM-SHA-256-PLUS",
	}, nonce(noncerandlen, cryptoReader{}), sha256.New, plus, connstate)
}
