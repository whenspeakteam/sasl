// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

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

func scram(name string, fn func() hash.Hash) Mechanism {
	iter := -1
	var salt, nonce, clientFirstMessage, serverSignature []byte
	var gs2Header []byte

	var authzid, username, password []byte

	return Mechanism{
		Name: name,
		Start: func(m Negotiator) (bool, []byte, error) {
			c := m.Config()

			// TODO(ssw): This could probably be done faster and in one pass.
			username = bytes.Replace(c.Username, []byte{'='}, []byte("=3D"), -1)
			username = bytes.Replace(username, []byte{','}, []byte("=2C"), -1)

			if len(c.Identity) != 0 {
				authzid = append([]byte("a="), c.Identity...)
			}

			password = c.Password

			clientFirstMessage = append([]byte("n="), username...)
			clientFirstMessage = append(clientFirstMessage, []byte(",r=")...)
			clientFirstMessage = append(clientFirstMessage, m.Nonce()...)

			switch {
			case m.Config().TLSState == nil || !strings.HasSuffix(name, "-PLUS"):
				// We do not support channel binding
				gs2Header = append([]byte(gs2HeaderNoCBSupport), authzid...)
			case m.State()&RemoteCB == RemoteCB:
				// We support channel binding and the server does too
				gs2Header = append([]byte(gs2HeaderCBSupport), authzid...)
			case m.State()&RemoteCB != RemoteCB:
				// We support channel binding but the server does not
				gs2Header = append([]byte(gs2HeaderNoServerCBSupport), authzid...)
			}
			gs2Header = append(gs2Header, ',')
			return true, append(gs2Header, clientFirstMessage...), nil
		},
		Next: func(m Negotiator, challenge []byte) (bool, []byte, error) {
			state := m.State()
			if challenge == nil || len(challenge) == 0 {
				return false, nil, ErrInvalidChallenge
			}
			if state&Receiving == Receiving {
				panic("sasl: Server side of SCRAM not yet implemented")
			}

			switch state & StepMask {
			case AuthTextSent:
				var err error
				for _, field := range bytes.Split(challenge, []byte{','}) {
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
				case iter < 0:
					return false, nil, errors.New("Iteration count is missing")
				case iter < 0:
					return false, nil, errors.New("Iteration count is invalid")
				case nonce == nil || !bytes.HasPrefix(nonce, m.Nonce()):
					return false, nil, errors.New("Server nonce does not match client nonce")
				case salt == nil:
					return false, nil, errors.New("Server sent empty salt")
				}

				var channelBinding []byte
				if m.Config().TLSState != nil && strings.HasSuffix(name, "-PLUS") {
					channelBinding = make(
						[]byte,
						2+base64.StdEncoding.EncodedLen(len(gs2Header)+len(m.Config().TLSState.TLSUnique)),
					)
					channelBinding[0] = 'c'
					channelBinding[1] = '='
					base64.StdEncoding.Encode(channelBinding[2:], append(gs2Header, m.Config().TLSState.TLSUnique...))
				} else {
					channelBinding = make(
						[]byte,
						2+base64.StdEncoding.EncodedLen(len(gs2Header)),
					)
					channelBinding[0] = 'c'
					channelBinding[1] = '='
					base64.StdEncoding.Encode(channelBinding[2:], gs2Header)
				}
				clientFinalMessageWithoutProof := append(channelBinding, []byte(",r=")...)
				clientFinalMessageWithoutProof = append(clientFinalMessageWithoutProof, nonce...)

				authMessage := append(clientFirstMessage, ',')
				authMessage = append(authMessage, challenge...)
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

				return true, clientFinalMessage, nil
			case ResponseSent:
				clientCalculatedServerFinalMessage := "v=" + base64.StdEncoding.EncodeToString(serverSignature)
				if clientCalculatedServerFinalMessage != string(challenge) {
					fmt.Printf("%s\n", clientCalculatedServerFinalMessage)
					return false, nil, ErrAuthn
				}
				// Success!
				return false, nil, nil
			}
			return false, nil, ErrInvalidState
		},
	}
}
