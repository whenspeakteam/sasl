// Copyright 2016 Sam Whited.
// Use of this source code is governed by the BSD 2-clause license that can be
// found in the LICENSE file.

package sasl

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"hash"
	"io"
	"io/ioutil"
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

func getGS2Header(name string, n *Negotiator) (gs2Header []byte) {
	c := n.Config()
	switch {
	case c.TLSState == nil || !strings.HasSuffix(name, "-PLUS"):
		// We do not support channel binding
		gs2Header = []byte(gs2HeaderNoCBSupport)
	case n.State()&RemoteCB == RemoteCB:
		// We support channel binding and the server does too
		gs2Header = []byte(gs2HeaderCBSupport)
	case n.State()&RemoteCB != RemoteCB:
		// We support channel binding but the server does not
		gs2Header = []byte(gs2HeaderNoServerCBSupport)
	}
	if len(c.Identity) > 0 {
		gs2Header = append(gs2Header, []byte(`a=`)...)
		gs2Header = append(gs2Header, c.Identity...)
	}
	gs2Header = append(gs2Header, ',')
	return
}

func scram(name string, fn func() hash.Hash) Mechanism {
	// BUG(ssw): We need a way to cache the SCRAM client and server key
	//           calculations.
	return Mechanism{
		Name: name,
		Start: func(m *Negotiator, resp io.Writer) (bool, interface{}, error) {
			c := m.Config()

			// Escape "=" and ",". This is mostly the same as bytes.Replace but
			// faster because we can do both replacements in a single pass.
			n := bytes.Count(c.Username, []byte{'='}) + bytes.Count(c.Username, []byte{','})
			username := make([]byte, len(c.Username)+(n*2))
			w := 0
			start := 0
			for i := 0; i < n; i++ {
				j := start
				j += bytes.IndexAny(c.Username[start:], "=,")
				w += copy(username[w:], c.Username[start:j])
				switch c.Username[j] {
				case '=':
					w += copy(username[w:], "=3D")
				case ',':
					w += copy(username[w:], "=2C")
				}
				start = j + 1
			}
			copy(username[w:], c.Username[start:])

			clientFirstMessage := make([]byte, 5+len(m.Nonce())+len(username))
			copy(clientFirstMessage, "n=")
			copy(clientFirstMessage[2:], username)
			copy(clientFirstMessage[2+len(username):], ",r=")
			copy(clientFirstMessage[5+len(username):], m.Nonce())

			gs2Header := getGS2Header(name, m)
			_, err := resp.Write(gs2Header)
			if err != nil {
				return false, nil, err
			}
			_, err = resp.Write(clientFirstMessage)
			if err != nil {
				return false, nil, err
			}

			return true, clientFirstMessage, nil
		},
		Next: func(m *Negotiator, rw io.ReadWriter, data interface{}) (more bool, cache interface{}, err error) {
			c := m.Config()
			state := m.State()

			challenge, err := ioutil.ReadAll(rw)
			if err != nil {
				return false, nil, err
			}

			if challenge == nil || len(challenge) == 0 {
				err = ErrInvalidChallenge
				return
			}

			// BUG(ssw): The server side of SCRAM is not yet implemented.
			if state&Receiving == Receiving {
				panic("sasl: Server side of SCRAM not yet implemented")
			}

			switch state & StepMask {
			case AuthTextSent:
				iter := -1
				var salt, nonce []byte
				for _, field := range bytes.Split(challenge, []byte{','}) {
					if len(field) < 3 || (len(field) >= 2 && field[1] != '=') {
						continue
					}
					switch field[0] {
					case 'i':
						ival := string(bytes.TrimRight(field[2:], "\x00"))

						if iter, err = strconv.Atoi(ival); err != nil {
							return
						}
					case 's':
						salt = make([]byte, base64.StdEncoding.DecodedLen(len(field)-2))
						var n int
						n, err = base64.StdEncoding.Decode(salt, field[2:])
						salt = salt[:n]
						if err != nil {
							return
						}
					case 'r':
						nonce = field[2:]
					case 'm':
						// RFC 5802:
						// m: This attribute is reserved for future extensibility.  In this
						// version of SCRAM, its presence in a client or a server message
						// MUST cause authentication failure when the attribute is parsed by
						// the other end.
						err = errors.New("Server sent reserved attribute `m`")
						return
					}
				}

				switch {
				case iter < 0:
					err = errors.New("Iteration count is missing")
					return
				case iter < 0:
					err = errors.New("Iteration count is invalid")
					return
				case nonce == nil || !bytes.HasPrefix(nonce, m.Nonce()):
					err = errors.New("Server nonce does not match client nonce")
					return
				case salt == nil:
					err = errors.New("Server sent empty salt")
					return
				}

				gs2Header := getGS2Header(name, m)
				var channelBinding []byte
				if m.Config().TLSState != nil && strings.HasSuffix(name, "-PLUS") {
					channelBinding = make(
						[]byte,
						2+base64.StdEncoding.EncodedLen(len(gs2Header)+len(m.Config().TLSState.TLSUnique)),
					)
					base64.StdEncoding.Encode(channelBinding[2:], append(gs2Header, m.Config().TLSState.TLSUnique...))
					channelBinding[0] = 'c'
					channelBinding[1] = '='
				} else {
					channelBinding = make(
						[]byte,
						2+base64.StdEncoding.EncodedLen(len(gs2Header)),
					)
					base64.StdEncoding.Encode(channelBinding[2:], gs2Header)
					channelBinding[0] = 'c'
					channelBinding[1] = '='
				}
				clientFinalMessageWithoutProof := append(channelBinding, []byte(",r=")...)
				clientFinalMessageWithoutProof = append(clientFinalMessageWithoutProof, nonce...)

				clientFirstMessage := data.([]byte)
				authMessage := append(clientFirstMessage, ',')
				authMessage = append(authMessage, challenge...)
				authMessage = append(authMessage, ',')
				authMessage = append(authMessage, clientFinalMessageWithoutProof...)

				// TODO(ssw): Have a shared LRU cache for HMAC and hi calculations

				saltedPassword := pbkdf2.Key(c.Password, salt, iter, fn().Size(), fn)

				h := hmac.New(fn, saltedPassword)
				h.Write(serverKeyInput)
				serverKey := h.Sum(nil)
				h.Reset()

				h.Write(clientKeyInput)
				clientKey := h.Sum(nil)

				h = hmac.New(fn, serverKey)
				h.Write(authMessage)
				serverSignature := h.Sum(nil)

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

				_, err = rw.Write(clientFinalMessageWithoutProof)
				if err != nil {
					return false, nil, err
				}
				_, err = rw.Write([]byte(",p="))
				if err != nil {
					return false, nil, err
				}
				_, err = rw.Write(encodedClientProof)
				if err != nil {
					return false, nil, err
				}

				return true, serverSignature, nil
			case ResponseSent:
				clientCalculatedServerFinalMessage := "v=" + base64.StdEncoding.EncodeToString(data.([]byte))
				if clientCalculatedServerFinalMessage != string(challenge) {
					err = ErrAuthn
					return
				}
				// Success!
				return false, nil, nil
			}
			err = ErrInvalidState
			return
		},
	}
}
