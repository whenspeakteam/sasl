// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file was borrowed from Go's crypto/cipher package.

package sasl

// Export internal functions for testing.
var XorBytes = xorBytes
