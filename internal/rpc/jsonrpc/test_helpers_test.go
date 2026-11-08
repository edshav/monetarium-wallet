// Copyright (c) 2026 The Monetarium developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package jsonrpc

import "github.com/monetarium/monetarium-wallet/errors"

// unexpectedCall is the error a test network backend returns for a method
// the test does not expect.
func unexpectedCall(method string) error {
	return errors.New("test network backend: unexpected call to " + method)
}
