// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows
// +build windows

package main

// Directory fsync is not available on Windows; MoveFileEx-style renames still
// provide the atomic replacement needed by the certificate transaction.
func syncDir(dir string) error {
	return nil
}
