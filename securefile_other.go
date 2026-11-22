// Copyright 2026 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris
// +build !aix,!darwin,!dragonfly,!freebsd,!linux,!netbsd,!openbsd,!solaris

package main

import "os"

// Platforms without O_NOFOLLOW still get the Lstat checks in
// readFileNoFollow. This fallback keeps the package buildable everywhere.
func openNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}

func fileOwnerID(fi os.FileInfo) (uint32, bool) {
	return 0, false
}
