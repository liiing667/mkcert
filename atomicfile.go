// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

// caTempPrefix is the common prefix of the temporary files used while
// committing the CA key and certificate. Files with this prefix can be
// removed safely on the next CA creation or recovery, after a crash left
// them behind.
const caTempPrefix = ".rootCA.tmp."

// atomicWriteFile writes data to path in a single atomic step: the data
// first lands in a temporary file in the same directory and is then
// renamed into place. A crash can therefore leave either the previous
// contents or the new ones, never a partially written file, and a reader
// never observes a half-written CA key or certificate.
//
// The temporary file is created in the same directory as the destination
// so the rename stays on one filesystem.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := ioutil.TempFile(dir, caTempPrefix+"*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	// Flush the contents before the rename so a crash after the rename
	// can't expose an empty file.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	committed = true

	// Make the rename itself durable where the platform supports syncing
	// a directory. This is best effort: some filesystems and Windows
	// reject opening or syncing a directory, and the files are still
	// atomically replaced without it.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
