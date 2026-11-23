// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

// atomicOutputFile is a pending replacement for one certificate artifact.
// All temporary files are fully written and validated before any destination
// is renamed, which is the commit point of the issuance transaction.
type atomicOutputFile struct {
	path string
	data []byte
	perm os.FileMode

	tempName  string
	committed bool
}

func writeAtomicFile(file *atomicOutputFile) error {
	dir := filepath.Dir(file.path)
	tmp, err := ioutil.TempFile(dir, "."+filepath.Base(file.path)+".tmp-*")
	if err != nil {
		return err
	}
	file.tempName = tmp.Name()

	if _, err = tmp.Write(file.data); err != nil {
		tmp.Close()
		os.Remove(file.tempName)
		return err
	}
	if err = tmp.Chmod(file.perm); err != nil {
		tmp.Close()
		os.Remove(file.tempName)
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(file.tempName)
		return err
	}
	if err = tmp.Close(); err != nil {
		os.Remove(file.tempName)
		return err
	}
	return nil
}

func (file *atomicOutputFile) commit() error {
	if file.committed {
		return nil
	}
	if file.tempName == "" {
		return os.ErrNotExist
	}
	if err := os.Rename(file.tempName, file.path); err != nil {
		return err
	}
	file.tempName = ""
	file.committed = true
	return syncDir(filepath.Dir(file.path))
}

// rollback removes a newly committed destination if another output in the
// same transaction fails to publish. A retained earlier generation is only
// possible when an unrelated platform error makes the replacement rename
// fail, in which case no destination was changed.
func (file *atomicOutputFile) rollback() {
	if file == nil || !file.committed {
		return
	}
	if err := os.Remove(file.path); err == nil {
		file.committed = false
	}
}

func (file *atomicOutputFile) cleanup() {
	if file == nil {
		return
	}
	if !file.committed && file.tempName != "" {
		os.Remove(file.tempName)
		file.tempName = ""
	}
}
