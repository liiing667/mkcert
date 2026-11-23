// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// atomicWrite describes one file that is part of a certificate transaction.
type atomicWrite struct {
	path string
	data []byte
	perm os.FileMode
}

// outputWriteError records which output path made a transaction fail. The
// caller can use it to keep the user-facing error specific (certificate, key,
// or PKCS#12), while the write itself is still applied as one transaction.
type outputWriteError struct {
	path string
	err  error
}

func (e *outputWriteError) Error() string {
	return fmt.Sprintf("%s: %v", e.path, e.err)
}

func (e *outputWriteError) Unwrap() error {
	return e.err
}

type stagedWrite struct {
	target    string
	tmp       string
	backup    string
	hadOld    bool
	installed bool
}

func (s *stagedWrite) cleanup() {
	if s.tmp != "" {
		os.Remove(s.tmp)
		s.tmp = ""
	}
	if s.backup != "" {
		os.Remove(s.backup)
		s.backup = ""
	}
}

func validateOutputFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace symlink")
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("existing path is not a regular file")
	}
	// Match the old WriteFile behavior: replacing a file still requires write
	// permission on that file, even though the transaction commits with rename.
	// This keeps read-only outputs read-only and makes key-write failures occur
	// before any certificate is published.
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return nil
}

func prepareAtomicWrite(w atomicWrite) (*stagedWrite, error) {
	if err := validateOutputFile(w.path); err != nil {
		return nil, &outputWriteError{path: w.path, err: err}
	}

	dir := filepath.Dir(w.path)
	prefix := "." + filepath.Base(w.path) + ".tmp-"
	f, err := ioutil.TempFile(dir, prefix+"*")
	if err != nil {
		return nil, &outputWriteError{path: w.path, err: err}
	}
	tmp := f.Name()
	cleanup := func() {
		f.Close()
		os.Remove(tmp)
	}

	if _, err := f.Write(w.data); err != nil {
		cleanup()
		return nil, &outputWriteError{path: w.path, err: err}
	}
	if err := f.Chmod(w.perm); err != nil {
		cleanup()
		return nil, &outputWriteError{path: w.path, err: err}
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return nil, &outputWriteError{path: w.path, err: err}
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return nil, &outputWriteError{path: w.path, err: err}
	}
	return &stagedWrite{target: w.path, tmp: tmp}, nil
}

func (s *stagedWrite) makeBackup() error {
	fi, err := os.Lstat(s.target)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return fmt.Errorf("existing path is not a regular file")
	}

	backup := s.tmp + ".old"
	// A hard link keeps the old inode available without making the output
	// disappear before the new file is installed. Fall back to a copy on
	// filesystems that do not support hard links.
	if err := os.Link(s.target, backup); err != nil {
		data, readErr := ioutil.ReadFile(s.target)
		if readErr != nil {
			return readErr
		}
		if writeErr := ioutil.WriteFile(backup, data, fi.Mode().Perm()); writeErr != nil {
			return writeErr
		}
	}
	s.backup = backup
	s.hadOld = true
	return nil
}

func (s *stagedWrite) restore() error {
	if s.installed {
		if s.hadOld {
			err := os.Rename(s.backup, s.target)
			if err != nil && runtime.GOOS == "windows" {
				if removeErr := os.Remove(s.target); removeErr == nil || os.IsNotExist(removeErr) {
					err = os.Rename(s.backup, s.target)
				}
			}
			if err != nil {
				return err
			}
			s.backup = ""
		} else {
			if err := os.Remove(s.target); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		s.installed = false
	}
	return nil
}

// writeFilesAtomic prepares every output before committing any of them. If a
// key cannot be written, for example, the certificate from the same
// transaction is never published and any previous pair is left untouched.
func writeFilesAtomic(writes []atomicWrite) error {
	if len(writes) == 0 {
		return nil
	}

	staged := make([]*stagedWrite, 0, len(writes))
	defer func() {
		for _, s := range staged {
			s.cleanup()
		}
	}()

	for _, w := range writes {
		s, err := prepareAtomicWrite(w)
		if err != nil {
			return err
		}
		staged = append(staged, s)
	}

	for _, s := range staged {
		if err := s.makeBackup(); err != nil {
			return &outputWriteError{path: s.target, err: err}
		}
	}

	for _, s := range staged {
		err := os.Rename(s.tmp, s.target)
		if err != nil && runtime.GOOS == "windows" {
			// os.Rename does not replace an existing destination on Windows.
			// The old contents are already preserved in s.backup, so removing
			// the destination keeps this commit recoverable.
			if removeErr := os.Remove(s.target); removeErr == nil || os.IsNotExist(removeErr) {
				err = os.Rename(s.tmp, s.target)
			}
		}
		if err != nil {
			writeErr := &outputWriteError{path: s.target, err: err}
			for i := len(staged) - 1; i >= 0; i-- {
				if restoreErr := staged[i].restore(); restoreErr != nil {
					return fmt.Errorf("%v (failed to restore %s: %v)", writeErr, staged[i].target, restoreErr)
				}
			}
			return writeErr
		}
		s.tmp = ""
		s.installed = true
	}

	for _, s := range staged {
		if s.backup != "" {
			os.Remove(s.backup)
			s.backup = ""
		}
	}
	return nil
}

// pathIdentity returns the canonical identity of a path for lock and equality
// purposes. The final component is intentionally not resolved, so two spellings
// of the same directory still map to the same output file.
func pathIdentity(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = filepath.Clean(path)
	}
	dir, base := filepath.Split(abs)
	if dir == "" {
		dir = "."
	}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	path = filepath.Join(dir, base)
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
	}
	return path
}

func samePath(a, b string) bool {
	return pathIdentity(a) == pathIdentity(b)
}
