// Copyright 2026 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// secureMkdirAll creates dir with private permissions and refuses to use a
// CAROOT that is a symlink or is controlled by another user. Older CAROOTs are
// kept working with their existing explicit permissions, provided they are not
// writable by group or other.
func secureMkdirAll(dir string) error {
	if dir == "" {
		return errors.New("CAROOT is empty")
	}
	clean := filepath.Clean(dir)
	existed := true

	if fi, err := os.Lstat(clean); err == nil {
		if err := validateCAROOTDir(clean, fi); err != nil {
			return err
		}
	} else if os.IsNotExist(err) {
		existed = false
	} else {
		return err
	}

	if err := os.MkdirAll(clean, 0700); err != nil {
		return err
	}
	fi, err := os.Lstat(clean)
	if err != nil {
		return err
	}
	if err := validateCAROOTDir(clean, fi); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	if !existed {
		return os.Chmod(clean, 0700)
	}
	return nil
}

func validateCAROOTDir(path string, fi os.FileInfo) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("CAROOT %q is a symlink", path)
	}
	if !fi.IsDir() {
		return fmt.Errorf("CAROOT %q is not a directory", path)
	}
	if err := checkOwner(path, fi); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	if perm := fi.Mode().Perm(); perm&0022 != 0 {
		return fmt.Errorf("CAROOT %q has mode %04o with group/other write access", path, perm)
	}
	return nil
}

func checkOwner(path string, fi os.FileInfo) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	uid, ok := fileOwnerID(fi)
	if !ok {
		return nil
	}
	expected := uint32(os.Geteuid())
	if uid != expected {
		return fmt.Errorf("%q is owned by uid %d with mode %04o, expected uid %d", path, uid, fi.Mode().Perm(), expected)
	}
	return nil
}

// validateSensitiveFile applies the shared permission policy for CA files and
// issuance outputs. Private material may not be accessible by group or other;
// certificates may be read-only but must not be writable by group or other.
func validateSensitiveFile(path string, fi os.FileInfo, secret bool) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to use symlink %q", path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", path)
	}
	if err := checkOwner(path, fi); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	perm := fi.Mode().Perm()
	if secret && perm&0077 != 0 {
		return fmt.Errorf("%q has mode %04o; private keys must not be accessible by group or other", path, perm)
	}
	if !secret && perm&0022 != 0 {
		return fmt.Errorf("%q has mode %04o; certificates must not be writable by group or other", path, perm)
	}
	return nil
}

func validateExistingOutput(path string, secret bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return validateSensitiveFile(path, fi, secret)
}

// readFileNoFollow reads a regular file without following a final symlink.
// The validation callback runs before the file contents are read.
// It returns exists == false only when the path itself does not exist. A
// dangling symlink is reported as an error rather than as a missing file.
func readFileNoFollow(path string, validate func(os.FileInfo) error) (data []byte, exists bool, err error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, true, fmt.Errorf("refusing to follow symlink %q", path)
	}
	if !fi.Mode().IsRegular() {
		return nil, true, fmt.Errorf("%q is not a regular file", path)
	}
	if validate != nil {
		if err := validate(fi); err != nil {
			return nil, true, err
		}
	}

	f, err := openNoFollow(path)
	if err != nil {
		return nil, true, err
	}
	defer f.Close()

	ofi, err := f.Stat()
	if err != nil {
		return nil, true, err
	}
	if !ofi.Mode().IsRegular() {
		return nil, true, fmt.Errorf("%q is not a regular file", path)
	}
	if !os.SameFile(fi, ofi) {
		return nil, true, fmt.Errorf("%q changed while it was being opened", path)
	}

	data, err = io.ReadAll(f)
	if err != nil {
		return nil, true, err
	}
	return data, true, nil
}

type atomicWrite struct {
	path       string
	data       []byte
	mode       os.FileMode
	sensitive  bool
	createOnly bool
}

type pendingWrite struct {
	tmp        string
	dst        string
	createOnly bool
}

// prepareAtomicWrite writes data to an unpredictable temporary file in the
// destination directory. The file is private while it is being written, and
// the final mode is set before the rename.
func prepareAtomicWrite(w atomicWrite) (*pendingWrite, error) {
	if err := validateExistingOutput(w.path, w.sensitive); err != nil {
		return nil, err
	}
	dir := filepath.Dir(w.path)
	f, err := os.CreateTemp(dir, ".mkcert-tmp-*")
	if err != nil {
		return nil, err
	}
	tmp := f.Name()
	cleanup := func() {
		f.Close()
		os.Remove(tmp)
	}

	if _, err := f.Write(w.data); err != nil {
		cleanup()
		return nil, err
	}
	if err := f.Chmod(w.mode); err != nil {
		cleanup()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	return &pendingWrite{tmp: tmp, dst: w.path, createOnly: w.createOnly}, nil
}

func (p *pendingWrite) commit() error {
	if p.createOnly {
		// link(2) publishes the fully-written inode without replacing an
		// existing CA generation.
		if err := os.Link(p.tmp, p.dst); err != nil {
			if _, statErr := os.Lstat(p.dst); statErr == nil {
				return fmt.Errorf("%q already exists", p.dst)
			} else if !os.IsNotExist(statErr) {
				return statErr
			}
			// Some filesystems do not support hard links. Fall back to a
			// checked rename, which is still safe for the no-replace case.
			if err := os.Rename(p.tmp, p.dst); err != nil {
				return err
			}
			p.tmp = ""
			return nil
		}
		os.Remove(p.tmp)
		p.tmp = ""
		return nil
	}
	if err := os.Rename(p.tmp, p.dst); err != nil {
		return err
	}
	p.tmp = ""
	return nil
}

func (p *pendingWrite) abort() {
	if p.tmp != "" {
		os.Remove(p.tmp)
	}
}

// writeAllAtomic prepares every output before committing any of them. A
// failure while creating or validating one destination therefore does not
// publish a partial set from the others.
func writeAllAtomic(writes []atomicWrite) error {
	pending := make([]*pendingWrite, 0, len(writes))
	defer func() {
		for _, p := range pending {
			p.abort()
		}
	}()

	for _, w := range writes {
		p, err := prepareAtomicWrite(w)
		if err != nil {
			return err
		}
		pending = append(pending, p)
	}
	committed := make([]*pendingWrite, 0, len(pending))
	for _, p := range pending {
		if err := p.commit(); err != nil {
			for _, done := range committed {
				if done.createOnly {
					os.Remove(done.dst)
				}
			}
			return err
		}
		committed = append(committed, p)
	}
	return nil
}

// pathIdentity returns a stable identity for a destination path. The final
// path component is deliberately not resolved: replacing a symlink is safe,
// while following one is not.
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
	return filepath.Join(dir, base)
}

func samePath(a, b string) bool {
	ia, ib := pathIdentity(a), pathIdentity(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(ia, ib)
	}
	return ia == ib
}
