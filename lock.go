// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
)

// fileLock is an advisory process lock. The lock is released by the kernel
// when the process exits, so a crash never leaves a stale lock behind.
type fileLock struct {
	file *os.File
}

func (l *fileLock) unlock() {
	if l == nil || l.file == nil {
		return
	}
	unlockFile(l.file)
	l.file.Close()
	l.file = nil
}

type fileLockSet struct {
	locks []*fileLock
}

func (s *fileLockSet) unlock() {
	if s == nil {
		return
	}
	for i := len(s.locks) - 1; i >= 0; i-- {
		s.locks[i].unlock()
	}
	s.locks = nil
}

func lockFilePath(scope string) string {
	sum := sha256.Sum256([]byte(scope))
	return filepath.Join(os.TempDir(), "mkcert-lock-"+hex.EncodeToString(sum[:16]))
}

func lockScope(scope string) (*fileLock, error) {
	f, err := os.OpenFile(lockFilePath(scope), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, err
	}
	return &fileLock{file: f}, nil
}

// lockCAROOT serializes CA loading/creation and issuance for one CAROOT. This
// keeps a fresh CA, its on-disk files and the leaf certificates issued from it
// in one observable order across concurrent mkcert processes.
func lockCAROOT(dir string) (*fileLock, error) {
	return lockScope("caroot:" + pathIdentity(dir))
}

// lockOutputs takes one lock per distinct output path, in a stable order to
// avoid deadlocks. Two transactions that share any output file therefore
// serialize, even if they were configured with different key paths.
func lockOutputs(paths []string) (*fileLockSet, error) {
	unique := make(map[string]bool, len(paths))
	identities := make([]string, 0, len(paths))
	for _, path := range paths {
		identity := pathIdentity(path)
		if unique[identity] {
			continue
		}
		unique[identity] = true
		identities = append(identities, identity)
	}
	sort.Strings(identities)

	set := &fileLockSet{}
	for _, identity := range identities {
		lock, err := lockScope("output:" + identity)
		if err != nil {
			set.unlock()
			return nil, err
		}
		set.locks = append(set.locks, lock)
	}
	return set, nil
}
