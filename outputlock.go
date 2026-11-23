// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"sync"
)

const outputLockName = "certificate-output.lock"

var (
	outputLockMu sync.Mutex
	outputLocks  = make(map[string]*outputLock)
)

type outputLock struct {
	file  *os.File
	users int
}

// lockOutputs serializes certificate generations in this CAROOT. A
// process-local mutex protects Go callers, while a kernel lock serializes
// separate mkcert processes. The lock is held across key generation, leaf
// signing, PEM/P12 encoding, validation and atomic commit, so output writes
// and retries cannot interleave between generations.
func lockOutputs(caroot string) (*outputLockHandle, error) {
	lockPath := filepath.Join(caroot, outputLockName)

	outputLockMu.Lock()
	defer outputLockMu.Unlock()

	lock := outputLocks[lockPath]
	if lock == nil {
		f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			return nil, err
		}
		if err := lockFile(f); err != nil {
			f.Close()
			return nil, err
		}
		lock = &outputLock{file: f}
		outputLocks[lockPath] = lock
	}
	lock.users++
	return &outputLockHandle{path: lockPath}, nil
}

type outputLockHandle struct {
	path string
}

func (h *outputLockHandle) unlock() {
	if h == nil {
		return
	}

	outputLockMu.Lock()
	defer outputLockMu.Unlock()

	lock := outputLocks[h.path]
	if lock == nil {
		return
	}
	lock.users--
	if lock.users > 0 {
		return
	}

	unlockFile(lock.file)
	lock.file.Close()
	delete(outputLocks, h.path)
	h.path = ""
}
