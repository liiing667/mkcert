// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
)

// lockName is the name of the lock file used to serialize CA creation,
// recovery and trust store installation within a CAROOT.
const lockName = "rootCA.lock"

// caLock is an exclusive, process-held lock on a CAROOT. It is released
// when unlock is called or the process exits, so a crash never leaves a
// stale lock behind.
type caLock struct {
	file *os.File
}

// lockCAROOT acquires an exclusive lock on the CAROOT. Concurrent
// invocations block until the lock is available, which makes CA creation,
// recovery and installation a single transaction instead of a race between
// independent processes.
func lockCAROOT(dir string) (*caLock, error) {
	f, err := os.OpenFile(filepath.Join(dir, lockName), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		// A read-only CAROOT can still hold a valid CA that is only used
		// to sign certificates. In that case fall back to locking the
		// directory itself, where the platform supports it.
		if d, derr := os.Open(dir); derr == nil {
			if lerr := lockFile(d); lerr == nil {
				return &caLock{file: d}, nil
			}
			d.Close()
		}
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, err
	}
	return &caLock{file: f}, nil
}

func (l *caLock) unlock() {
	if l == nil || l.file == nil {
		return
	}
	unlockFile(l.file)
	l.file.Close()
	l.file = nil
}
