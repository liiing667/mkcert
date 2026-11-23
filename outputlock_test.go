// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOutputLockSerializesGenerationsInOneProcess(t *testing.T) {
	caroot := t.TempDir()
	acquired := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})

	first, err := lockOutputs(caroot)
	if err != nil {
		t.Fatal(err)
	}
	defer first.unlock()

	go func() {
		second, err := lockOutputs(caroot)
		if err != nil {
			t.Error(err)
			close(done)
			return
		}
		close(acquired)
		<-release
		second.unlock()
		close(done)
	}()

	select {
	case <-acquired:
		t.Fatal("the output lock did not serialize concurrent generations")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	<-done

	if _, err := os.Stat(filepath.Join(caroot, outputLockName)); err != nil {
		t.Fatalf("kernel lock file was not retained for cross-process use: %v", err)
	}
}
