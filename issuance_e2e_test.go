// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func buildIssuanceTestBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "mkcert-issuance-test")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", binary, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build mkcert: %v\n%s", err, out)
	}
	return binary
}

func runIssuanceTestCLI(t *testing.T, binary, caroot, workdir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Dir = workdir
	cmd.Env = append(os.Environ(),
		"CAROOT="+caroot,
		"TRUST_STORES=none",
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestE2EConcurrentWildcardIssuance exercises the exact reported path through
// the CLI: concurrent processes ask for the same wildcard files in one
// directory. Whatever process wins, the certificate and key left on disk must
// be a single transaction, and a later issue must not reuse its serial.
func TestE2EConcurrentWildcardIssuance(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-level concurrency test is Unix-only")
	}
	binary := buildIssuanceTestBinary(t)
	caroot := filepath.Join(t.TempDir(), "root")
	work := t.TempDir()

	const n = 10
	var wg sync.WaitGroup
	outputs := make(chan string, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := runIssuanceTestCLI(t, binary, caroot, work, "*.race.example.test")
			outputs <- out
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(outputs)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent issuance failed: %v", err)
	}
	for out := range outputs {
		if !strings.Contains(out, "Created a new certificate valid for the following names") {
			t.Fatalf("unexpected mkcert output: %s", out)
		}
	}

	ca := &mkcert{CAROOT: caroot}
	ca.loadCA()
	certPath := filepath.Join(work, "_wildcard.race.example.test.pem")
	keyPath := filepath.Join(work, "_wildcard.race.example.test-key.pem")
	cert := txTestAssertPair(t, ca, certPath, keyPath)
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "*.race.example.test" {
		t.Fatalf("concurrent wildcard SANs = %v", cert.DNSNames)
	}
	txTestAssertNoTemps(t, work)

	serial := cert.SerialNumber
	if out, err := runIssuanceTestCLI(t, binary, caroot, work, "*.race.example.test"); err != nil {
		t.Fatalf("sequential reissue failed: %v\n%s", err, out)
	}
	next := txTestAssertPair(t, ca, certPath, keyPath)
	if next.SerialNumber.Cmp(serial) == 0 {
		t.Fatal("a later issuance reused the serial from the previous transaction")
	}
}

// TestE2EWriteFailureDoesNotPublishOrReuseTransaction covers the failure half:
// the certificate file from the previous transaction must survive a failed key
// write, and the retry must use a fresh serial with a matching key.
func TestE2EWriteFailureDoesNotPublishOrReuseTransaction(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory-based failure injection is Unix-only")
	}
	binary := buildIssuanceTestBinary(t)
	caroot := filepath.Join(t.TempDir(), "root")
	work := t.TempDir()

	certPath := filepath.Join(work, "cert.pem")
	keyPath := filepath.Join(work, "key.pem")
	args := []string{"-cert-file", "cert.pem", "-key-file", "key.pem", "*.retry.example.test"}

	if out, err := runIssuanceTestCLI(t, binary, caroot, work, args...); err != nil {
		t.Fatalf("initial issuance failed: %v\n%s", err, out)
	}
	oldCert := txTestReadCert(t, certPath)
	oldPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(keyPath, 0700); err != nil {
		t.Fatal(err)
	}
	out, err := runIssuanceTestCLI(t, binary, caroot, work, args...)
	if err == nil {
		t.Fatalf("issuance with a directory at the key path unexpectedly succeeded:\n%s", out)
	}
	if !strings.Contains(out, "failed to save certificate key") {
		t.Fatalf("unexpected write failure message:\n%s", out)
	}
	afterPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterPEM) != string(oldPEM) {
		t.Fatal("a failed key write changed the previous certificate")
	}

	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if out, err := runIssuanceTestCLI(t, binary, caroot, work, args...); err != nil {
		t.Fatalf("retry after key write failure failed: %v\n%s", err, out)
	}
	ca := &mkcert{CAROOT: caroot}
	ca.loadCA()
	retried := txTestAssertPair(t, ca, certPath, keyPath)
	if retried.SerialNumber.Cmp(oldCert.SerialNumber) == 0 {
		t.Fatal("retry reused the serial from the pre-failure certificate")
	}
	txTestAssertNoTemps(t, work)
}

// TestE2EConcurrentDifferentHostsNeverCrossAssign outputs from unrelated hosts
// share both output paths. The final certificate must belong wholly to one
// request and its key must be the matching one.
func TestE2EConcurrentDifferentHostsNeverCrossAssign(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-level concurrency test is Unix-only")
	}
	binary := buildIssuanceTestBinary(t)
	caroot := filepath.Join(t.TempDir(), "root")
	work := t.TempDir()

	hosts := []string{"alpha.cross.example.test", "beta.cross.example.test"}
	var wg sync.WaitGroup
	errs := make(chan error, len(hosts)*4)
	for i := 0; i < len(hosts)*4; i++ {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			out, err := runIssuanceTestCLI(t, binary, caroot, work,
				"-cert-file", "shared.pem", "-key-file", "shared-key.pem", host)
			if err != nil {
				errs <- err
				t.Logf("mkcert %s failed: %v\n%s", host, err, out)
			}
		}(hosts[i%len(hosts)])
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent different-host issuance failed: %v", err)
	}

	ca := &mkcert{CAROOT: caroot}
	ca.loadCA()
	cert := txTestAssertPair(t, ca,
		filepath.Join(work, "shared.pem"),
		filepath.Join(work, "shared-key.pem"))
	if len(cert.DNSNames) != 1 ||
		(cert.DNSNames[0] != hosts[0] && cert.DNSNames[0] != hosts[1]) {
		t.Fatalf("certificate attributed to the shared file has unrelated SANs: %v", cert.DNSNames)
	}
}
