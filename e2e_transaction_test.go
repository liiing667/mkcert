// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// txBuildMkcert compiles the current source so the end-to-end tests exercise
// the real CLI, including CAROOT locking across processes.
func txBuildMkcert(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "mkcert")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build mkcert for e2e tests: %v\n%s", err, out)
	}
	return binary
}

func txRunMkcert(t *testing.T, binary, caroot, workdir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Dir = workdir
	cmd.Env = append(os.Environ(),
		"CAROOT="+caroot,
		"TRUST_STORES=none", // never touch the host's real trust stores
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func txHashFile(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("hash %q: %v", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func txAssertPairOnDisk(t *testing.T, caroot string) {
	t.Helper()
	cert := txTestReadCert(t, filepath.Join(caroot, rootName))
	key := loadCAKey(filepath.Join(caroot, rootKeyName))
	if !keyMatchesCertificate(key, cert) {
		t.Fatalf("CA key and certificate in %q do not match", caroot)
	}
}

// TestE2EConcurrentInstallations is the headline acceptance test: many mkcert
// processes create and install the CA at the same CAROOT at the same time.
// They must serialize on the lock, leave exactly one matching key/certificate
// pair, and never overwrite each other's CA.
func TestE2EConcurrentInstallations(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-level concurrency test is Unix-only")
	}
	binary := txBuildMkcert(t)
	caroot := filepath.Join(t.TempDir(), "root")

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	outputs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			workdir := t.TempDir()
			out, err := txRunMkcert(t, binary, caroot, workdir,
				"-install", "host"+strconv.Itoa(i)+".example")
			outputs <- out
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	close(outputs)

	for err := range errs {
		t.Fatalf("a concurrent mkcert invocation failed: %v", err)
	}
	for out := range outputs {
		if !strings.Contains(out, "Created a new certificate valid for the following names") {
			t.Fatalf("unexpected mkcert output: %s", out)
		}
	}

	entries, err := ioutil.ReadDir(caroot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != rootName && name != rootKeyName && name != lockName {
			t.Fatalf("unexpected file in CAROOT: %q", name)
		}
		if strings.HasPrefix(name, caTempPrefix) {
			t.Fatalf("leftover temporary file in CAROOT: %q", name)
		}
	}
	txAssertPairOnDisk(t, caroot)

	// A later, sequential invocation must reuse the CA unchanged.
	certHashBefore := txHashFile(t, filepath.Join(caroot, rootName))
	keyHashBefore := txHashFile(t, filepath.Join(caroot, rootKeyName))
	if out, err := txRunMkcert(t, binary, caroot, t.TempDir(), "later.example"); err != nil {
		t.Fatalf("sequential reuse failed: %v\n%s", err, out)
	}
	if txHashFile(t, filepath.Join(caroot, rootName)) != certHashBefore ||
		txHashFile(t, filepath.Join(caroot, rootKeyName)) != keyHashBefore {
		t.Fatal("the existing CA was overwritten on a later invocation")
	}
	txAssertPairOnDisk(t, caroot)
}

// TestE2EInterruptedCreationRecovery simulates the exact reported bug: the
// key is present after a failed first run but the certificate is missing. The
// retry must recover the same key into a matching certificate rather than
// generating a fresh key, and the resulting CA must be fully usable.
func TestE2EInterruptedCreationRecovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-level interruption test is Unix-only")
	}
	binary := txBuildMkcert(t)
	caroot := filepath.Join(t.TempDir(), "root")

	m := &mkcert{CAROOT: caroot}
	priv, err := m.generateKey(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(caroot, 0755); err != nil {
		t.Fatal(err)
	}
	m.writeRootKey(priv)
	orphanedKeyHash := txHashFile(t, filepath.Join(caroot, rootKeyName))

	out, err := txRunMkcert(t, binary, caroot, t.TempDir(), "recovered.example")
	if err != nil {
		t.Fatalf("recovery run failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "recovering it into a new CA certificate") {
		t.Fatalf("recovery message missing from output: %s", out)
	}
	if txHashFile(t, filepath.Join(caroot, rootKeyName)) != orphanedKeyHash {
		t.Fatal("the orphaned CA key was replaced instead of recovered")
	}
	txAssertPairOnDisk(t, caroot)

	workdir := t.TempDir()
	if out, err := txRunMkcert(t, binary, caroot, workdir, "leaf.example"); err != nil {
		t.Fatalf("certificate issuance after recovery failed: %v\n%s", err, out)
	}
	leaf := txTestReadCert(t, filepath.Join(workdir, "leaf.example.pem"))
	root := txTestReadCert(t, filepath.Join(caroot, rootName))
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		DNSName:     "leaf.example",
		CurrentTime: leaf.NotBefore,
	}); err != nil {
		t.Fatalf("recovered CA does not verify the leaf it issued: %v", err)
	}
}

// TestE2ELegacyCAIsNeverOverwritten proves that a CA created by an older
// mkcert version keeps working and is not regenerated or overwritten,
// including under concurrent installs.
func TestE2ELegacyCAIsNeverOverwritten(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-level concurrency test is Unix-only")
	}
	binary := txBuildMkcert(t)
	caroot := filepath.Join(t.TempDir(), "root")

	if out, err := txRunMkcert(t, binary, caroot, t.TempDir(), "first.example"); err != nil {
		t.Fatalf("initial run failed: %v\n%s", err, out)
	}
	certHash := txHashFile(t, filepath.Join(caroot, rootName))
	keyHash := txHashFile(t, filepath.Join(caroot, rootKeyName))

	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out, err := txRunMkcert(t, binary, caroot, t.TempDir(),
				"-install", "parallel"+strconv.Itoa(i)+".example")
			if err != nil {
				t.Errorf("concurrent run against the legacy CA failed: %v\n%s", err, out)
			}
		}(i)
	}
	wg.Wait()

	if txHashFile(t, filepath.Join(caroot, rootName)) != certHash ||
		txHashFile(t, filepath.Join(caroot, rootKeyName)) != keyHash {
		t.Fatal("the pre-existing legacy CA was overwritten")
	}
	txAssertPairOnDisk(t, caroot)
}

// TestE2EMismatchedPairIsRefused makes sure a key/certificate pair that got
// mixed up by an older version is rejected without modifying either file.
func TestE2EMismatchedPairIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-level test is Unix-only")
	}
	binary := txBuildMkcert(t)
	caroot := filepath.Join(t.TempDir(), "root")
	if out, err := txRunMkcert(t, binary, caroot, t.TempDir(), "x.example"); err != nil {
		t.Fatalf("initial run failed: %v\n%s", err, out)
	}

	other, err := (&mkcert{CAROOT: caroot}).generateKey(true)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKCS8PrivateKey(other)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(caroot, rootKeyName)
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(keyPath, pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER}), 0400); err != nil {
		t.Fatal(err)
	}

	certHash := txHashFile(t, filepath.Join(caroot, rootName))
	keyHash := txHashFile(t, keyPath)
	out, err := txRunMkcert(t, binary, caroot, t.TempDir(), "y.example")
	if err == nil {
		t.Fatalf("mismatched CA was accepted:\n%s", out)
	}
	if !strings.Contains(out, "do not match") {
		t.Fatalf("mismatch error missing from output: %s", out)
	}
	if txHashFile(t, filepath.Join(caroot, rootName)) != certHash ||
		txHashFile(t, keyPath) != keyHash {
		t.Fatal("rejecting a mismatched pair modified the CA files")
	}
}

// TestE2EExplicitCAROOTAndECDSA covers the explicit CAROOT env var and ECDSA
// CAs with custom leaf output names.
func TestE2EExplicitCAROOTAndECDSA(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-level test is Unix-only")
	}
	binary := txBuildMkcert(t)
	caroot := filepath.Join(t.TempDir(), "explicit-root")
	workdir := t.TempDir()

	out, err := txRunMkcert(t, binary, caroot, workdir,
		"-ecdsa",
		"-cert-file", filepath.Join(workdir, "custom.crt"),
		"-key-file", filepath.Join(workdir, "custom.key"),
		"ecdsa.example")
	if err != nil {
		t.Fatalf("ECDSA run failed: %v\n%s", err, out)
	}
	txAssertPairOnDisk(t, caroot)
	if !pathExists(filepath.Join(workdir, "custom.crt")) ||
		!pathExists(filepath.Join(workdir, "custom.key")) {
		t.Fatal("custom leaf output paths were not honored")
	}
}

// TestE2EReadOnlyLegacyCAROOT keeps a valid old CA usable when its CAROOT is
// read-only. Such a CAROOT has no lock file yet, so the directory itself is
// used for serialization.
func TestE2EReadOnlyLegacyCAROOT(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions test is Unix-only")
	}
	binary := txBuildMkcert(t)
	caroot := filepath.Join(t.TempDir(), "root")
	if out, err := txRunMkcert(t, binary, caroot, t.TempDir(), "first.example"); err != nil {
		t.Fatalf("initial run failed: %v\n%s", err, out)
	}
	// Simulate a CA created by an older mkcert version, before the lock
	// file existed.
	if err := os.Remove(filepath.Join(caroot, lockName)); err != nil {
		t.Fatal(err)
	}
	certHash := txHashFile(t, filepath.Join(caroot, rootName))
	keyHash := txHashFile(t, filepath.Join(caroot, rootKeyName))

	if err := os.Chmod(caroot, 0555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(caroot, 0755)

	workdir := t.TempDir()
	if out, err := txRunMkcert(t, binary, caroot, workdir, "readonly.example"); err != nil {
		t.Fatalf("read-only legacy CAROOT failed: %v\n%s", err, out)
	}
	if !pathExists(filepath.Join(workdir, "readonly.example.pem")) {
		t.Fatal("leaf certificate was not issued")
	}
	if txHashFile(t, filepath.Join(caroot, rootName)) != certHash ||
		txHashFile(t, filepath.Join(caroot, rootKeyName)) != keyHash {
		t.Fatal("the read-only legacy CA was modified")
	}
	txAssertPairOnDisk(t, caroot)
}
