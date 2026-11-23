// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func txTestMkcert(t *testing.T, ecdsa bool) (*mkcert, string) {
	t.Helper()
	dir := t.TempDir()
	return &mkcert{CAROOT: dir, ecdsa: ecdsa}, dir
}

func txTestReadCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read certificate %q: %v", path, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("certificate %q is not a PEM CERTIFICATE", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate %q: %v", path, err)
	}
	return cert
}

func txTestReadCA(t *testing.T, dir string) (*x509.Certificate, interface{}) {
	t.Helper()
	cert := txTestReadCert(t, filepath.Join(dir, rootName))
	return cert, loadCAKey(filepath.Join(dir, rootKeyName))
}

func txTestAssertPair(t *testing.T, dir string) {
	t.Helper()
	cert, key := txTestReadCA(t, dir)
	if !keyMatchesCertificate(key, cert) {
		t.Fatalf("CA key and certificate in %q do not match", dir)
	}
}

func txTestAssertNoTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if len(entry.Name()) >= len(caTempPrefix) && entry.Name()[:len(caTempPrefix)] == caTempPrefix {
			t.Fatalf("found leftover temporary file %q", entry.Name())
		}
	}
}

// TestTransactionCreatesMatchingPair checks the happy path for both RSA and
// ECDSA: an empty CAROOT gets a matching, atomically committed key/cert pair.
func TestTransactionCreatesMatchingPair(t *testing.T) {
	for _, useECDSA := range []bool{false, true} {
		name := "RSA"
		if useECDSA {
			name = "ECDSA"
		}
		t.Run(name, func(t *testing.T) {
			m, dir := txTestMkcert(t, useECDSA)
			m.loadCA()

			if m.caCert == nil || m.caKey == nil {
				t.Fatal("loadCA did not populate the in-memory CA")
			}
			if !m.caCert.IsCA {
				t.Fatal("the generated CA certificate is not marked as a CA")
			}
			if useECDSA {
				if _, ok := m.caKey.(*ecdsa.PrivateKey); !ok {
					t.Fatalf("expected an ECDSA key, got %T", m.caKey)
				}
			} else {
				rsaKey, ok := m.caKey.(*rsa.PrivateKey)
				if !ok || rsaKey.N.BitLen() != 3072 {
					t.Fatalf("expected a 3072-bit RSA key, got %T", m.caKey)
				}
			}

			txTestAssertPair(t, dir)
			txTestAssertNoTemps(t, dir)

			info, err := os.Stat(filepath.Join(dir, rootKeyName))
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != 0400 {
				t.Fatalf("CA key permissions = %o, want 0400", perm)
			}
		})
	}
}

// TestTransactionPreservesLegacyCA makes sure a pre-existing, valid CA is
// loaded verbatim and never regenerated or rewritten.
func TestTransactionPreservesLegacyCA(t *testing.T) {
	m, dir := txTestMkcert(t, false)
	m.loadCA()

	certPath := filepath.Join(dir, rootName)
	keyPath := filepath.Join(dir, rootKeyName)
	certBefore, err := ioutil.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyBefore, err := ioutil.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	m2 := &mkcert{CAROOT: dir}
	m2.loadCA()

	certAfter, err := ioutil.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyAfter, err := ioutil.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(certBefore) != string(certAfter) || string(keyBefore) != string(keyAfter) {
		t.Fatal("reloading the CA rewrote the existing CA files")
	}
	certInfo2, err := os.Stat(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyInfo2, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !certInfo.ModTime().Equal(certInfo2.ModTime()) || !keyInfo.ModTime().Equal(keyInfo2.ModTime()) {
		t.Fatal("reloading the CA touched the existing CA files")
	}
	if !m2.caCert.Equal(m.caCert) {
		t.Fatal("the existing CA certificate was replaced")
	}
	txTestAssertPair(t, dir)
}

// TestTransactionKeylessMode keeps the historical behavior: a certificate
// without a key is accepted for -install and never triggers key generation.
func TestTransactionKeylessMode(t *testing.T) {
	m, dir := txTestMkcert(t, false)
	m.loadCA()
	if err := os.Remove(filepath.Join(dir, rootKeyName)); err != nil {
		t.Fatal(err)
	}

	m2 := &mkcert{CAROOT: dir}
	m2.loadCA()
	if m2.caCert == nil {
		t.Fatal("keyless CA certificate was not loaded")
	}
	if m2.caKey != nil {
		t.Fatal("a key was generated in keyless mode")
	}
	if _, err := os.Stat(filepath.Join(dir, rootKeyName)); !os.IsNotExist(err) {
		t.Fatalf("keyless mode created a key file, stat err = %v", err)
	}
}

// TestTransactionRecoversOrphanedKey reproduces the reported interruption:
// the key was written but the process died before the certificate. The retry
// must recover the orphaned key instead of generating a new one, so a new
// key can never end up next to an old certificate.
func TestTransactionRecoversOrphanedKey(t *testing.T) {
	for _, useECDSA := range []bool{false, true} {
		name := "RSA"
		if useECDSA {
			name = "ECDSA"
		}
		t.Run(name, func(t *testing.T) {
			m, dir := txTestMkcert(t, useECDSA)
			priv, err := m.generateKey(true)
			if err != nil {
				t.Fatal(err)
			}
			m.writeRootKey(priv)
			if _, err := os.Stat(filepath.Join(dir, rootName)); !os.IsNotExist(err) {
				t.Fatalf("test setup wrong: certificate already exists, err = %v", err)
			}

			keyBefore, err := ioutil.ReadFile(filepath.Join(dir, rootKeyName))
			if err != nil {
				t.Fatal(err)
			}

			m2 := &mkcert{CAROOT: dir, ecdsa: useECDSA}
			m2.loadCA()

			if !pathExists(filepath.Join(dir, rootName)) {
				t.Fatal("recovery did not write the CA certificate")
			}
			keyAfter, err := ioutil.ReadFile(filepath.Join(dir, rootKeyName))
			if err != nil {
				t.Fatal(err)
			}
			if string(keyBefore) != string(keyAfter) {
				t.Fatal("the orphaned key was replaced by a newly generated key")
			}
			txTestAssertPair(t, dir)
			if m2.caKey == nil || m2.caCert == nil {
				t.Fatal("recovered CA was not loaded into memory")
			}
			txTestAssertNoTemps(t, dir)
		})
	}
}

// TestTransactionRecoversLegacyKeyEncodings makes sure an orphaned key that
// uses the traditional RSA or EC PEM encoding is recovered as well, instead
// of being rejected or rotated.
func TestTransactionRecoversLegacyKeyEncodings(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		pem  []byte
	}{
		{
			name: "PKCS1-RSA",
			pem:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}),
		},
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, struct {
		name string
		pem  []byte
	}{
		name: "SEC1-EC",
		pem:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}),
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := ioutil.WriteFile(filepath.Join(dir, rootKeyName), tt.pem, 0400); err != nil {
				t.Fatal(err)
			}
			m := &mkcert{CAROOT: dir}
			m.loadCA()
			if m.caKey == nil || m.caCert == nil {
				t.Fatal("legacy key was not recovered")
			}
			if !keyMatchesCertificate(m.caKey, m.caCert) {
				t.Fatal("recovered legacy key does not match the new certificate")
			}
			got, err := ioutil.ReadFile(filepath.Join(dir, rootKeyName))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(tt.pem) {
				t.Fatal("legacy key file was rewritten")
			}
			txTestAssertPair(t, dir)
		})
	}
}

// TestTransactionKeyMatchRejectsMismatch verifies that an unrelated key is
// detected and never considered a usable pair.
func TestTransactionKeyMatchRejectsMismatch(t *testing.T) {
	m, dir := txTestMkcert(t, false)
	m.loadCA()
	cert, key := txTestReadCA(t, dir)
	if !keyMatchesCertificate(key, cert) {
		t.Fatal("the freshly generated pair should match")
	}

	otherRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherECDSA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if keyMatchesCertificate(otherRSA, cert) {
		t.Fatal("an unrelated RSA key matched the certificate")
	}
	if keyMatchesCertificate(otherECDSA, cert) {
		t.Fatal("an unrelated ECDSA key matched the certificate")
	}
}

// TestTransactionAtomicWriteReplacesContents checks the atomic commit
// primitive itself, including replacing an existing read-only file.
func TestTransactionAtomicWriteReplacesContents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := atomicWriteFile(path, []byte("old"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(path, []byte("new"), 0644); err != nil {
		t.Fatalf("replacing an existing file failed: %v", err)
	}
	got, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("contents = %q, want %q", got, "new")
	}
	txTestAssertNoTemps(t, dir)
}

// TestTransactionCleanupTempFiles verifies crash leftovers are swept without
// touching unrelated user files.
func TestTransactionCleanupTempFiles(t *testing.T) {
	m, dir := txTestMkcert(t, false)
	stale := filepath.Join(dir, caTempPrefix+"stale123")
	userFile := filepath.Join(dir, "keep-me.pem")
	if err := ioutil.WriteFile(stale, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(userFile, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	m.cleanupCATempFiles()
	if pathExists(stale) {
		t.Fatal("stale temporary file was not removed")
	}
	if !pathExists(userFile) {
		t.Fatal("an unrelated user file was removed")
	}
}

// TestTransactionLockSerializesAccess proves the CAROOT lock is exclusive and
// blocking: a second lock attempt has to wait for the first one.
func TestTransactionLockSerializesAccess(t *testing.T) {
	dir := t.TempDir()
	first, err := lockCAROOT(dir)
	if err != nil {
		t.Fatalf("first lock failed: %v", err)
	}

	acquired := make(chan struct{})
	go func() {
		second, err := lockCAROOT(dir)
		if err != nil {
			t.Errorf("second lock failed: %v", err)
			return
		}
		close(acquired)
		second.unlock()
	}()

	select {
	case <-acquired:
		t.Fatal("the second lock was acquired while the first was still held")
	case <-time.After(200 * time.Millisecond):
	}

	first.unlock()
	select {
	case <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("the second lock was not granted after release")
	}

	again, err := lockCAROOT(dir)
	if err != nil {
		t.Fatalf("re-acquiring the released lock failed: %v", err)
	}
	again.unlock()
}

// TestTransactionConcurrentLoadCA makes sure callers that create a CA from
// several goroutines in one process still end up with one matching pair.
func TestTransactionConcurrentLoadCA(t *testing.T) {
	dir := t.TempDir()

	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := &mkcert{CAROOT: dir}
			m.loadCA()
			if m.caCert == nil || m.caKey == nil {
				t.Errorf("loadCA did not load a usable CA")
				return
			}
			if !keyMatchesCertificate(m.caKey, m.caCert) {
				t.Errorf("loadCA returned a mismatched pair")
			}
		}()
	}
	wg.Wait()

	txTestAssertPair(t, dir)
	txTestAssertNoTemps(t, dir)
}
