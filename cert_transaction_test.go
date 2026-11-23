// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func txTestCA(t *testing.T) *mkcert {
	t.Helper()
	m := &mkcert{CAROOT: t.TempDir()}
	m.loadCA()
	if key, ok := m.caKey.(*rsa.PrivateKey); ok {
		// Avoid lazy precomputation racing across the concurrent-issuance test.
		key.Precompute()
	}
	return m
}

func txTestClone(m *mkcert) *mkcert {
	return &mkcert{
		CAROOT:   m.CAROOT,
		caCert:   m.caCert,
		caKey:    m.caKey,
		ecdsa:    m.ecdsa,
		pkcs12:   m.pkcs12,
		client:   m.client,
		certFile: m.certFile,
		keyFile:  m.keyFile,
		p12File:  m.p12File,
	}
}

func txTestReadCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("read certificate %q: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("%q is not a PEM certificate", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate %q: %v", path, err)
	}
	return cert
}

func txTestReadKey(t *testing.T, path string) crypto.PrivateKey {
	t.Helper()
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("read key %q: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%q is not PEM", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse key %q: %v", path, err)
	}
	return key
}

func txTestPublicKey(t *testing.T, key crypto.PrivateKey) []byte {
	t.Helper()
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatalf("%T is not a crypto.Signer", key)
	}
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func txTestCertificatePublicKey(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func txTestAssertPair(t *testing.T, ca *mkcert, certPath, keyPath string) *x509.Certificate {
	t.Helper()
	cert := txTestReadCert(t, certPath)
	key := txTestReadKey(t, keyPath)
	if !bytes.Equal(txTestCertificatePublicKey(t, cert), txTestPublicKey(t, key)) {
		t.Fatalf("certificate %q and key %q do not belong together", certPath, keyPath)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.caCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: cert.NotBefore.Add(time.Second),
	}); err != nil {
		t.Fatalf("certificate %q was not signed by the transaction CA: %v", certPath, err)
	}
	return cert
}

func txTestAssertNoTemps(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".*.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("transaction left temporary files behind: %v", matches)
	}
}

// TestTransactionFileNamesPreserveBehavior pins the historical output names
// used by single-host, multi-SAN and wildcard certificates.
func TestTransactionFileNamesPreserveBehavior(t *testing.T) {
	m := &mkcert{}
	certFile, keyFile, p12File := m.fileNames([]string{"example.test"})
	if certFile != "./example.test.pem" || keyFile != "./example.test-key.pem" || p12File != "./example.test.p12" {
		t.Fatalf("single-host names = %q, %q, %q", certFile, keyFile, p12File)
	}

	certFile, keyFile, _ = m.fileNames([]string{"example.test", "www.example.test"})
	if certFile != "./example.test+1.pem" || keyFile != "./example.test+1-key.pem" {
		t.Fatalf("multi-SAN names = %q, %q", certFile, keyFile)
	}

	certFile, keyFile, _ = m.fileNames([]string{"*.example.test"})
	if certFile != "./_wildcard.example.test.pem" || keyFile != "./_wildcard.example.test-key.pem" {
		t.Fatalf("wildcard names = %q, %q", certFile, keyFile)
	}
}

// TestTransactionRSAAndECDSAPairs checks that SANs, serial, key and output
// files all come from the same transaction for both key algorithms.
func TestTransactionRSAAndECDSAPairs(t *testing.T) {
	for _, ecdsaKey := range []bool{false, true} {
		name := "RSA"
		if ecdsaKey {
			name = "ECDSA"
		}
		t.Run(name, func(t *testing.T) {
			ca := txTestCA(t)
			work := t.TempDir()
			m := txTestClone(ca)
			m.ecdsa = ecdsaKey
			m.certFile = filepath.Join(work, "cert.pem")
			m.keyFile = filepath.Join(work, "key.pem")

			hosts := []string{"example.test", "www.example.test"}
			m.makeCert(hosts)

			cert := txTestAssertPair(t, ca, m.certFile, m.keyFile)
			if cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 {
				t.Fatal("certificate has no serial number")
			}
			if len(cert.DNSNames) != 2 || cert.DNSNames[0] != hosts[0] || cert.DNSNames[1] != hosts[1] {
				t.Fatalf("SANs = %v, want %v", cert.DNSNames, hosts)
			}
			key := txTestReadKey(t, m.keyFile)
			if ecdsaKey {
				if _, ok := key.(*ecdsa.PrivateKey); !ok {
					t.Fatalf("expected ECDSA key, got %T", key)
				}
			} else {
				if _, ok := key.(*rsa.PrivateKey); !ok {
					t.Fatalf("expected RSA key, got %T", key)
				}
			}
			txTestAssertNoTemps(t, work)
		})
	}
}

func TestTransactionPKCS12(t *testing.T) {
	ca := txTestCA(t)
	work := t.TempDir()
	m := txTestClone(ca)
	m.pkcs12 = true
	m.p12File = filepath.Join(work, "bundle.p12")

	m.makeCert([]string{"*.p12.example.test"})

	data, err := ioutil.ReadFile(m.p12File)
	if err != nil {
		t.Fatal(err)
	}
	key, cert, _, err := pkcs12.Decode(data, "changeit")
	if err != nil {
		t.Fatalf("decode PKCS#12: %v", err)
	}
	if !bytes.Equal(txTestCertificatePublicKey(t, cert), txTestPublicKey(t, key)) {
		t.Fatal("PKCS#12 key and certificate do not belong together")
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "*.p12.example.test" {
		t.Fatalf("PKCS#12 SANs = %v", cert.DNSNames)
	}
}

func TestTransactionCombinedCertificateAndKeyFile(t *testing.T) {
	ca := txTestCA(t)
	work := t.TempDir()
	path := filepath.Join(work, "combined.pem")
	m := txTestClone(ca)
	m.certFile = path
	m.keyFile = path

	m.makeCert([]string{"combined.example.test"})

	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	certBlock, rest := pem.Decode(data)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatal("combined output does not start with a certificate")
	}
	keyBlock, _ := pem.Decode(rest)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatal("combined output does not contain a private key")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(txTestCertificatePublicKey(t, cert), txTestPublicKey(t, key)) {
		t.Fatal("combined certificate and key do not belong together")
	}
}

// TestTransactionConcurrentRequestsStayPaired is the in-process version of the
// reported race: many requests write the same two output paths at once. The
// final certificate and key must always be from one request, never a mix.
func TestTransactionConcurrentRequestsStayPaired(t *testing.T) {
	ca := txTestCA(t)
	work := t.TempDir()

	const n = 12
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		hosts := []string{"alpha.example.test"}
		if i%2 == 1 {
			hosts = []string{"beta.example.test"}
		}
		wg.Add(1)
		go func(hosts []string) {
			defer wg.Done()
			m := txTestClone(ca)
			m.certFile = filepath.Join(work, "shared.pem")
			m.keyFile = filepath.Join(work, "shared-key.pem")
			m.makeCert(hosts)
		}(hosts)
	}
	wg.Wait()

	cert := txTestAssertPair(t, ca,
		filepath.Join(work, "shared.pem"),
		filepath.Join(work, "shared-key.pem"))
	if len(cert.DNSNames) != 1 ||
		(cert.DNSNames[0] != "alpha.example.test" && cert.DNSNames[0] != "beta.example.test") {
		t.Fatalf("final certificate has unrelated SANs: %v", cert.DNSNames)
	}
	txTestAssertNoTemps(t, work)
}

// TestTransactionFailedKeyWriteKeepsOldPairAndUsesFreshSerial reproduces the
// failure half of the report. The certificate must not be published when the
// key cannot be written, the previous file must survive, and a retry must issue
// a new serial rather than reusing the abandoned one.
func TestTransactionFailedKeyWriteKeepsOldPairAndUsesFreshSerial(t *testing.T) {
	ca := txTestCA(t)
	work := t.TempDir()
	certPath := filepath.Join(work, "cert.pem")
	keyPath := filepath.Join(work, "key.pem")

	old := txTestClone(ca)
	old.certFile = certPath
	old.keyFile = keyPath
	old.makeCert([]string{"*.old.example.test"})
	oldCert := txTestReadCert(t, certPath)
	oldPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}

	// Make the key destination a directory so writing the key fails.
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(keyPath, 0700); err != nil {
		t.Fatal(err)
	}

	failed := txTestClone(ca)
	failed.certFile = certPath
	failed.keyFile = keyPath
	tx, err := failed.beginCertificateTransaction([]string{"*.retry.example.test"}, outputCertificateAndKey)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.close()

	if err := tx.newSerialNumber(); err != nil {
		t.Fatal(err)
	}
	abandonedSerial := tx.serial
	priv, err := failed.generateKey(false)
	if err != nil {
		t.Fatal(err)
	}
	tpl := tx.certificateTemplate()
	if err := tx.create(tpl, priv.(crypto.Signer).Public()); err != nil {
		t.Fatal(err)
	}
	if err := tx.encodePrivateKey(priv); err != nil {
		t.Fatal(err)
	}
	if err := tx.commit(); err == nil {
		t.Fatal("key write unexpectedly succeeded")
	}
	tx.close()

	after, err := ioutil.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, oldPEM) {
		t.Fatal("failed key write modified the previous certificate")
	}
	if abandonedSerial.Cmp(oldCert.SerialNumber) == 0 {
		t.Fatal("the abandoned transaction reused the previous serial")
	}

	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	retry := txTestClone(ca)
	retry.certFile = certPath
	retry.keyFile = keyPath
	retry.makeCert([]string{"*.retry.example.test"})
	retried := txTestAssertPair(t, ca, certPath, keyPath)
	if retried.SerialNumber.Cmp(oldCert.SerialNumber) == 0 {
		t.Fatal("retry reused the serial from the previous certificate")
	}
	if retried.SerialNumber.Cmp(abandonedSerial) == 0 {
		t.Fatal("retry reused the serial from the failed transaction")
	}
}
