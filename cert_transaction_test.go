// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func newCertificateTestMkcert(t *testing.T, useECDSA bool) *mkcert {
	t.Helper()
	m := &mkcert{CAROOT: t.TempDir(), ecdsa: useECDSA}
	m.loadCA()
	return m
}

func certificateOutputPaths(t *testing.T, m *mkcert, name string) (string, string, string) {
	t.Helper()
	dir := filepath.Join(m.CAROOT, "outputs")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, name+".pem")
	keyFile := filepath.Join(dir, name+"-key.pem")
	p12File := filepath.Join(dir, name+".p12")
	m.certFile, m.keyFile, m.p12File = certFile, keyFile, p12File
	return certFile, keyFile, p12File
}

func assertPrivateKeyType(t *testing.T, key crypto.PrivateKey, useECDSA bool) {
	t.Helper()
	if useECDSA {
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			t.Fatalf("expected ECDSA key, got %T", key)
		}
		return
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected RSA key, got %T", key)
	}
	if rsaKey.N.BitLen() != 2048 {
		t.Fatalf("expected 2048-bit RSA key, got %d bits", rsaKey.N.BitLen())
	}
}

func assertPEMCertificateTransaction(t *testing.T, m *mkcert, certFile, keyFile string, hosts []string, useECDSA, client bool) {
	t.Helper()

	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	certBlock, rest := pem.Decode(certBytes)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatalf("certificate PEM type = %q, want CERTIFICATE", certBlockType(certBlock))
	}
	leaf, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, keyRest := pem.Decode(keyBytes)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatalf("key PEM type = %q, want PRIVATE KEY", certBlockType(keyBlock))
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	assertPrivateKeyType(t, key, useECDSA)
	if !publicKeysEqual(key.(crypto.Signer).Public(), leaf.PublicKey) {
		t.Fatal("PEM private key does not match the leaf certificate")
	}
	if err := leaf.CheckSignatureFrom(m.caCert); err != nil {
		t.Fatalf("PEM leaf is not signed by the transaction CA: %v", err)
	}
	assertCertificateIdentity(t, leaf, hosts, client)
	if len(rest) != 0 || len(keyRest) != 0 {
		t.Fatal("PEM output contains unexpected trailing blocks")
	}
}

func assertP12CertificateTransaction(t *testing.T, m *mkcert, p12File string, hosts []string, useECDSA, client bool) {
	t.Helper()

	data, err := ioutil.ReadFile(p12File)
	if err != nil {
		t.Fatal(err)
	}
	key, leaf, ca, err := pkcs12.DecodeChain(data, "changeit")
	if err != nil {
		t.Fatalf("failed to parse P12 as an importing consumer: %v", err)
	}
	assertPrivateKeyType(t, key, useECDSA)
	if !publicKeysEqual(key.(crypto.Signer).Public(), leaf.PublicKey) {
		t.Fatal("P12 private key does not match the leaf certificate")
	}
	if err := leaf.CheckSignatureFrom(m.caCert); err != nil {
		t.Fatalf("P12 leaf is not signed by the transaction CA: %v", err)
	}
	if len(ca) != 1 || !ca[0].Equal(m.caCert) {
		t.Fatal("P12 does not contain the CA chain from the issuance transaction")
	}
	assertCertificateIdentity(t, leaf, hosts, client)
}

func certBlockType(block *pem.Block) string {
	if block == nil {
		return "<nil>"
	}
	return block.Type
}

func assertCertificateIdentity(t *testing.T, leaf *x509.Certificate, hosts []string, client bool) {
	t.Helper()
	if len(leaf.DNSNames) != 2 || leaf.DNSNames[0] != hosts[0] || leaf.DNSNames[1] != hosts[1] {
		t.Fatalf("DNS SANs = %v, want %v", leaf.DNSNames, hosts[:2])
	}
	ip := net.ParseIP(hosts[2])
	if ip == nil || len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(ip) {
		t.Fatalf("IP SANs = %v, want [%s]", leaf.IPAddresses, hosts[2])
	}
	if len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != hosts[3] {
		t.Fatalf("email SANs = %v, want [%s]", leaf.EmailAddresses, hosts[3])
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != hosts[4] {
		t.Fatalf("URI SANs = %v, want [%s]", leaf.URIs, hosts[4])
	}
	if leaf.KeyUsage != (x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature) {
		t.Fatalf("KeyUsage = %v, want digital signature and key encipherment", leaf.KeyUsage)
	}
	assertHasEKU(t, leaf, x509.ExtKeyUsageServerAuth)
	assertHasEKU(t, leaf, x509.ExtKeyUsageEmailProtection)
	if client {
		assertHasEKU(t, leaf, x509.ExtKeyUsageClientAuth)
	}
}

func assertHasEKU(t *testing.T, leaf *x509.Certificate, want x509.ExtKeyUsage) {
	t.Helper()
	for _, eku := range leaf.ExtKeyUsage {
		if eku == want {
			return
		}
	}
	t.Fatalf("EKUs = %v, missing %v", leaf.ExtKeyUsage, want)
}

func TestCertificateTransactionOutputs(t *testing.T) {
	hosts := []string{"*.example.test", "api.example.test", "127.0.0.1", "dev@example.test", "spiffe://example.test/service"}

	for _, useECDSA := range []bool{false, true} {
		for _, p12 := range []bool{false, true} {
			for _, client := range []bool{false, true} {
				name := map[bool]string{false: "RSA", true: "ECDSA"}[useECDSA]
				if p12 {
					name += "-P12"
				} else {
					name += "-PEM"
				}
				if client {
					name += "-client"
				}

				t.Run(name, func(t *testing.T) {
					m := newCertificateTestMkcert(t, useECDSA)
					m.pkcs12 = p12
					m.client = client
					certFile, keyFile, p12File := certificateOutputPaths(t, m, name)

					m.makeCert(hosts)

					if p12 {
						if pathExists(certFile) || pathExists(keyFile) {
							t.Fatal("P12 mode created PEM outputs")
						}
						assertP12CertificateTransaction(t, m, p12File, hosts, useECDSA, client)
					} else {
						if pathExists(p12File) {
							t.Fatal("PEM mode created a P12 output")
						}
						assertPEMCertificateTransaction(t, m, certFile, keyFile, hosts, useECDSA, client)
					}
					assertNoCertificateTemporaryFiles(t, filepath.Dir(certFile))
				})
			}
		}
	}
}

func TestP12TransactionsDoNotInterleave(t *testing.T) {
	const count = 8
	m := newCertificateTestMkcert(t, false)
	outputDir := filepath.Join(m.CAROOT, "concurrent")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errors := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker := &mkcert{
				CAROOT:   m.CAROOT,
				caCert:   m.caCert,
				caKey:    m.caKey,
				pkcs12:   true,
				p12File:  filepath.Join(outputDir, "wildcard.p12"),
				certFile: filepath.Join(outputDir, "unused.pem"),
				keyFile:  filepath.Join(outputDir, "unused-key.pem"),
			}
			worker.makeCert([]string{"*.example.test", "www.example.test"})

			data, err := ioutil.ReadFile(worker.p12File)
			if err != nil {
				errors <- err
				return
			}
			key, leaf, ca, err := pkcs12.DecodeChain(data, "changeit")
			if err != nil {
				errors <- err
				return
			}
			if !publicKeysEqual(key.(crypto.Signer).Public(), leaf.PublicKey) || len(ca) != 1 || !ca[0].Equal(m.caCert) {
				errors <- os.ErrInvalid
			}
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	assertNoCertificateTemporaryFiles(t, outputDir)
	assertNoCertificateTemporaryFiles(t, m.CAROOT)
}

func TestP12RetryReplacesTheWholeGeneration(t *testing.T) {
	m := newCertificateTestMkcert(t, false)
	m.pkcs12 = true
	_, _, p12File := certificateOutputPaths(t, m, "retry")

	m.makeCert([]string{"*.example.test"})
	firstKey, firstLeaf, firstCA, err := pkcs12.DecodeChain(mustReadFile(t, p12File), "changeit")
	if err != nil {
		t.Fatal(err)
	}

	m.makeCert([]string{"*.retry.example.test"})
	secondKey, secondLeaf, secondCA, err := pkcs12.DecodeChain(mustReadFile(t, p12File), "changeit")
	if err != nil {
		t.Fatal(err)
	}

	if publicKeysEqual(firstKey.(crypto.Signer).Public(), secondKey.(crypto.Signer).Public()) {
		t.Fatal("retry reused the old private key")
	}
	if firstLeaf.Equal(secondLeaf) || len(secondLeaf.DNSNames) != 1 || secondLeaf.DNSNames[0] != "*.retry.example.test" {
		t.Fatalf("retry did not replace the leaf identity: old = %v, new = %v", firstLeaf.DNSNames, secondLeaf.DNSNames)
	}
	if len(firstCA) != 1 || len(secondCA) != 1 || !firstCA[0].Equal(secondCA[0]) || !secondCA[0].Equal(m.caCert) {
		t.Fatal("retry changed the CA chain shared by the issuance transactions")
	}
	if !publicKeysEqual(secondKey.(crypto.Signer).Public(), secondLeaf.PublicKey) {
		t.Fatal("retry paired the new leaf with a key from another generation")
	}
}

func TestCombinedPEMTransactionKeepsOneMatchingGeneration(t *testing.T) {
	m := newCertificateTestMkcert(t, true)
	dir := filepath.Join(m.CAROOT, "combined")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	combined := filepath.Join(dir, "combined.pem")
	m.certFile = combined
	m.keyFile = combined

	if err := m.makeCertLocked([]string{"*.example.test", "api.example.test"}); err != nil {
		t.Fatal(err)
	}

	combinedBytes, err := ioutil.ReadFile(combined)
	if err != nil {
		t.Fatal(err)
	}
	certBlock, rest := pem.Decode(combinedBytes)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatalf("first PEM block type = %q, want CERTIFICATE", certBlockType(certBlock))
	}
	keyBlock, trailing := pem.Decode(rest)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(trailing) != 0 {
		t.Fatalf("combined PEM must contain exactly one leaf and one private key")
	}
	leaf, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !publicKeysEqual(key.(crypto.Signer).Public(), leaf.PublicKey) {
		t.Fatal("combined PEM paired a key and leaf from different generations")
	}
	info, err := os.Stat(combined)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("combined PEM permissions = %o, want 0600", perm)
	}
	assertNoCertificateTemporaryFiles(t, dir)
}

func TestMissingOutputDirectoryLeavesNoCrossGeneration(t *testing.T) {
	m := newCertificateTestMkcert(t, false)
	outputDir := filepath.Join(m.CAROOT, "readonly")
	p12File := filepath.Join(outputDir, "wildcard.p12")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatal(err)
	}
	assertNoCertificateTemporaryFiles(t, m.CAROOT)

	m.pkcs12 = true
	m.p12File = p12File
	m.certFile = filepath.Join(outputDir, "unused.pem")
	m.keyFile = filepath.Join(outputDir, "unused-key.pem")
	tx, err := m.issueCertificate([]string{"*.example.test"})
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the reported P12 write failure before any destination is
	// published. The failed generation must leave no output behind.
	if err := os.RemoveAll(outputDir); err != nil {
		t.Fatal(err)
	}
	if err := tx.write([]string{p12File}); err == nil {
		t.Fatal("expected write to a missing output directory to fail")
	}
	tx.cleanup()
	if _, err := os.Stat(outputDir); !os.IsNotExist(err) {
		t.Fatalf("failed write recreated the output directory, stat err = %v", err)
	}

	// A retry starts a fresh transaction and atomically publishes only its own
	// key, leaf and CA chain.
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := m.makeCertLocked([]string{"*.example.test"}); err != nil {
		t.Fatal(err)
	}
	key, leaf, ca, err := pkcs12.DecodeChain(mustReadFile(t, m.p12File), "changeit")
	if err != nil {
		t.Fatalf("retry did not produce a valid P12: %v", err)
	}
	if !publicKeysEqual(key.(crypto.Signer).Public(), leaf.PublicKey) || len(ca) != 1 || !ca[0].Equal(m.caCert) {
		t.Fatal("retry produced a cross-generation P12")
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "*.example.test" {
		t.Fatalf("retry certificate identity = %v", leaf.DNSNames)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertNoCertificateTemporaryFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.Contains(name, ".tmp-") || strings.Contains(name, ".stage-") || strings.Contains(name, ".backup-") {
			t.Fatalf("found transaction temporary file %q in %q", name, dir)
		}
	}
}
