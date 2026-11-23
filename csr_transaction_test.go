// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newCSRTransactionTestMkcert(t *testing.T) *mkcert {
	t.Helper()
	m := &mkcert{CAROOT: t.TempDir()}
	m.loadCA()
	return m
}

func newCSRTransactionTestRequest(t *testing.T, useECDSA bool, cn string, dnsNames []string, ips []string, emails []string, uris []string) ([]byte, crypto.PublicKey) {
	t.Helper()

	var priv crypto.PrivateKey
	var err error
	if useECDSA {
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatalf("failed to generate CSR key: %v", err)
	}

	tpl := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: cn},
		DNSNames:       append([]string(nil), dnsNames...),
		EmailAddresses: append([]string(nil), emails...),
	}
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Fatalf("invalid test IP %q", ip)
		}
		tpl.IPAddresses = append(tpl.IPAddresses, parsed)
	}
	for _, rawURI := range uris {
		parsed, err := url.Parse(rawURI)
		if err != nil {
			t.Fatalf("invalid test URI %q: %v", rawURI, err)
		}
		tpl.URIs = append(tpl.URIs, parsed)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, priv.(crypto.Signer))
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), priv.(crypto.Signer).Public()
}

func writeCSRTransactionTestRequest(t *testing.T, path string, request []byte) {
	t.Helper()
	if err := ioutil.WriteFile(path, request, 0600); err != nil {
		t.Fatalf("failed to write CSR: %v", err)
	}
}

func readCSRTransactionTestCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read output certificate: %v", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("output is not a PEM certificate")
	}
	if len(rest) != 0 {
		t.Fatalf("output contains trailing data after the certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse output certificate: %v", err)
	}
	return cert
}

func assertCSRTransactionOutput(t *testing.T, m *mkcert, certFile string, publicKey crypto.PublicKey, dnsNames []string, ips []string, emails []string, uris []string) {
	t.Helper()
	cert := readCSRTransactionTestCertificate(t, certFile)
	if !publicKeysEqual(cert.PublicKey, publicKey) {
		t.Fatal("output certificate does not use the CSR public key")
	}
	if err := cert.CheckSignatureFrom(m.caCert); err != nil {
		t.Fatalf("output certificate is not signed by the transaction CA: %v", err)
	}
	if !sameStrings(cert.DNSNames, dnsNames) {
		t.Fatalf("DNS SANs = %v, want %v", cert.DNSNames, dnsNames)
	}
	if !sameStrings(cert.EmailAddresses, emails) {
		t.Fatalf("email SANs = %v, want %v", cert.EmailAddresses, emails)
	}
	var wantIPs []net.IP
	for _, ip := range ips {
		wantIPs = append(wantIPs, net.ParseIP(ip))
	}
	if !sameIPs(cert.IPAddresses, wantIPs) {
		t.Fatalf("IP SANs = %v, want %v", cert.IPAddresses, wantIPs)
	}
	var wantURIs []*url.URL
	for _, rawURI := range uris {
		parsed, err := url.Parse(rawURI)
		if err != nil {
			t.Fatal(err)
		}
		wantURIs = append(wantURIs, parsed)
	}
	if !sameURIs(cert.URIs, wantURIs) {
		t.Fatalf("URI SANs = %v, want %v", cert.URIs, wantURIs)
	}
}

func assertNoCSRTransactionTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to list output directory: %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("found temporary issuance file %q", entry.Name())
		}
	}
}

func TestCSRIssuanceTransactionPreservesRequestIdentity(t *testing.T) {
	for _, useECDSA := range []bool{false, true} {
		name := map[bool]string{false: "RSA", true: "ECDSA"}[useECDSA]
		t.Run(name, func(t *testing.T) {
			m := newCSRTransactionTestMkcert(t)
			dir := t.TempDir()
			m.csrPath = filepath.Join(dir, "request.csr")
			m.certFile = filepath.Join(dir, "output.pem")

			request, publicKey := newCSRTransactionTestRequest(t, useECDSA, "leaf.example",
				[]string{"leaf.example", "www.leaf.example"},
				[]string{"192.0.2.10"},
				[]string{"dev@example.test"},
				[]string{"spiffe://example.test/service"})
			writeCSRTransactionTestRequest(t, m.csrPath, request)

			if err := m.makeCertFromCSRLocked(); err != nil {
				t.Fatalf("CSR issuance failed: %v", err)
			}
			assertCSRTransactionOutput(t, m, m.certFile, publicKey,
				[]string{"leaf.example", "www.leaf.example"},
				[]string{"192.0.2.10"},
				[]string{"dev@example.test"},
				[]string{"spiffe://example.test/service"})
			assertNoCSRTransactionTempFiles(t, dir)
		})
	}
}

func TestCSRIssuanceRetryUsesReplacementRequestAtSamePath(t *testing.T) {
	m := newCSRTransactionTestMkcert(t)
	dir := t.TempDir()
	m.csrPath = filepath.Join(dir, "request.csr")

	firstRequest, firstKey := newCSRTransactionTestRequest(t, false, "first.example",
		nil, []string{"192.0.2.10"}, nil, nil)
	secondRequest, secondKey := newCSRTransactionTestRequest(t, true, "",
		[]string{"second.example"}, nil, nil, nil)
	writeCSRTransactionTestRequest(t, m.csrPath, firstRequest)

	// The first transaction cannot publish because the output directory is
	// missing. It must leave no partial file behind.
	missingDir := filepath.Join(t.TempDir(), "missing")
	m.certFile = filepath.Join(missingDir, "output.pem")
	if err := m.makeCertFromCSRLocked(); err == nil {
		t.Fatal("expected the first write to fail")
	}
	if pathExists(missingDir) {
		t.Fatal("failed issuance recreated its missing output directory")
	}

	// Replace the CSR at the same path. The retry must read and use the new
	// request, not a snapshot from the failed attempt.
	writeCSRTransactionTestRequest(t, m.csrPath, secondRequest)
	m.certFile = filepath.Join(dir, "output.pem")
	if err := m.makeCertFromCSRLocked(); err != nil {
		t.Fatalf("retry after a failed write failed: %v", err)
	}

	cert := readCSRTransactionTestCertificate(t, m.certFile)
	if !publicKeysEqual(cert.PublicKey, secondKey) {
		t.Fatal("retry certificate does not use the replacement CSR public key")
	}
	if publicKeysEqual(cert.PublicKey, firstKey) {
		t.Fatal("retry certificate reused the first CSR public key")
	}
	if len(cert.IPAddresses) != 0 {
		t.Fatalf("retry certificate retained the first CSR IP SANs: %v", cert.IPAddresses)
	}
	if !sameStrings(cert.DNSNames, []string{"second.example"}) {
		t.Fatalf("retry certificate DNS SANs = %v, want [second.example]", cert.DNSNames)
	}
	assertNoCSRTransactionTempFiles(t, dir)
}

func TestCSRIssuanceFallsBackToCommonName(t *testing.T) {
	m := newCSRTransactionTestMkcert(t)
	dir := t.TempDir()
	m.csrPath = filepath.Join(dir, "request.csr")
	m.certFile = filepath.Join(dir, "output.pem")

	request, publicKey := newCSRTransactionTestRequest(t, false, "cn-only.example", nil, nil, nil, nil)
	writeCSRTransactionTestRequest(t, m.csrPath, request)

	if err := m.makeCertFromCSRLocked(); err != nil {
		t.Fatalf("CN-only CSR issuance failed: %v", err)
	}
	assertCSRTransactionOutput(t, m, m.certFile, publicKey,
		[]string{"cn-only.example"}, nil, nil, nil)
}

func TestCSRIssuanceMissingCSR(t *testing.T) {
	m := newCSRTransactionTestMkcert(t)
	m.csrPath = filepath.Join(t.TempDir(), "does-not-exist.csr")
	m.certFile = filepath.Join(t.TempDir(), "output.pem")

	err := m.makeCertFromCSRLocked()
	if err == nil {
		t.Fatal("expected a missing CSR to be rejected")
	}
	if !strings.Contains(err.Error(), "failed to read the CSR") {
		t.Fatalf("unexpected error for a missing CSR: %v", err)
	}
	if _, statErr := os.Stat(m.certFile); !os.IsNotExist(statErr) {
		t.Fatalf("missing CSR produced an output file, stat error = %v", statErr)
	}
}
