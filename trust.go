// Copyright 2026 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
)

// caCertPEM returns exactly the certificate that was loaded for this
// invocation. Trust store operations must not re-read rootCA.pem: another
// process (or a symlink swapped after loadCA) must not be able to make mkcert
// trust a different CA.
func (m *mkcert) caCertPEM() []byte {
	if m.caCert == nil {
		if m.CAROOT != "" {
			fatalIfErr(secureMkdirAll(m.CAROOT), "failed to create the CAROOT")
		}
		path := filepath.Join(m.CAROOT, rootName)
		certPEM, exists, err := readFileNoFollow(path, func(fi os.FileInfo) error {
			return validateSensitiveFile(path, fi, false)
		})
		if err != nil {
			log.Fatalf("ERROR: failed to read the CA certificate: %s", err)
		}
		if !exists {
			log.Fatalln("ERROR: failed to read the CA certificate: file is missing")
		}
		if containsPrivateKeyPEM(certPEM) {
			log.Fatalf("ERROR: the CA certificate file %q contains a private key", path)
		}
		block, _ := pem.Decode(certPEM)
		if block == nil || block.Type != "CERTIFICATE" {
			log.Fatalln("ERROR: failed to read the CA certificate: unexpected content")
		}
		m.caCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalf("ERROR: failed to parse the CA certificate: %s", err)
		}
		keyPath := filepath.Join(m.CAROOT, rootKeyName)
		keyPEM, keyExists, err := readFileNoFollow(keyPath, func(fi os.FileInfo) error {
			return validateSensitiveFile(keyPath, fi, true)
		})
		if err != nil {
			log.Fatalf("ERROR: failed to read the CA key: %s", err)
		}
		if keyExists {
			keyBlock, _ := pem.Decode(keyPEM)
			if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
				log.Fatalln("ERROR: failed to read the CA key: unexpected content")
			}
			key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
			if err != nil {
				log.Fatalf("ERROR: failed to parse the CA key: %s", err)
			}
			if err := checkCAKeyPair(m.caCert, key); err != nil {
				log.Fatalf("ERROR: CA certificate %q and key %q are not a matching pair: %s", path, keyPath, err)
			}
			m.caKey = key
		}
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.caCert.Raw})
}

// trustStoreCertFile materializes the in-memory CA certificate in a private
// temporary file for tools that can only import a certificate from a path.
func (m *mkcert) trustStoreCertFile() (string, func(), error) {
	data := m.caCertPEM()
	f, err := os.CreateTemp("", "mkcert-trust-*.pem")
	if err != nil {
		return "", nil, err
	}
	name := f.Name()
	cleanup := func() {
		f.Close()
		os.Remove(name)
	}
	if err := f.Chmod(0600); err != nil {
		cleanup()
		return "", nil, err
	}
	if _, err := f.Write(data); err != nil {
		cleanup()
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return "", nil, err
	}
	return name, func() { os.Remove(name) }, nil
}
