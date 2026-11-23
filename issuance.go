// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type certificateOutputKind int

const (
	outputCertificateAndKey certificateOutputKind = iota
	outputCertificateOnly
	outputPKCS12
)

// certificateTransaction binds every value that determines an issued
// certificate: the SANs, serial number, private key, output file names and the
// CA key/certificate used to sign it. The transaction holds locks on all output
// files from before the key and serial are generated until the outputs have
// been committed, so concurrent requests cannot mix two certificates.
type certificateTransaction struct {
	hosts  []string
	output certificateOutputKind
	client bool

	certFile, keyFile, p12File string
	locks                      *fileLockSet
	caCert                     *x509.Certificate
	caKey                      crypto.PrivateKey

	serial     *big.Int
	cert       *x509.Certificate
	certPEM    []byte
	keyPEM     []byte
	p12Data    []byte
	expiration time.Time
}

func (m *mkcert) certificateOutputKind() certificateOutputKind {
	if m.pkcs12 {
		return outputPKCS12
	}
	return outputCertificateAndKey
}

func (m *mkcert) beginCertificateTransaction(hosts []string, output certificateOutputKind) (*certificateTransaction, error) {
	if m.caKey == nil {
		return nil, errors.New("can't create new certificates because the CA key (rootCA-key.pem) is missing")
	}
	if m.caCert == nil {
		return nil, errors.New("can't create new certificates because the CA certificate is missing")
	}
	if len(hosts) == 0 {
		return nil, errors.New("no hosts specified")
	}

	tx := &certificateTransaction{
		hosts:  append([]string(nil), hosts...),
		output: output,
		client: m.client,
		caCert: m.caCert,
		caKey:  m.caKey,
	}
	tx.certFile, tx.keyFile, tx.p12File = m.fileNames(tx.hosts)

	var paths []string
	switch output {
	case outputCertificateOnly:
		paths = []string{tx.certFile}
	case outputPKCS12:
		paths = []string{tx.p12File}
	default:
		if samePath(tx.certFile, tx.keyFile) {
			paths = []string{tx.certFile}
		} else {
			paths = []string{tx.certFile, tx.keyFile}
		}
	}
	locks, err := lockOutputs(paths)
	if err != nil {
		return nil, err
	}
	tx.locks = locks
	return tx, nil
}

func (tx *certificateTransaction) close() {
	if tx == nil {
		return
	}
	tx.locks.unlock()
	tx.locks = nil
}

func (tx *certificateTransaction) newSerialNumber() error {
	if tx.serial != nil {
		return nil
	}
	serial, err := newSerialNumber()
	if err != nil {
		return err
	}
	tx.serial = serial
	return nil
}

// certificateTemplate builds the certificate from the transaction's own hosts
// and serial. No value is re-derived from the command line or from an existing
// file afterwards.
func (tx *certificateTransaction) certificateTemplate() *x509.Certificate {
	// Certificates last for 2 years and 3 months, which is always less than
	// 825 days, the limit that macOS/iOS apply to all certificates,
	// including custom roots. See https://support.apple.com/en-us/HT210176.
	tx.expiration = time.Now().AddDate(2, 3, 0)
	tpl := &x509.Certificate{
		SerialNumber: tx.serial,
		Subject: pkix.Name{
			Organization:       []string{"mkcert development certificate"},
			OrganizationalUnit: []string{userAndHostname},
		},

		NotBefore: time.Now(), NotAfter: tx.expiration,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	for _, h := range tx.hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(h); err == nil && email.Address == h {
			tpl.EmailAddresses = append(tpl.EmailAddresses, h)
		} else if uriName, err := url.Parse(h); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			tpl.URIs = append(tpl.URIs, uriName)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}

	if tx.client {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if len(tpl.IPAddresses) > 0 || len(tpl.DNSNames) > 0 || len(tpl.URIs) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if len(tpl.EmailAddresses) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
	}

	// IIS (the main target of PKCS #12 files), only shows the deprecated
	// Common Name in the UI. See issue #115.
	if tx.output == outputPKCS12 {
		tpl.Subject.CommonName = tx.hosts[0]
	}

	return tpl
}

func (tx *certificateTransaction) create(tpl *x509.Certificate, pub crypto.PublicKey) error {
	if tpl.SerialNumber == nil {
		return errors.New("certificate template has no serial number")
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tx.caCert, pub, tx.caKey)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	tx.cert = cert
	tx.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return nil
}

func (tx *certificateTransaction) encodePrivateKey(priv crypto.PrivateKey) error {
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	tx.keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	return nil
}

func (tx *certificateTransaction) encodePKCS12(priv crypto.PrivateKey) error {
	pfxData, err := pkcs12.Encode(rand.Reader, priv, tx.cert, []*x509.Certificate{tx.caCert}, "changeit")
	if err != nil {
		return err
	}
	tx.p12Data = pfxData
	return nil
}

func (tx *certificateTransaction) commit() error {
	switch tx.output {
	case outputCertificateOnly:
		return writeFilesAtomic([]atomicWrite{
			{path: tx.certFile, data: tx.certPEM, perm: 0644},
		})
	case outputPKCS12:
		return writeFilesAtomic([]atomicWrite{
			{path: tx.p12File, data: tx.p12Data, perm: 0644},
		})
	default:
		if samePath(tx.certFile, tx.keyFile) {
			combined := make([]byte, 0, len(tx.certPEM)+len(tx.keyPEM))
			combined = append(combined, tx.certPEM...)
			combined = append(combined, tx.keyPEM...)
			return writeFilesAtomic([]atomicWrite{
				{path: tx.certFile, data: combined, perm: 0600},
			})
		}
		return writeFilesAtomic([]atomicWrite{
			{path: tx.certFile, data: tx.certPEM, perm: 0644},
			{path: tx.keyFile, data: tx.keyPEM, perm: 0600},
		})
	}
}

func commitErrorPath(err error, path string) bool {
	var writeErr *outputWriteError
	if !errors.As(err, &writeErr) {
		return false
	}
	return samePath(writeErr.path, path)
}

func fatalSaveError(err error, tx *certificateTransaction) {
	switch tx.output {
	case outputCertificateOnly:
		fatalIfErr(err, "failed to save certificate")
	case outputPKCS12:
		fatalIfErr(err, "failed to save PKCS#12")
	default:
		if samePath(tx.certFile, tx.keyFile) {
			fatalIfErr(err, "failed to save certificate and key")
		}
		if commitErrorPath(err, tx.keyFile) {
			fatalIfErr(err, "failed to save certificate key")
		}
		if commitErrorPath(err, tx.certFile) {
			fatalIfErr(err, "failed to save certificate")
		}
		fatalIfErr(err, "failed to save certificate and key")
	}
}

// hostsFromCSR returns the names in the same order they were previously read
// back from the issued certificate. Deriving them before signing lets the file
// name and the SAN extension belong to the same CSR transaction.
func hostsFromCSR(csr *x509.CertificateRequest) []string {
	var hosts []string
	hosts = append(hosts, csr.DNSNames...)
	hosts = append(hosts, csr.EmailAddresses...)
	for _, ip := range csr.IPAddresses {
		hosts = append(hosts, ip.String())
	}
	for _, uri := range csr.URIs {
		hosts = append(hosts, uri.String())
	}
	if len(hosts) == 0 && csr.Subject.CommonName != "" {
		hosts = append(hosts, csr.Subject.CommonName)
	}
	return hosts
}
