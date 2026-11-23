// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"time"
)

var oidCSRSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// csrRequestSnapshot is an immutable copy of the request that authorized one
// certificate. Everything used to build the certificate and its output name
// comes from this snapshot, never from mutable state left by a previous
// attempt.
type csrRequestSnapshot struct {
	subject        pkix.Name
	rawSubject     []byte
	publicKey      crypto.PublicKey
	extensions     []pkix.Extension
	hasSAN         bool
	dnsNames       []string
	emailAddresses []string
	ipAddresses    []net.IP
	uris           []*url.URL
}

// csrIssuanceTransaction groups the request snapshot, the signed leaf, and
// the encoded output produced from that exact leaf. The output is published
// only after the leaf has been checked against the request and the CA.
type csrIssuanceTransaction struct {
	certPEM    []byte
	certFile   string
	hosts      []string
	expiration time.Time
}

func (m *mkcert) makeCertFromCSRLocked() error {
	tx, err := m.issueCertificateFromCSR()
	if err != nil {
		return err
	}

	certFile, err := tx.commit()
	if err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	m.printHosts(tx.hosts)

	log.Printf("\nThe certificate is at \"%s\" ✅\n\n", certFile)
	log.Printf("It will expire on %s 🗓\n\n", tx.expiration.Format("2 January 2006"))
	return nil
}

func (m *mkcert) issueCertificateFromCSR() (*csrIssuanceTransaction, error) {
	if m.caKey == nil {
		return nil, errors.New("can't create new certificates because the CA key (rootCA-key.pem) is missing")
	}
	if m.caCert == nil {
		return nil, errors.New("can't create new certificates because the CA certificate (rootCA.pem) is missing")
	}
	if err := checkCAKeyPair(m.caCert, m.caKey); err != nil {
		return nil, fmt.Errorf("refusing to issue a certificate: %w", err)
	}

	// Read and verify the CSR exactly once for this attempt. In particular,
	// do not cache it by path: a retry may replace the file at the same path
	// with a different request, key, and SAN set.
	csr, err := m.readCSR()
	if err != nil {
		return nil, err
	}
	request := snapshotCSR(csr)

	expiration := time.Now().AddDate(2, 3, 0)
	tpl := m.certificateTemplateFromCSR(request, expiration)

	certDER, err := x509.CreateCertificate(rand.Reader, tpl, m.caCert, request.publicKey, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}
	if err := verifyCSRIssuance(request, leaf, m.caCert); err != nil {
		return nil, fmt.Errorf("failed to verify generated certificate: %w", err)
	}

	hosts := certificateHosts(leaf)
	if len(hosts) == 0 {
		return nil, errors.New("the CSR does not contain any subject alternative names or a common name")
	}
	certFile, _, _ := m.fileNames(hosts)

	return &csrIssuanceTransaction{
		certPEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		certFile:   certFile,
		hosts:      hosts,
		expiration: expiration,
	}, nil
}

func (m *mkcert) readCSR() (*x509.CertificateRequest, error) {
	csrPEMBytes, err := ioutil.ReadFile(m.csrPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read the CSR: %w", err)
	}
	csrPEM, _ := pem.Decode(csrPEMBytes)
	if csrPEM == nil {
		return nil, errors.New("failed to read the CSR: unexpected content")
	}
	if csrPEM.Type != "CERTIFICATE REQUEST" &&
		csrPEM.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("failed to read the CSR: expected CERTIFICATE REQUEST, got %s", csrPEM.Type)
	}
	csr, err := x509.ParseCertificateRequest(csrPEM.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}
	return csr, nil
}

func snapshotCSR(csr *x509.CertificateRequest) *csrRequestSnapshot {
	request := &csrRequestSnapshot{
		subject:        cloneName(csr.Subject),
		rawSubject:     append([]byte(nil), csr.RawSubject...),
		publicKey:      csr.PublicKey,
		extensions:     cloneExtensions(csr.Extensions),
		hasSAN:         hasExtension(csr.Extensions, oidCSRSubjectAltName),
		dnsNames:       append([]string(nil), csr.DNSNames...),
		emailAddresses: append([]string(nil), csr.EmailAddresses...),
	}
	for _, ip := range csr.IPAddresses {
		request.ipAddresses = append(request.ipAddresses, append(net.IP(nil), ip...))
	}
	for _, uri := range csr.URIs {
		request.uris = append(request.uris, cloneURL(uri))
	}
	if !request.hasSAN {
		// Preserve mkcert's historical fallback for a CSR without SANs.
		request.dnsNames = []string{csr.Subject.CommonName}
	}
	return request
}

func (m *mkcert) certificateTemplateFromCSR(request *csrRequestSnapshot, expiration time.Time) *x509.Certificate {
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:    randomSerialNumber(),
		Subject:         request.subject,
		RawSubject:      append([]byte(nil), request.rawSubject...),
		ExtraExtensions: cloneExtensions(request.extensions),

		NotBefore: now, NotAfter: expiration,

		// If the CSR does not request a SAN extension, fix it up for them as
		// the Common Name field does not work in modern browsers. Otherwise,
		// the copied SAN extension takes precedence.
		DNSNames: append([]string(nil), request.dnsNames...),

		// Likewise, if the CSR does not set KUs and EKUs, fix it up as Apple
		// platforms require serverAuth for TLS.
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if m.client {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if len(request.emailAddresses) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
	}
	return tpl
}

func verifyCSRIssuance(request *csrRequestSnapshot, leaf *x509.Certificate, ca *x509.Certificate) error {
	if !publicKeysEqual(request.publicKey, leaf.PublicKey) {
		return errors.New("the certificate public key does not match the CSR")
	}
	if !bytes.Equal(request.rawSubject, leaf.RawSubject) {
		return errors.New("the certificate subject does not match the CSR")
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("the certificate is not signed by the loaded CA: %w", err)
	}
	if !sameStrings(leaf.DNSNames, request.dnsNames) {
		return fmt.Errorf("DNS SANs %v do not match the CSR SANs %v", leaf.DNSNames, request.dnsNames)
	}
	if !sameStrings(leaf.EmailAddresses, request.emailAddresses) {
		return fmt.Errorf("email SANs %v do not match the CSR SANs %v", leaf.EmailAddresses, request.emailAddresses)
	}
	if !sameIPs(leaf.IPAddresses, request.ipAddresses) {
		return fmt.Errorf("IP SANs %v do not match the CSR SANs %v", leaf.IPAddresses, request.ipAddresses)
	}
	if !sameURIs(leaf.URIs, request.uris) {
		return fmt.Errorf("URI SANs %v do not match the CSR SANs %v", leaf.URIs, request.uris)
	}
	return nil
}

func (tx *csrIssuanceTransaction) commit() (string, error) {
	if err := writeFileAtomic(tx.certFile, tx.certPEM, 0644); err != nil {
		return "", err
	}
	return tx.certFile, nil
}

func certificateHosts(cert *x509.Certificate) []string {
	var hosts []string
	hosts = append(hosts, cert.DNSNames...)
	hosts = append(hosts, cert.EmailAddresses...)
	for _, ip := range cert.IPAddresses {
		hosts = append(hosts, ip.String())
	}
	for _, uri := range cert.URIs {
		hosts = append(hosts, uri.String())
	}
	return hosts
}

func checkCAKeyPair(cert *x509.Certificate, key crypto.PrivateKey) error {
	if cert == nil {
		return errors.New("the CA certificate is missing")
	}
	if key == nil {
		return errors.New("the CA key is missing")
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return errors.New("the CA key cannot sign certificates")
	}
	if !publicKeysEqual(cert.PublicKey, signer.Public()) {
		return errors.New("the CA certificate and private key do not match")
	}
	return nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	aBytes, aErr := x509.MarshalPKIXPublicKey(a)
	bBytes, bErr := x509.MarshalPKIXPublicKey(b)
	return aErr == nil && bErr == nil && bytes.Equal(aBytes, bBytes)
}

func hasExtension(extensions []pkix.Extension, oid asn1.ObjectIdentifier) bool {
	for _, extension := range extensions {
		if extension.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func cloneExtensions(extensions []pkix.Extension) []pkix.Extension {
	cloned := make([]pkix.Extension, len(extensions))
	for i, extension := range extensions {
		cloned[i] = pkix.Extension{
			Id:       append(asn1.ObjectIdentifier(nil), extension.Id...),
			Critical: extension.Critical,
			Value:    append([]byte(nil), extension.Value...),
		}
	}
	return cloned
}

func cloneName(name pkix.Name) pkix.Name {
	name.Country = append([]string(nil), name.Country...)
	name.Organization = append([]string(nil), name.Organization...)
	name.OrganizationalUnit = append([]string(nil), name.OrganizationalUnit...)
	name.Locality = append([]string(nil), name.Locality...)
	name.Province = append([]string(nil), name.Province...)
	name.StreetAddress = append([]string(nil), name.StreetAddress...)
	name.PostalCode = append([]string(nil), name.PostalCode...)
	name.Names = append([]pkix.AttributeTypeAndValue(nil), name.Names...)
	name.ExtraNames = append([]pkix.AttributeTypeAndValue(nil), name.ExtraNames...)
	return name
}

func cloneURL(uri *url.URL) *url.URL {
	if uri == nil {
		return nil
	}
	cloned := *uri
	return &cloned
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameIPs(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

func sameURIs(a, b []*url.URL) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] == nil || b[i] == nil {
			if a[i] != nil || b[i] != nil {
				return false
			}
			continue
		}
		if a[i].String() != b[i].String() {
			return false
		}
	}
	return true
}
