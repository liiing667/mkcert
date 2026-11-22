// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

var userAndHostname string

func init() {
	u, err := user.Current()
	if err == nil {
		userAndHostname = u.Username + "@"
	}
	if h, err := os.Hostname(); err == nil {
		userAndHostname += h
	}
	if err == nil && u.Name != "" && u.Name != u.Username {
		userAndHostname += " (" + u.Name + ")"
	}
}

func (m *mkcert) makeCert(hosts []string) {
	if m.caKey == nil {
		log.Fatalln("ERROR: can't create new certificates because the CA key (rootCA-key.pem) is missing")
	}
	if m.caCert == nil {
		log.Fatalln("ERROR: can't create new certificates because the CA certificate is missing")
	}
	fatalIfErr(checkCAKeyPair(m.caCert, m.caKey), "the CA certificate and key do not match")
	if m.CAROOT != "" {
		fatalIfErr(secureMkdirAll(m.CAROOT), "failed to create the CAROOT")
	}

	certFile, keyFile, p12File := m.fileNames(hosts)
	if !m.pkcs12 {
		m.checkOutputPath(certFile, "certificate")
		m.checkOutputPath(keyFile, "key")
		fatalIfErr(validateExistingOutput(certFile, false), "failed to save certificate")
		fatalIfErr(validateExistingOutput(keyFile, true), "failed to save certificate key")
	} else {
		m.checkOutputPath(p12File, "PKCS#12 bundle")
		fatalIfErr(validateExistingOutput(p12File, true), "failed to save PKCS#12")
	}

	priv, err := m.generateKey(false)
	fatalIfErr(err, "failed to generate certificate key")
	pub := priv.(crypto.Signer).Public()

	// Certificates last for 2 years and 3 months, which is always less than
	// 825 days, the limit that macOS/iOS apply to all certificates,
	// including custom roots. See https://support.apple.com/en-us/HT210176.
	expiration := time.Now().AddDate(2, 3, 0)

	tpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject: pkix.Name{
			Organization:       []string{"mkcert development certificate"},
			OrganizationalUnit: []string{userAndHostname},
		},

		NotBefore: time.Now(), NotAfter: expiration,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	for _, h := range hosts {
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

	if m.client {
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
	if m.pkcs12 {
		tpl.Subject.CommonName = hosts[0]
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, m.caCert, pub, m.caKey)
	fatalIfErr(err, "failed to generate certificate")

	if !m.pkcs12 {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		fatalIfErr(err, "failed to encode certificate key")
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

		if samePath(certFile, keyFile) {
			combined := append(append([]byte{}, certPEM...), privPEM...)
			err = writeAllAtomic([]atomicWrite{{certFile, combined, 0600, true, false}})
			fatalIfErr(err, "failed to save certificate and key")
		} else {
			err = writeAllAtomic([]atomicWrite{
				{certFile, certPEM, 0644, false, false},
				{keyFile, privPEM, 0600, true, false},
			})
			fatalIfErr(err, "failed to save certificate and key")
		}
	} else {
		domainCert, _ := x509.ParseCertificate(cert)
		pfxData, err := pkcs12.Encode(rand.Reader, priv, domainCert, []*x509.Certificate{m.caCert}, "changeit")
		fatalIfErr(err, "failed to generate PKCS#12")
		err = writeAllAtomic([]atomicWrite{{p12File, pfxData, 0600, true, false}})
		fatalIfErr(err, "failed to save PKCS#12")
	}

	m.printHosts(hosts)

	if !m.pkcs12 {
		if samePath(certFile, keyFile) {
			log.Printf("\nThe certificate and key are at \"%s\" ✅\n\n", certFile)
		} else {
			log.Printf("\nThe certificate is at \"%s\" and the key at \"%s\" ✅\n\n", certFile, keyFile)
		}
	} else {
		log.Printf("\nThe PKCS#12 bundle is at \"%s\" ✅\n", p12File)
		log.Printf("\nThe legacy PKCS#12 encryption password is the often hardcoded default \"changeit\" ℹ️\n\n")
	}

	log.Printf("It will expire on %s 🗓\n\n", expiration.Format("2 January 2006"))
}

func (m *mkcert) printHosts(hosts []string) {
	secondLvlWildcardRegexp := regexp.MustCompile(`(?i)^\*\.[0-9a-z_-]+$`)
	log.Printf("\nCreated a new certificate valid for the following names 📜")
	for _, h := range hosts {
		log.Printf(" - %q", h)
		if secondLvlWildcardRegexp.MatchString(h) {
			log.Printf("   Warning: many browsers don't support second-level wildcards like %q ⚠️", h)
		}
	}

	for _, h := range hosts {
		if strings.HasPrefix(h, "*.") {
			log.Printf("\nReminder: X.509 wildcards only go one level deep, so this won't match a.b.%s ℹ️", h[2:])
			break
		}
	}
}

func (m *mkcert) generateKey(rootCA bool) (crypto.PrivateKey, error) {
	if m.ecdsa {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if rootCA {
		return rsa.GenerateKey(rand.Reader, 3072)
	}
	return rsa.GenerateKey(rand.Reader, 2048)
}

func (m *mkcert) fileNames(hosts []string) (certFile, keyFile, p12File string) {
	defaultName := strings.Replace(hosts[0], ":", "_", -1)
	defaultName = strings.Replace(defaultName, "*", "_wildcard", -1)
	if len(hosts) > 1 {
		defaultName += "+" + strconv.Itoa(len(hosts)-1)
	}
	if m.client {
		defaultName += "-client"
	}

	certFile = "./" + defaultName + ".pem"
	if m.certFile != "" {
		certFile = m.certFile
	}
	keyFile = "./" + defaultName + "-key.pem"
	if m.keyFile != "" {
		keyFile = m.keyFile
	}
	p12File = "./" + defaultName + ".p12"
	if m.p12File != "" {
		p12File = m.p12File
	}

	return
}

func (m *mkcert) checkOutputPath(path, kind string) {
	for _, caPath := range []string{
		filepath.Join(m.CAROOT, rootName),
		filepath.Join(m.CAROOT, rootKeyName),
	} {
		if samePath(path, caPath) {
			log.Fatalf("ERROR: refusing to overwrite the CA %s at %q with output path %q", kind, caPath, path)
		}
	}
}

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	fatalIfErr(err, "failed to generate serial number")
	return serialNumber
}

func (m *mkcert) makeCertFromCSR() {
	if m.caKey == nil {
		log.Fatalln("ERROR: can't create new certificates because the CA key (rootCA-key.pem) is missing")
	}
	if m.caCert == nil {
		log.Fatalln("ERROR: can't create new certificates because the CA certificate is missing")
	}
	fatalIfErr(checkCAKeyPair(m.caCert, m.caKey), "the CA certificate and key do not match")
	if m.CAROOT != "" {
		fatalIfErr(secureMkdirAll(m.CAROOT), "failed to create the CAROOT")
	}

	csrPEMBytes, err := ioutil.ReadFile(m.csrPath)
	fatalIfErr(err, "failed to read the CSR")
	csrPEM, _ := pem.Decode(csrPEMBytes)
	if csrPEM == nil {
		log.Fatalln("ERROR: failed to read the CSR: unexpected content")
	}
	if csrPEM.Type != "CERTIFICATE REQUEST" &&
		csrPEM.Type != "NEW CERTIFICATE REQUEST" {
		log.Fatalln("ERROR: failed to read the CSR: expected CERTIFICATE REQUEST, got " + csrPEM.Type)
	}
	csr, err := x509.ParseCertificateRequest(csrPEM.Bytes)
	fatalIfErr(err, "failed to parse the CSR")
	fatalIfErr(csr.CheckSignature(), "invalid CSR signature")

	expiration := time.Now().AddDate(2, 3, 0)
	tpl := &x509.Certificate{
		SerialNumber:    randomSerialNumber(),
		Subject:         csr.Subject,
		ExtraExtensions: csr.Extensions, // includes requested SANs, KUs and EKUs

		NotBefore: time.Now(), NotAfter: expiration,

		// If the CSR does not request a SAN extension, fix it up for them as
		// the Common Name field does not work in modern browsers. Otherwise,
		// this will get overridden.
		DNSNames: []string{csr.Subject.CommonName},

		// Likewise, if the CSR does not set KUs and EKUs, fix it up as Apple
		// platforms require serverAuth for TLS.
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if m.client {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if len(csr.EmailAddresses) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, m.caCert, csr.PublicKey, m.caKey)
	fatalIfErr(err, "failed to generate certificate")
	c, err := x509.ParseCertificate(cert)
	fatalIfErr(err, "failed to parse generated certificate")

	var hosts []string
	hosts = append(hosts, c.DNSNames...)
	hosts = append(hosts, c.EmailAddresses...)
	for _, ip := range c.IPAddresses {
		hosts = append(hosts, ip.String())
	}
	for _, uri := range c.URIs {
		hosts = append(hosts, uri.String())
	}
	certFile, _, _ := m.fileNames(hosts)
	m.checkOutputPath(certFile, "certificate")

	err = writeAllAtomic([]atomicWrite{{certFile, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644, false, false}})
	fatalIfErr(err, "failed to save certificate")

	m.printHosts(hosts)

	log.Printf("\nThe certificate is at \"%s\" ✅\n\n", certFile)

	log.Printf("It will expire on %s 🗓\n\n", expiration.Format("2 January 2006"))
}

// loadCA will load or create the CA at CAROOT.
func (m *mkcert) loadCA() {
	fatalIfErr(secureMkdirAll(m.CAROOT), "failed to create the CAROOT")

	certPath := filepath.Join(m.CAROOT, rootName)
	certPEMBlock, certExists, err := readFileNoFollow(certPath, func(fi os.FileInfo) error {
		return validateSensitiveFile(certPath, fi, false)
	})
	fatalIfErr(err, "failed to read the CA certificate")
	if !certExists {
		m.newCA()
		return
	}
	if containsPrivateKeyPEM(certPEMBlock) {
		log.Fatalf("ERROR: the CA certificate file %q contains a private key", certPath)
	}

	certDERBlock, _ := pem.Decode(certPEMBlock)
	if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
		log.Fatalln("ERROR: failed to read the CA certificate: unexpected content")
	}
	m.caCert, err = x509.ParseCertificate(certDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA certificate")

	keyPath := filepath.Join(m.CAROOT, rootKeyName)
	keyPEMBlock, keyExists, err := readFileNoFollow(keyPath, func(fi os.FileInfo) error {
		return validateSensitiveFile(keyPath, fi, true)
	})
	fatalIfErr(err, "failed to read the CA key")
	if !keyExists {
		return // keyless mode, where only -install works
	}

	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	if keyDERBlock == nil || keyDERBlock.Type != "PRIVATE KEY" {
		log.Fatalln("ERROR: failed to read the CA key: unexpected content")
	}
	m.caKey, err = x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA key")

	if err := checkCAKeyPair(m.caCert, m.caKey); err != nil {
		log.Fatalf("ERROR: CA certificate %q and key %q are not a matching pair: %s", certPath, keyPath, err)
	}
}

func checkCAKeyPair(cert *x509.Certificate, key crypto.PrivateKey) error {
	if !cert.IsCA && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("certificate is not a CA certificate")
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return errors.New("the CA key does not implement crypto.Signer")
	}
	certPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to encode the CA certificate public key: %v", err)
	}
	keyPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("failed to encode the CA key public key: %v", err)
	}
	if !bytes.Equal(certPub, keyPub) {
		return errors.New("public key mismatch")
	}
	return nil
}

func containsPrivateKeyPEM(data []byte) bool {
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			return false
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return true
		}
		data = rest
	}
	return false
}

func (m *mkcert) newCA() {
	fatalIfErr(secureMkdirAll(m.CAROOT), "failed to create the CAROOT")

	keyPath := filepath.Join(m.CAROOT, rootKeyName)
	certPath := filepath.Join(m.CAROOT, rootName)

	if err := validateExistingOutput(keyPath, true); err != nil {
		fatalIfErr(err, "failed to read the CA key")
	}
	keyExists := false
	if _, err := os.Lstat(keyPath); err == nil {
		keyExists = true
	} else if !os.IsNotExist(err) {
		fatalIfErr(err, "failed to read the CA key")
	}

	priv, err := m.generateKey(true)
	fatalIfErr(err, "failed to generate the CA key")
	if _, ok := priv.(crypto.Signer); !ok {
		log.Fatalln("ERROR: failed to read the CA key: unsupported key type")
	}
	pub := priv.(crypto.Signer).Public()

	spkiASN1, err := x509.MarshalPKIXPublicKey(pub)
	fatalIfErr(err, "failed to encode public key")

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	fatalIfErr(err, "failed to decode public key")

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)

	tpl := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject: pkix.Name{
			Organization:       []string{"mkcert development CA"},
			OrganizationalUnit: []string{userAndHostname},

			// The CommonName is required by iOS to show the certificate in the
			// "Certificate Trust Settings" menu.
			// https://github.com/FiloSottile/mkcert/issues/47
			CommonName: "mkcert " + userAndHostname,
		},
		SubjectKeyId: skid[:],

		NotAfter:  time.Now().AddDate(10, 0, 0),
		NotBefore: time.Now(),

		KeyUsage: x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	fatalIfErr(err, "failed to generate CA certificate")

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	fatalIfErr(err, "failed to encode CA key")
	createOnly := !keyExists
	err = writeAllAtomic([]atomicWrite{
		{keyPath, pem.EncodeToMemory(
			&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0400, true, createOnly},
		{certPath, pem.EncodeToMemory(
			&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644, false, createOnly},
	})
	fatalIfErr(err, "failed to save CA key and certificate")

	m.caCert, err = x509.ParseCertificate(cert)
	fatalIfErr(err, "failed to parse the generated CA certificate")
	m.caKey = priv

	log.Printf("Created a new local CA 💥\n")
}

func (m *mkcert) caUniqueName() string {
	return "mkcert development CA " + m.caCert.SerialNumber.String()
}
