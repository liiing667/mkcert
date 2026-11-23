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
	"sync"
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

	certFile, keyFile, p12File := m.fileNames(hosts)

	if !m.pkcs12 {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
		privDER, err := x509.MarshalPKCS8PrivateKey(priv)
		fatalIfErr(err, "failed to encode certificate key")
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

		if certFile == keyFile {
			err = ioutil.WriteFile(keyFile, append(certPEM, privPEM...), 0600)
			fatalIfErr(err, "failed to save certificate and key")
		} else {
			err = ioutil.WriteFile(certFile, certPEM, 0644)
			fatalIfErr(err, "failed to save certificate")
			err = ioutil.WriteFile(keyFile, privPEM, 0600)
			fatalIfErr(err, "failed to save certificate key")
		}
	} else {
		domainCert, _ := x509.ParseCertificate(cert)
		pfxData, err := pkcs12.Encode(rand.Reader, priv, domainCert, []*x509.Certificate{m.caCert}, "changeit")
		fatalIfErr(err, "failed to generate PKCS#12")
		err = ioutil.WriteFile(p12File, pfxData, 0644)
		fatalIfErr(err, "failed to save PKCS#12")
	}

	m.printHosts(hosts)

	if !m.pkcs12 {
		if certFile == keyFile {
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

	err = ioutil.WriteFile(certFile, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
	fatalIfErr(err, "failed to save certificate")

	m.printHosts(hosts)

	log.Printf("\nThe certificate is at \"%s\" ✅\n\n", certFile)

	log.Printf("It will expire on %s 🗓\n\n", expiration.Format("2 January 2006"))
}

// caLoadMu serializes in-process callers of loadCA. Cross-process callers
// are serialized by the CAROOT lock in Run.
var caLoadMu sync.Mutex

// loadCA will load or create the CA at CAROOT.
//
// It must be called with the CAROOT lock held. The CA key, certificate
// and their on-disk files are handled as a single recovery transaction:
//
//   - a complete, matching key/certificate pair is loaded as-is;
//   - a certificate without a key keeps working in keyless (-install) mode;
//   - a key left behind by a creation interrupted after the key was
//     written but before the certificate made it to disk is recovered
//     into a matching certificate instead of being replaced by a new key;
//   - an empty CAROOT gets a brand-new key/certificate pair.
//
// In every case the key and certificate are written atomically, so a
// crash or a concurrent invocation can never leave a new key next to an
// old certificate or overwrite an existing CA.
func (m *mkcert) loadCA() {
	caLoadMu.Lock()
	defer caLoadMu.Unlock()

	certPath := filepath.Join(m.CAROOT, rootName)
	keyPath := filepath.Join(m.CAROOT, rootKeyName)

	certExists, err := fileExists(certPath)
	fatalIfErr(err, "failed to stat the CA certificate")
	keyExists, err := fileExists(keyPath)
	fatalIfErr(err, "failed to stat the CA key")

	switch {
	case certExists && keyExists:
		// A CA was created previously. Load it and make sure the key and
		// certificate still match, rather than silently trusting a pair
		// that got mixed up by an interrupted or concurrent creation.
		cert := loadCACertificate(certPath)
		key := loadCAKey(keyPath)
		if !keyMatchesCertificate(key, cert) {
			log.Fatalf("ERROR: the CA key (%q) and certificate (%q) do not match; refusing to modify them, please remove the stale file",
				keyPath, certPath)
		}
		m.caCert = cert
		m.caKey = key

	case certExists && !keyExists:
		// Keyless mode, where only -install works. The certificate is
		// deliberately left untouched.
		m.caCert = loadCACertificate(certPath)

	case !certExists && keyExists:
		// A previous creation was interrupted after the key was written
		// but before the certificate made it to disk. Recover the
		// orphaned key into a matching certificate so the transaction
		// completes without generating a new key.
		key := loadCAKey(keyPath)
		log.Printf("Found an orphaned CA key without a certificate, recovering it into a new CA certificate 🔧\n")
		m.cleanupCATempFiles()
		m.writeRootCertificate(key)
		m.caCert = loadCACertificate(certPath)
		m.caKey = key

	default:
		// Nothing on disk: create a brand-new CA as one atomic unit.
		m.newCA()
		m.caCert = loadCACertificate(certPath)
		m.caKey = loadCAKey(keyPath)
	}
}

func loadCACertificate(path string) *x509.Certificate {
	certPEMBlock, err := ioutil.ReadFile(path)
	fatalIfErr(err, "failed to read the CA certificate")
	certDERBlock, _ := pem.Decode(certPEMBlock)
	if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
		log.Fatalln("ERROR: failed to read the CA certificate: unexpected content")
	}
	cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA certificate")
	return cert
}

func loadCAKey(path string) crypto.PrivateKey {
	keyPEMBlock, err := ioutil.ReadFile(path)
	fatalIfErr(err, "failed to read the CA key")
	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	if keyDERBlock == nil {
		log.Fatalln("ERROR: failed to read the CA key: unexpected content")
	}
	switch keyDERBlock.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes)
		fatalIfErr(err, "failed to parse the CA key")
		return key
	case "RSA PRIVATE KEY":
		// Accept the traditional RSA encoding too. mkcert itself writes
		// PKCS #8, but an interrupted CAROOT may contain a key imported
		// from another tool, and rotating it would break the transaction.
		key, err := x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes)
		fatalIfErr(err, "failed to parse the CA key")
		return key
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(keyDERBlock.Bytes)
		fatalIfErr(err, "failed to parse the CA key")
		return key
	default:
		log.Fatalln("ERROR: failed to read the CA key: unexpected content")
		return nil
	}
}

// fileExists reports whether path exists. Errors other than "not found"
// are returned so that a temporarily unreadable CA is never mistaken for
// an empty CAROOT and overwritten.
func fileExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// keyMatchesCertificate reports whether key is the private key
// corresponding to cert's public key.
func keyMatchesCertificate(key crypto.PrivateKey, cert *x509.Certificate) bool {
	priv, ok := key.(crypto.Signer)
	if !ok {
		return false
	}
	certSPKI, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return false
	}
	keySPKI, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return false
	}
	return bytes.Equal(certSPKI, keySPKI)
}

// newCA generates a fresh CA key and certificate and commits both to
// disk atomically. Leftover temporary files from a crashed creation are
// removed first, and an existing CA is never overwritten.
func (m *mkcert) newCA() {
	certPath := filepath.Join(m.CAROOT, rootName)
	keyPath := filepath.Join(m.CAROOT, rootKeyName)

	// These checks are redundant with loadCA, but keep newCA safe if it
	// is ever called from another path: a valid CA must never be
	// replaced, and an orphaned key must be rolled forward, not rotated.
	if certExists, err := fileExists(certPath); err != nil {
		fatalIfErr(err, "failed to stat the CA certificate")
	} else if certExists {
		log.Fatalf("ERROR: refusing to overwrite the existing CA certificate %q", certPath)
	}
	if keyExists, err := fileExists(keyPath); err != nil {
		fatalIfErr(err, "failed to stat the CA key")
	} else if keyExists {
		key := loadCAKey(keyPath)
		log.Printf("Found an orphaned CA key without a certificate, recovering it into a new CA certificate 🔧\n")
		m.cleanupCATempFiles()
		m.writeRootCertificate(key)
		log.Printf("Created a new local CA 💥\n")
		return
	}

	priv, err := m.generateKey(true)
	fatalIfErr(err, "failed to generate the CA key")

	m.cleanupCATempFiles()
	m.writeRootKey(priv)
	m.writeRootCertificate(priv)

	log.Printf("Created a new local CA 💥\n")
}

// writeRootKey marshals priv and commits it to rootKeyName atomically.
func (m *mkcert) writeRootKey(priv crypto.PrivateKey) {
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	fatalIfErr(err, "failed to encode CA key")
	err = atomicWriteFile(
		filepath.Join(m.CAROOT, rootKeyName),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
		0400)
	fatalIfErr(err, "failed to save CA key")
}

// writeRootCertificate builds a self-signed root certificate for priv and
// commits it to rootName atomically. It is shared by fresh creations and
// interrupted-creation recovery.
func (m *mkcert) writeRootCertificate(priv crypto.PrivateKey) {
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

	err = atomicWriteFile(
		filepath.Join(m.CAROOT, rootName),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}),
		0644)
	fatalIfErr(err, "failed to save CA certificate")
}

// cleanupCATempFiles removes temporary files left behind by a creation
// that crashed before the atomic rename. It only touches the well-known
// mkcert temporary prefix, never user files or the committed CA.
func (m *mkcert) cleanupCATempFiles() {
	entries, err := ioutil.ReadDir(m.CAROOT)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), caTempPrefix) {
			_ = os.Remove(filepath.Join(m.CAROOT, entry.Name()))
		}
	}
}

func (m *mkcert) caUniqueName() string {
	return "mkcert development CA " + m.caCert.SerialNumber.String()
}
