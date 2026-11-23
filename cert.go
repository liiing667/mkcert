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

var errKeyCertificateMismatch = errors.New("certificate public key does not match the generated private key")

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
		log.Fatalln("ERROR: can't create new certificates because the CA certificate (rootCA.pem) is missing")
	}

	lock, err := lockOutputs(m.CAROOT)
	fatalIfErr(err, "failed to lock certificate output")
	defer lock.unlock()
	fatalIfErr(m.makeCertLocked(hosts), "failed to create certificate")
}

func (m *mkcert) makeCertLocked(hosts []string) error {
	certFile, keyFile, p12File := m.fileNames(hosts)
	outputs := []string{certFile, keyFile}
	if m.pkcs12 {
		outputs = []string{p12File}
	}
	tx, err := m.issueCertificate(hosts)
	if err != nil {
		return fmt.Errorf("failed to issue certificate: %w", err)
	}
	if err := tx.write(outputs); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}
	defer tx.cleanup()

	// Verify the artifact that an importing consumer will actually parse. This
	// happens before the transaction is committed, so an encoding/write failure
	// cannot leave a key, leaf or CA chain from a different generation behind.
	if err := tx.verify(m.pkcs12, m.caCert); err != nil {
		return err
	}
	if err := tx.commit(); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}
	// The transaction has committed, so deferred cleanup must not remove a
	// published destination. Future errors after this point do not roll back.
	tx.files = nil

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

	log.Printf("It will expire on %s 🗓\n\n", tx.expiration.Format("2 January 2006"))
}

// certificateTransaction bundles every object and encoded artifact produced
// for one certificate generation. None of its outputs become visible until
// commit succeeds, so retries always replace the whole previous generation
// rather than mixing an old key with a new leaf.
type certificateTransaction struct {
	key  crypto.PrivateKey
	leaf *x509.Certificate

	expiration time.Time

	certPEM []byte
	keyPEM  []byte
	p12     []byte

	files []atomicOutputFile
}

func (m *mkcert) issueCertificate(hosts []string) (*certificateTransaction, error) {
	priv, err := m.generateKey(false)
	if err != nil {
		return nil, err
	}
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

	certDER, err := x509.CreateCertificate(rand.Reader, tpl, m.caCert, pub, m.caKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	if !publicKeysEqual(leaf.PublicKey, pub) {
		return nil, errKeyCertificateMismatch
	}

	tx := &certificateTransaction{key: priv, leaf: leaf, expiration: expiration}
	tx.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	tx.keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if m.pkcs12 {
		tx.p12, err = pkcs12.Encode(rand.Reader, priv, leaf, []*x509.Certificate{m.caCert}, "changeit")
		if err != nil {
			return nil, err
		}
	}

	return tx, nil
}

func (tx *certificateTransaction) write(outputs []string) error {
	if tx == nil || len(outputs) == 0 {
		return errors.New("no certificate output files")
	}

	if len(outputs) == 1 {
		if len(tx.p12) == 0 {
			return errors.New("PKCS#12 data was not generated")
		}
		tx.files = []atomicOutputFile{{path: outputs[0], data: tx.p12, perm: 0644}}
	} else {
		certFile, keyFile := outputs[0], outputs[1]
		if certFile == keyFile {
			data := make([]byte, 0, len(tx.certPEM)+len(tx.keyPEM))
			data = append(data, tx.certPEM...)
			data = append(data, tx.keyPEM...)
			tx.files = []atomicOutputFile{{path: keyFile, data: data, perm: 0600}}
		} else {
			tx.files = []atomicOutputFile{
				{path: certFile, data: tx.certPEM, perm: 0644},
				{path: keyFile, data: tx.keyPEM, perm: 0600},
			}
		}
	}

	for i := range tx.files {
		if err := writeAtomicFile(&tx.files[i]); err != nil {
			tx.cleanup()
			return err
		}
	}
	return nil
}

func (tx *certificateTransaction) commit() error {
	if len(tx.files) == 0 {
		return errors.New("certificate transaction was not written")
	}
	for i := range tx.files {
		if err := tx.files[i].commit(); err != nil {
			for j := i - 1; j >= 0; j-- {
				tx.files[j].rollback()
			}
			return err
		}
	}
	return nil
}

func (tx *certificateTransaction) cleanup() {
	for i := range tx.files {
		tx.files[i].cleanup()
	}
}

func (tx *certificateTransaction) verify(p12 bool, ca *x509.Certificate) error {
	if !publicKeysEqual(tx.key.(crypto.Signer).Public(), tx.leaf.PublicKey) {
		return errKeyCertificateMismatch
	}
	if err := tx.leaf.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("leaf is not signed by the transaction CA: %w", err)
	}
	if p12 {
		parsedKey, parsedCert, parsedCA, err := pkcs12.DecodeChain(tx.p12, "changeit")
		if err != nil {
			return fmt.Errorf("failed to verify PKCS#12: %w", err)
		}
		signer, ok := parsedKey.(crypto.Signer)
		if !ok {
			return fmt.Errorf("failed to verify PKCS#12: parsed key type %T cannot sign", parsedKey)
		}
		if !publicKeysEqual(signer.Public(), tx.leaf.PublicKey) {
			return fmt.Errorf("failed to verify PKCS#12: %w", errKeyCertificateMismatch)
		}
		if !parsedCert.Equal(tx.leaf) || len(parsedCA) != 1 || !parsedCA[0].Equal(ca) {
			return errors.New("failed to verify PKCS#12: certificate or CA chain changed within the issuance transaction")
		}
	}
	return nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	aBytes, aErr := x509.MarshalPKIXPublicKey(a)
	bBytes, bErr := x509.MarshalPKIXPublicKey(b)
	return aErr == nil && bErr == nil && string(aBytes) == string(bBytes)
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

// loadCA will load or create the CA at CAROOT.
func (m *mkcert) loadCA() {
	if !pathExists(filepath.Join(m.CAROOT, rootName)) {
		m.newCA()
	}

	certPEMBlock, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read the CA certificate")
	certDERBlock, _ := pem.Decode(certPEMBlock)
	if certDERBlock == nil || certDERBlock.Type != "CERTIFICATE" {
		log.Fatalln("ERROR: failed to read the CA certificate: unexpected content")
	}
	m.caCert, err = x509.ParseCertificate(certDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA certificate")

	if !pathExists(filepath.Join(m.CAROOT, rootKeyName)) {
		return // keyless mode, where only -install works
	}

	keyPEMBlock, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootKeyName))
	fatalIfErr(err, "failed to read the CA key")
	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	if keyDERBlock == nil || keyDERBlock.Type != "PRIVATE KEY" {
		log.Fatalln("ERROR: failed to read the CA key: unexpected content")
	}
	m.caKey, err = x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes)
	fatalIfErr(err, "failed to parse the CA key")
}

func (m *mkcert) newCA() {
	priv, err := m.generateKey(true)
	fatalIfErr(err, "failed to generate the CA key")
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
	err = ioutil.WriteFile(filepath.Join(m.CAROOT, rootKeyName), pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0400)
	fatalIfErr(err, "failed to save CA key")

	err = ioutil.WriteFile(filepath.Join(m.CAROOT, rootName), pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
	fatalIfErr(err, "failed to save CA certificate")

	log.Printf("Created a new local CA 💥\n")
}

func (m *mkcert) caUniqueName() string {
	return "mkcert development CA " + m.caCert.SerialNumber.String()
}
