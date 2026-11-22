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

	"golang.org/x/net/idna"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

var userAndHostname string

type sanKind uint8

const (
	sanDNS sanKind = iota
	sanIP
	sanEmail
	sanURI
)

// hostIdentity is the canonical form of one subject alternative name. It is
// computed once from the command line input and then used for the certificate,
// the output file names, and everything we print to the user.
type hostIdentity struct {
	kind  sanKind
	value string
	ip    net.IP
	uri   *url.URL
}

func (h hostIdentity) key() string {
	return strconv.Itoa(int(h.kind)) + ":" + h.value
}

var dnsIDNA = idna.New(
	idna.MapForLookup(),
	// mkcert has always accepted names used by development servers, such as
	// _service._tcp.localhost, which are not valid under the strict DNS
	// rules.
	idna.StrictDomainName(false),
	idna.Transitional(false),
	// UTS #46 reserves "--" in positions 3 and 4 for A-labels, but plain DNS
	// labels are allowed to contain it. Keep accepting those legacy labels;
	// the checks below still reject invalid A-labels and empty labels.
	idna.CheckHyphens(false),
	idna.BidiRule(),
	idna.VerifyDNSLength(true),
)

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
	identities, err := parseHostIdentities(hosts)
	if err != nil {
		log.Fatalf("ERROR: %v", err)
	}
	m.makeCertForIdentities(identities)
}

func (m *mkcert) makeCertForIdentities(hosts []hostIdentity) {
	if m.caKey == nil {
		log.Fatalln("ERROR: can't create new certificates because the CA key (rootCA-key.pem) is missing")
	}
	if len(hosts) == 0 {
		log.Fatalln("ERROR: no hosts specified")
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

	applyHostIdentities(tpl, hosts)

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
		tpl.Subject.CommonName = hosts[0].value
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, m.caCert, pub, m.caKey)
	fatalIfErr(err, "failed to generate certificate")

	certFile, keyFile, p12File := m.fileNamesForIdentities(hosts)

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

	m.printHostIdentities(hosts)

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
	m.printHostIdentities(hostIdentities(hosts))
}

func (m *mkcert) printHostIdentities(hosts []hostIdentity) {
	secondLvlWildcardRegexp := regexp.MustCompile(`(?i)^\*\.[0-9a-z_-]+$`)
	log.Printf("\nCreated a new certificate valid for the following names 📜")
	for _, h := range hosts {
		log.Printf(" - %q", h.value)
		if secondLvlWildcardRegexp.MatchString(h.value) {
			log.Printf("   Warning: many browsers don't support second-level wildcards like %q ⚠️", h.value)
		}
	}

	for _, h := range hosts {
		if strings.HasPrefix(h.value, "*.") {
			log.Printf("\nReminder: X.509 wildcards only go one level deep, so this won't match a.b.%s ℹ️", h.value[2:])
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
	return m.fileNamesForIdentities(hostIdentities(hosts))
}

func (m *mkcert) fileNamesForIdentities(hosts []hostIdentity) (certFile, keyFile, p12File string) {
	defaultName := ""
	if len(hosts) > 0 {
		defaultName = outputFileName(hosts[0].value)
	}
	if len(hosts) > 1 {
		defaultName += "+" + strconv.Itoa(len(hosts)-1)
	}
	if m.client {
		defaultName += "-client"
	}
	if defaultName == "" {
		defaultName = "cert"
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

// hostIdentities canonicalizes hosts for callers that need the same naming
// rules as makeCert but do not have a place to report an error.
func hostIdentities(hosts []string) []hostIdentity {
	identities := make([]hostIdentity, 0, len(hosts))
	for _, host := range hosts {
		identity, err := parseHostIdentity(host)
		if err != nil {
			// This path is only used for values that came from a certificate
			// or CSR and were already validated by the X.509 parser. Keep the
			// value rather than losing it if it uses an unusual legacy form.
			identity = hostIdentity{kind: sanDNS, value: host}
		}
		identities = append(identities, identity)
	}
	return dedupeHostIdentities(identities)
}

func parseHostIdentities(hosts []string) ([]hostIdentity, error) {
	identities := make([]hostIdentity, 0, len(hosts))
	for _, host := range hosts {
		identity, err := parseHostIdentity(host)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	identities = dedupeHostIdentities(identities)
	if len(identities) == 0 {
		return nil, fmt.Errorf("no hosts specified")
	}
	return identities, nil
}

func dedupeHostIdentities(hosts []hostIdentity) []hostIdentity {
	identities := make([]hostIdentity, 0, len(hosts))
	seen := make(map[string]bool, len(hosts))
	for _, identity := range hosts {
		if seen[identity.key()] {
			continue
		}
		seen[identity.key()] = true
		identities = append(identities, identity)
	}
	return identities
}

func applyHostIdentities(tpl *x509.Certificate, hosts []hostIdentity) {
	for _, h := range hosts {
		switch h.kind {
		case sanDNS:
			tpl.DNSNames = append(tpl.DNSNames, h.value)
		case sanIP:
			tpl.IPAddresses = append(tpl.IPAddresses, h.ip)
		case sanEmail:
			tpl.EmailAddresses = append(tpl.EmailAddresses, h.value)
		case sanURI:
			tpl.URIs = append(tpl.URIs, h.uri)
		}
	}
}

func parseHostIdentity(host string) (hostIdentity, error) {
	if identity, ok := parseIPIdentity(host); ok {
		return identity, nil
	}
	if identity, ok := parseEmailIdentity(host); ok {
		return identity, nil
	}
	if identity, ok := parseURIIdentity(host); ok {
		return identity, nil
	}
	if name, err := canonicalDNSName(host); err == nil {
		// IDNA mapping can turn width variants into an IP address. Classify
		// the canonical form, not the input spelling, so an IP consumer and
		// the SAN agree.
		if ip := net.ParseIP(name); ip != nil {
			value := ip.String()
			return hostIdentity{kind: sanIP, value: value, ip: net.ParseIP(value)}, nil
		}
		return hostIdentity{kind: sanDNS, value: name}, nil
	}
	return hostIdentity{}, fmt.Errorf("%q is not a valid hostname, IP, URL or email", host)
}

func parseIPIdentity(host string) (hostIdentity, bool) {
	candidate := host
	if strings.HasSuffix(candidate, ".") {
		candidate = strings.TrimSuffix(candidate, ".")
	}
	if len(candidate) >= 2 && candidate[0] == '[' && candidate[len(candidate)-1] == ']' {
		candidate = candidate[1 : len(candidate)-1]
	}
	ip := net.ParseIP(candidate)
	if ip == nil {
		return hostIdentity{}, false
	}
	value := ip.String()
	return hostIdentity{kind: sanIP, value: value, ip: net.ParseIP(value)}, true
}

func parseEmailIdentity(host string) (hostIdentity, bool) {
	if email, err := mail.ParseAddress(host); err == nil && email.Address == host {
		if value, err := canonicalEmailAddress(host); err == nil {
			return hostIdentity{kind: sanEmail, value: value}, true
		}
	}

	// net/mail only accepts ASCII domains. Accept the SMTPUTF8 form when the
	// rest of the address is already valid, and canonicalize its IDN domain.
	// Also handle a trailing root dot, which is valid for a DNS name but not
	// accepted by net/mail's dot-atom parser.
	local, domain, ok := splitEmailAddress(host)
	if !ok || (isASCII(domain) && !strings.HasSuffix(domain, ".") && !strings.HasPrefix(domain, "[")) {
		return hostIdentity{}, false
	}
	value, err := canonicalEmailAddress(local + "@" + domain)
	if err != nil {
		return hostIdentity{}, false
	}
	return hostIdentity{kind: sanEmail, value: value}, true
}

func splitEmailAddress(address string) (local, domain string, ok bool) {
	at := strings.LastIndexByte(address, '@')
	if at <= 0 || at == len(address)-1 {
		return "", "", false
	}
	local, domain = address[:at], address[at+1:]
	if strings.ContainsAny(local, "\r\n\t ") {
		return "", "", false
	}
	// This rejects URL-shaped strings such as https://user@example.com while
	// still allowing quoted local parts.
	if parsed, err := mail.ParseAddress(local + "@example.invalid"); err != nil || parsed.Address != local+"@example.invalid" {
		return "", "", false
	}
	return local, domain, true
}

func canonicalEmailAddress(address string) (string, error) {
	local, domain, ok := splitEmailAddress(address)
	if !ok {
		return "", fmt.Errorf("%q is not a valid email address", address)
	}
	if strings.HasPrefix(domain, "[") && strings.HasSuffix(domain, "]") {
		literal := domain[1 : len(domain)-1]
		prefix := ""
		if len(literal) >= len("IPv6:") && strings.EqualFold(literal[:len("IPv6:")], "IPv6:") {
			prefix = "IPv6:"
			literal = literal[len("IPv6:"):]
		}
		ip := net.ParseIP(literal)
		if ip == nil {
			return "", fmt.Errorf("%q is not a valid email address", address)
		}
		return local + "@[" + prefix + ip.String() + "]", nil
	}
	if strings.Contains(domain, "*") {
		return "", fmt.Errorf("%q is not a valid email address", address)
	}
	name, err := canonicalDNSName(domain)
	if err != nil {
		return "", err
	}
	return local + "@" + name, nil
}

func parseURIIdentity(host string) (hostIdentity, bool) {
	uri, err := url.Parse(host)
	if err != nil || uri.Scheme == "" || uri.Host == "" || uri.Opaque != "" {
		return hostIdentity{}, false
	}
	uri, err = canonicalURI(uri)
	if err != nil {
		return hostIdentity{}, false
	}
	return hostIdentity{kind: sanURI, value: uri.String(), uri: uri}, true
}

func canonicalURI(uri *url.URL) (*url.URL, error) {
	canonical := *uri
	canonical.Scheme = strings.ToLower(canonical.Scheme)
	hostname := canonical.Hostname()
	if hostname == "" {
		return nil, fmt.Errorf("URI has no host")
	}
	if strings.Contains(hostname, "*") {
		return nil, fmt.Errorf("URI host must not contain a wildcard")
	}

	ipCandidate := hostname
	zone := ""
	if i := strings.LastIndexByte(ipCandidate, '%'); i != -1 {
		zone = ipCandidate[i+1:]
		ipCandidate = ipCandidate[:i]
	}
	if strings.HasSuffix(ipCandidate, ".") {
		ipCandidate = strings.TrimSuffix(ipCandidate, ".")
	}
	var canonicalHost string
	if ip := net.ParseIP(ipCandidate); ip != nil {
		canonicalHost = ip.String()
		if zone != "" {
			canonicalHost += "%" + zone
		}
	} else {
		if zone != "" {
			return nil, fmt.Errorf("invalid URI host")
		}
		var err error
		canonicalHost, err = canonicalDNSName(hostname)
		if err != nil {
			return nil, err
		}
	}

	if port := canonical.Port(); port != "" {
		canonical.Host = net.JoinHostPort(canonicalHost, port)
	} else if strings.Contains(canonicalHost, ":") {
		canonical.Host = "[" + canonicalHost + "]"
	} else {
		canonical.Host = canonicalHost
	}
	return &canonical, nil
}

func canonicalDNSName(name string) (string, error) {
	// UTS #46 treats these as label separators, but the Punycode profile used
	// by idna.ToASCII historically did not. Normalize them up front so that
	// all spellings of a name share one identity.
	name = strings.NewReplacer(
		"\u3002", ".",
		"\uff0e", ".",
		"\uff61", ".",
	).Replace(name)
	if name == "" {
		return "", fmt.Errorf("empty DNS name")
	}
	if strings.HasSuffix(name, ".") {
		name = strings.TrimSuffix(name, ".")
	}
	if name == "" || strings.HasSuffix(name, ".") {
		return "", fmt.Errorf("invalid DNS name")
	}

	wildcard := false
	if strings.Contains(name, "*") {
		if !strings.HasPrefix(name, "*.") || strings.Count(name, "*") != 1 {
			return "", fmt.Errorf("wildcard must be the entire left-most label")
		}
		wildcard = true
		name = name[len("*."):]
		if name == "" {
			return "", fmt.Errorf("wildcard has no domain")
		}
	}

	ascii, err := dnsIDNA.ToASCII(name)
	if err != nil {
		return "", err
	}
	ascii = strings.ToLower(ascii)
	if err := validateASCIIDNSName(ascii); err != nil {
		return "", err
	}
	if wildcard {
		ascii = "*." + ascii
		if len(ascii) > 253 {
			return "", fmt.Errorf("DNS name is too long")
		}
	}
	return ascii, nil
}

func validateASCIIDNSName(name string) error {
	if name == "" || len(name) > 253 {
		return fmt.Errorf("invalid DNS name")
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("invalid DNS label")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid DNS label")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_' {
				continue
			}
			return fmt.Errorf("invalid DNS label")
		}
	}
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func outputFileName(name string) string {
	name = strings.ReplaceAll(name, "*", "_wildcard")
	var b strings.Builder
	for _, r := range name {
		switch r {
		case '/', '\\', ':', '?', '"', '<', '>', '|':
			b.WriteByte('_')
		default:
			if r < 0x20 || r == 0x7f {
				b.WriteByte('_')
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
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
	if err := validateCSRSANs(csr); err != nil {
		log.Fatalf("ERROR: %v", err)
	}
	csrIdentities, hasCSRSAN, replaceCSRSAN := certificateRequestIdentities(csr)
	hosts := csrIdentities
	if !hasCSRSAN {
		commonName, err := dnsCSRSANIdentity(csr.Subject.CommonName)
		if err != nil {
			log.Fatalf("ERROR: invalid Common Name %q in CSR", csr.Subject.CommonName)
		}
		hosts = []hostIdentity{commonName}
	}

	expiration := time.Now().AddDate(2, 3, 0)
	tpl := &x509.Certificate{
		SerialNumber:    randomSerialNumber(),
		Subject:         csr.Subject,
		ExtraExtensions: csrExtensionsWithoutSAN(csr, replaceCSRSAN),

		NotBefore: time.Now(), NotAfter: expiration,

		// Likewise, if the CSR does not set KUs and EKUs, fix it up as Apple
		// platforms require serverAuth for TLS.
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if replaceCSRSAN {
		// Use the same canonical identities for CSR-issued certificates as
		// for certificates built directly from command-line hosts.
		applyHostIdentities(tpl, hosts)
	} else if !hasCSRSAN {
		// If the CSR does not request a SAN extension, fix it up for them as
		// the Common Name field does not work in modern browsers.
		tpl.DNSNames = []string{hosts[0].value}
	}

	if m.client {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if len(csr.EmailAddresses) > 0 {
		tpl.ExtKeyUsage = append(tpl.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, m.caCert, csr.PublicKey, m.caKey)
	fatalIfErr(err, "failed to generate certificate")
	_, err = x509.ParseCertificate(cert)
	fatalIfErr(err, "failed to parse generated certificate")

	certFile, _, _ := m.fileNamesForIdentities(hosts)

	err = ioutil.WriteFile(certFile, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
	fatalIfErr(err, "failed to save certificate")

	m.printHostIdentities(hosts)

	log.Printf("\nThe certificate is at \"%s\" ✅\n\n", certFile)

	log.Printf("It will expire on %s 🗓\n\n", expiration.Format("2 January 2006"))
}

var subjectAltNameOID = asn1.ObjectIdentifier{2, 5, 29, 17}

func csrExtensionsWithoutSAN(csr *x509.CertificateRequest, removeSAN bool) []pkix.Extension {
	if !removeSAN {
		return csr.Extensions
	}
	extensions := make([]pkix.Extension, 0, len(csr.Extensions))
	for _, extension := range csr.Extensions {
		if extension.Id.Equal(subjectAltNameOID) {
			continue
		}
		extensions = append(extensions, extension)
	}
	return extensions
}

func certificateRequestIdentities(csr *x509.CertificateRequest) ([]hostIdentity, bool, bool) {
	hasSAN := false
	for _, extension := range csr.Extensions {
		if extension.Id.Equal(subjectAltNameOID) {
			hasSAN = true
			break
		}
	}
	if !hasSAN {
		return nil, false, false
	}

	identities := make([]hostIdentity, 0,
		len(csr.DNSNames)+len(csr.EmailAddresses)+len(csr.IPAddresses)+len(csr.URIs))
	seen := make(map[string]bool, cap(identities))
	rewrite := false
	add := func(identity hostIdentity, raw string) {
		if identity.value != raw || seen[identity.key()] {
			rewrite = true
		}
		seen[identity.key()] = true
		identities = append(identities, identity)
	}
	for _, name := range csr.DNSNames {
		identity, _ := dnsCSRSANIdentity(name)
		add(identity, name)
	}
	for _, address := range csr.EmailAddresses {
		identity := hostIdentity{kind: sanEmail, value: address}
		if canonical, err := canonicalEmailAddress(address); err == nil {
			identity.value = canonical
		}
		add(identity, address)
	}
	for _, ip := range csr.IPAddresses {
		value := ip.String()
		add(hostIdentity{
			kind: sanIP, value: value, ip: net.ParseIP(value),
		}, value)
	}
	for _, uri := range csr.URIs {
		identity := hostIdentity{kind: sanURI, value: uri.String(), uri: uri}
		if uri.Host != "" {
			if canonical, err := canonicalURI(uri); err == nil {
				identity.value = canonical.String()
				identity.uri = canonical
			}
		}
		add(identity, uri.String())
	}
	return dedupeHostIdentities(identities), true, rewrite
}

func dnsCSRSANIdentity(name string) (hostIdentity, error) {
	identity := hostIdentity{kind: sanDNS, value: name}
	canonical, err := canonicalDNSName(name)
	if err != nil {
		// Keep old non-wildcard SAN spellings that IDNA cannot represent,
		// but never preserve a wildcard that does not occupy exactly the
		// left-most label.
		if strings.Contains(name, "*") {
			return identity, err
		}
		return identity, nil
	}
	identity.value = canonical
	return identity, nil
}

func validateCSRSANs(csr *x509.CertificateRequest) error {
	for _, name := range csr.DNSNames {
		if name == "" {
			return fmt.Errorf("invalid DNS SAN in CSR")
		}
		// Preserve legacy SAN spellings, but never pass a wildcard that
		// spans more than the complete left-most label into the certificate.
		if strings.Contains(name, "*") {
			if _, err := canonicalDNSName(name); err != nil {
				return fmt.Errorf("invalid DNS SAN %q in CSR", name)
			}
		}
	}
	for _, address := range csr.EmailAddresses {
		at := strings.LastIndexByte(address, '@')
		if at <= 0 || at == len(address)-1 {
			return fmt.Errorf("invalid email SAN %q in CSR", address)
		}
		if strings.Contains(address[at+1:], "*") {
			return fmt.Errorf("invalid email SAN %q in CSR", address)
		}
	}
	for _, uri := range csr.URIs {
		if strings.Contains(uri.Hostname(), "*") {
			return fmt.Errorf("invalid URI SAN %q in CSR", uri)
		}
	}
	return nil
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
