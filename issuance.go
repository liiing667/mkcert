// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
	"time"
)

var (
	oidMkcertSubjectAltName          = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidMkcertBasicConstraints        = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidMkcertKeyUsage                = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidMkcertExtendedKeyUsage        = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidMkcertNameConstraints         = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidMkcertPolicyConstraints       = asn1.ObjectIdentifier{2, 5, 29, 36}
	oidMkcertInhibitAnyPolicy        = asn1.ObjectIdentifier{2, 5, 29, 54}
	oidMkcertPolicyMappings          = asn1.ObjectIdentifier{2, 5, 29, 33}
	oidMkcertIssuerAltName           = asn1.ObjectIdentifier{2, 5, 29, 18}
	oidMkcertSubjectKeyIdentifier    = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidMkcertAuthorityKeyIdentifier  = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidMkcertAuthorityInfoAccess     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidMkcertSubjectInfoAccess       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11}
	oidMkcertExtKeyUsageAny          = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidMkcertExtKeyUsageServerAuth   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidMkcertExtKeyUsageClientAuth   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidMkcertExtKeyUsageEmailProtect = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
)

const (
	defaultLeafKeyUsage x509.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	allowedLeafKeyUsage x509.KeyUsage = x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageEncipherOnly |
		x509.KeyUsageDecipherOnly
)

type forbiddenCSRExtension struct {
	oid  asn1.ObjectIdentifier
	name string
}

var forbiddenCSRExtensions = []forbiddenCSRExtension{
	{oidMkcertNameConstraints, "nameConstraints"},
	{oidMkcertPolicyConstraints, "policyConstraints"},
	{oidMkcertInhibitAnyPolicy, "inhibitAnyPolicy"},
	{oidMkcertPolicyMappings, "policyMappings"},
}

// These extensions are issuer-controlled metadata. A CSR cannot choose them,
// but they do not grant a capability, so they are ignored rather than turned
// into an incompatibility for an otherwise valid legacy request.
var ignoredCSRExtensions = []asn1.ObjectIdentifier{
	oidMkcertIssuerAltName,
	oidMkcertSubjectKeyIdentifier,
	oidMkcertAuthorityKeyIdentifier,
	oidMkcertAuthorityInfoAccess,
	oidMkcertSubjectInfoAccess,
}

// The issuer derives Authority Key Identifier from the CA's Subject Key
// Identifier, so that extension is allowed in the signed leaf even though a
// requested Authority Key Identifier is ignored in the CSR.
var forbiddenIssuedExtensions = []asn1.ObjectIdentifier{
	oidMkcertNameConstraints,
	oidMkcertPolicyConstraints,
	oidMkcertInhibitAnyPolicy,
	oidMkcertPolicyMappings,
	oidMkcertIssuerAltName,
	oidMkcertSubjectKeyIdentifier,
	oidMkcertAuthorityInfoAccess,
	oidMkcertSubjectInfoAccess,
}

var leafKeyUsageBits = []struct {
	bit   int
	usage x509.KeyUsage
}{
	{0, x509.KeyUsageDigitalSignature},
	{1, x509.KeyUsageContentCommitment},
	{2, x509.KeyUsageKeyEncipherment},
	{3, x509.KeyUsageDataEncipherment},
	{4, x509.KeyUsageKeyAgreement},
	// Bits 5 and 6 are keyCertSign and cRLSign. A leaf certificate must never
	// receive them from an external CSR.
	{7, x509.KeyUsageEncipherOnly},
	{8, x509.KeyUsageDecipherOnly},
}

var allowedCSRExtKeyUsages = []struct {
	oid   asn1.ObjectIdentifier
	usage x509.ExtKeyUsage
}{
	{oidMkcertExtKeyUsageServerAuth, x509.ExtKeyUsageServerAuth},
	{oidMkcertExtKeyUsageClientAuth, x509.ExtKeyUsageClientAuth},
	{oidMkcertExtKeyUsageEmailProtect, x509.ExtKeyUsageEmailProtection},
}

// csrRequestProfile is the static part of one issuance authorization. It is
// derived only from the CSR and the command flags; no CA key material is
// touched while it is being built.
type csrRequestProfile struct {
	subject         pkix.Name
	dnsNames        []string
	emailAddresses  []string
	ipAddresses     []net.IP
	uris            []*url.URL
	keyUsage        x509.KeyUsage
	extKeyUsage     []x509.ExtKeyUsage
	extraExtensions []pkix.Extension
	basicConstraints bool
}

// leafCertificateProfile is the complete authorization for one leaf
// certificate. It combines the authorized CSR request with the CA validity
// window. Every value written to the certificate comes from this profile, and
// the signed certificate is checked against it before it is written.
type leafCertificateProfile struct {
	csrRequestProfile
	notBefore time.Time
	notAfter  time.Time
}

func (m *mkcert) prepareCSRIssuance() {
	csr := m.readAndVerifyCSR()
	request, err := m.analyzeCSRRequest(csr)
	fatalIfErr(err, "refusing to authorize CSR")
	m.csr = csr
	m.csrRequest = request
	m.csrSource = m.csrPath
}

// analyzeCSRRequest classifies every requested extension before any CA key is
// read. Unauthorized capabilities are rejected. Legal SAN/KU/EKU values are
// translated into the leaf profile, while unknown non-critical extensions are
// passed through unchanged.
func (m *mkcert) analyzeCSRRequest(csr *x509.CertificateRequest) (*csrRequestProfile, error) {
	if csr == nil {
		return nil, fmt.Errorf("missing certificate request")
	}

	request := &csrRequestProfile{
		subject:        csr.Subject,
		dnsNames:       append([]string(nil), csr.DNSNames...),
		emailAddresses: append([]string(nil), csr.EmailAddresses...),
		ipAddresses:    append([]net.IP(nil), csr.IPAddresses...),
		uris:           append([]*url.URL(nil), csr.URIs...),
	}

	hasParsedSAN := len(request.dnsNames) > 0 ||
		len(request.emailAddresses) > 0 ||
		len(request.ipAddresses) > 0 ||
		len(request.uris) > 0
	if !hasParsedSAN && csr.Subject.CommonName != "" {
		// Preserve mkcert's historical behaviour of using the Common Name
		// when the CSR does not contain a usable subject alternative name.
		request.dnsNames = []string{csr.Subject.CommonName}
	}
	keyUsageRequested := false
	var requestedKeyUsage x509.KeyUsage
	extKeyUsageRequested := false
	var requestedExtKeyUsage []x509.ExtKeyUsage
	seenExtKeyUsage := make(map[x509.ExtKeyUsage]bool)

	for _, extension := range csr.Extensions {
		switch {
		case extension.Id.Equal(oidMkcertSubjectAltName):
			// Rebuilt from the parsed SAN fields above. This also prevents
			// duplicate or raw SAN extensions from bypassing the profile.
			continue
		case extension.Id.Equal(oidMkcertBasicConstraints):
			if err := validateCSRBasicConstraints(extension); err != nil {
				return nil, err
			}
			request.basicConstraints = true
			continue
		case extension.Id.Equal(oidMkcertKeyUsage):
			keyUsageRequested = true
			usage, err := parseCSRKeyUsage(extension)
			if err != nil {
				return nil, fmt.Errorf("the CSR key usage (2.5.29.15): %v", err)
			}
			requestedKeyUsage |= usage
			continue
		case extension.Id.Equal(oidMkcertExtendedKeyUsage):
			extKeyUsageRequested = true
			usages, err := parseCSRExtKeyUsage(extension)
			if err != nil {
				return nil, fmt.Errorf("the CSR extended key usage (2.5.29.37): %v", err)
			}
			for _, usage := range usages {
				if !seenExtKeyUsage[usage] {
					seenExtKeyUsage[usage] = true
					requestedExtKeyUsage = append(requestedExtKeyUsage, usage)
				}
			}
			continue
		}

		if name, ok := forbiddenCSRExtensionName(extension.Id); ok {
			return nil, fmt.Errorf("the CSR requests unauthorized %s extension (%s)", name, extension.Id)
		}
		if isIgnoredCSRExtension(extension.Id) {
			if extension.Critical {
				return nil, fmt.Errorf("the CSR requests an unsupported critical extension (%s)", extension.Id)
			}
			continue
		}
		if extension.Critical {
			return nil, fmt.Errorf("the CSR requests unknown critical extension (%s)", extension.Id)
		}
		request.extraExtensions = append(request.extraExtensions,
			cloneCSRExtension(extension))
	}

	if len(request.dnsNames) == 0 &&
		len(request.emailAddresses) == 0 &&
		len(request.ipAddresses) == 0 &&
		len(request.uris) == 0 {
		return nil, fmt.Errorf("the CSR does not contain a subject alternative name or Common Name")
	}

	request.keyUsage = defaultLeafKeyUsage
	if keyUsageRequested {
		if requestedKeyUsage == 0 {
			return nil, fmt.Errorf("the CSR key usage has no authorized leaf capability")
		}
		request.keyUsage = requestedKeyUsage & allowedLeafKeyUsage
	}

	request.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if extKeyUsageRequested {
		if len(requestedExtKeyUsage) == 0 {
			return nil, fmt.Errorf("the CSR extended key usage has no authorized purpose")
		}
		request.extKeyUsage = canonicalExtKeyUsage(requestedExtKeyUsage)
	}
	if m != nil && m.client &&
		!profileHasExtKeyUsage(request.extKeyUsage, x509.ExtKeyUsageClientAuth) {
		request.extKeyUsage = append(request.extKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if len(request.emailAddresses) > 0 &&
		!profileHasExtKeyUsage(request.extKeyUsage, x509.ExtKeyUsageEmailProtection) {
		request.extKeyUsage = append(request.extKeyUsage, x509.ExtKeyUsageEmailProtection)
	}
	request.extKeyUsage = canonicalExtKeyUsage(request.extKeyUsage)

	return request, nil
}

func validateCSRBasicConstraints(extension pkix.Extension) error {
	var constraints struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional"`
	}
	rest, err := asn1.Unmarshal(extension.Value, &constraints)
	if err != nil {
		return fmt.Errorf("invalid basicConstraints in CSR: %v", err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("invalid basicConstraints in CSR: trailing data")
	}
	if constraints.IsCA {
		return fmt.Errorf("the CSR requests unauthorized basicConstraints with CA=true (2.5.29.19)")
	}
	if constraints.MaxPathLen != 0 {
		return fmt.Errorf("the CSR requests unauthorized basicConstraints pathLenConstraint (2.5.29.19)")
	}
	// A CA=false request with no path length is harmless and is translated to
	// the issuer-owned leaf profile. Any path length request is rejected above.
	return nil
}

func parseCSRKeyUsage(extension pkix.Extension) (x509.KeyUsage, error) {
	var bits asn1.BitString
	rest, err := asn1.Unmarshal(extension.Value, &bits)
	if err != nil {
		return 0, err
	}
	if len(rest) != 0 {
		return 0, fmt.Errorf("trailing data after key usage")
	}

	if bitStringSet(bits, 5) {
		return 0, fmt.Errorf("keyCertSign is not allowed for a leaf certificate")
	}
	if bitStringSet(bits, 6) {
		return 0, fmt.Errorf("cRLSign is not allowed for a leaf certificate")
	}
	for bit := 9; bit < bits.BitLength; bit++ {
		if bitStringSet(bits, bit) {
			return 0, fmt.Errorf("unsupported key usage bit %d", bit)
		}
	}

	var usage x509.KeyUsage
	for _, candidate := range leafKeyUsageBits {
		if bitStringSet(bits, candidate.bit) {
			usage |= candidate.usage
		}
	}
	if usage == 0 {
		return 0, fmt.Errorf("no authorized leaf key usage bit is set")
	}
	return usage, nil
}

func bitStringSet(bits asn1.BitString, index int) bool {
	return index >= 0 && index < bits.BitLength && bits.At(index) != 0
}

func parseCSRExtKeyUsage(extension pkix.Extension) ([]x509.ExtKeyUsage, error) {
	var oids []asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(extension.Value, &oids)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after extended key usage")
	}
	if len(oids) == 0 {
		return nil, fmt.Errorf("extended key usage is empty")
	}

	var usages []x509.ExtKeyUsage
	for _, oid := range oids {
		if oid.Equal(oidMkcertExtKeyUsageAny) {
			return nil, fmt.Errorf("anyExtendedKeyUsage (2.5.29.37.0) is not allowed")
		}
		found := false
		for _, allowed := range allowedCSRExtKeyUsages {
			if oid.Equal(allowed.oid) {
				usages = append(usages, allowed.usage)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unsupported extended key usage OID %s", oid)
		}
	}
	return usages, nil
}

func profileHasExtKeyUsage(usages []x509.ExtKeyUsage, want x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == want {
			return true
		}
	}
	return false
}

func canonicalExtKeyUsage(usages []x509.ExtKeyUsage) []x509.ExtKeyUsage {
	var canonical []x509.ExtKeyUsage
	for _, usage := range []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageEmailProtection,
	} {
		if profileHasExtKeyUsage(usages, usage) {
			canonical = append(canonical, usage)
		}
	}
	return canonical
}

func forbiddenCSRExtensionName(oid asn1.ObjectIdentifier) (string, bool) {
	for _, forbidden := range forbiddenCSRExtensions {
		if oid.Equal(forbidden.oid) {
			return forbidden.name, true
		}
	}
	return "", false
}

func isIgnoredCSRExtension(oid asn1.ObjectIdentifier) bool {
	for _, ignored := range ignoredCSRExtensions {
		if oid.Equal(ignored) {
			return true
		}
	}
	return false
}

func isForbiddenIssuedExtension(oid asn1.ObjectIdentifier) bool {
	for _, forbidden := range forbiddenIssuedExtensions {
		if oid.Equal(forbidden) {
			return true
		}
	}
	return false
}

func cloneCSRExtension(extension pkix.Extension) pkix.Extension {
	id := make(asn1.ObjectIdentifier, len(extension.Id))
	copy(id, extension.Id)
	value := make([]byte, len(extension.Value))
	copy(value, extension.Value)
	return pkix.Extension{Id: id, Critical: extension.Critical, Value: value}
}

func (m *mkcert) authorizeCSRIssuance(request *csrRequestProfile) (*leafCertificateProfile, error) {
	if request == nil {
		return nil, fmt.Errorf("missing CSR authorization")
	}
	if m.caCert == nil {
		return nil, fmt.Errorf("the CA certificate is missing")
	}

	profile := &leafCertificateProfile{csrRequestProfile: *request}
	if err := validateCAExtKeyUsage(m.caCert, profile.extKeyUsage); err != nil {
		return nil, err
	}

	now := time.Now()
	notAfter := now.AddDate(2, 3, 0)
	profile.notBefore = now
	if profile.notBefore.Before(m.caCert.NotBefore) {
		profile.notBefore = m.caCert.NotBefore
	}
	if notAfter.After(m.caCert.NotAfter) {
		notAfter = m.caCert.NotAfter
	}
	profile.notAfter = notAfter
	if !profile.notAfter.After(profile.notBefore) {
		return nil, fmt.Errorf("the CA certificate is not valid for a new leaf certificate")
	}

	return profile, nil
}

func validateCAExtKeyUsage(ca *x509.Certificate, usages []x509.ExtKeyUsage) error {
	if ca == nil || len(ca.ExtKeyUsage) == 0 {
		return nil
	}
	allowed := make(map[x509.ExtKeyUsage]bool, len(ca.ExtKeyUsage))
	for _, usage := range ca.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny {
			return nil
		}
		allowed[usage] = true
	}
	for _, usage := range usages {
		if !allowed[usage] {
			return fmt.Errorf("the CA extended key usage does not permit %s", extKeyUsageName(usage))
		}
	}
	return nil
}

func extKeyUsageName(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageServerAuth:
		return "serverAuth"
	case x509.ExtKeyUsageClientAuth:
		return "clientAuth"
	case x509.ExtKeyUsageEmailProtection:
		return "emailProtection"
	default:
		return fmt.Sprintf("%d", usage)
	}
}

func (profile *leafCertificateProfile) certificateTemplate() *x509.Certificate {
	ipAddresses := make([]net.IP, len(profile.ipAddresses))
	for i, ip := range profile.ipAddresses {
		ipAddresses[i] = append(net.IP(nil), ip...)
	}
	extensions := make([]pkix.Extension, len(profile.extraExtensions))
	for i, extension := range profile.extraExtensions {
		extensions[i] = cloneCSRExtension(extension)
	}

	return &x509.Certificate{
		SerialNumber:          randomSerialNumber(),
		Subject:               profile.subject,
		DNSNames:              append([]string(nil), profile.dnsNames...),
		EmailAddresses:        append([]string(nil), profile.emailAddresses...),
		IPAddresses:           ipAddresses,
		URIs:                  append([]*url.URL(nil), profile.uris...),
		NotBefore:             profile.notBefore,
		NotAfter:              profile.notAfter,
		KeyUsage:              profile.keyUsage,
		ExtKeyUsage:           append([]x509.ExtKeyUsage(nil), profile.extKeyUsage...),
		BasicConstraintsValid: profile.basicConstraints,
		IsCA:                  false,
		ExtraExtensions:       extensions,
	}
}

// validateCACertificateForIssuance checks the public CA capabilities that are
// relevant to signing a leaf. It does not need or read the CA private key.
func validateCACertificateForIssuance(ca *x509.Certificate, now time.Time) error {
	if ca == nil {
		return fmt.Errorf("the CA certificate is missing")
	}
	if !ca.BasicConstraintsValid || !ca.IsCA {
		return fmt.Errorf("the loaded CA certificate basicConstraints is not a CA")
	}
	if ca.KeyUsage != 0 && ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("the loaded CA certificate keyUsage does not allow keyCertSign")
	}
	if len(ca.UnhandledCriticalExtensions) != 0 {
		return fmt.Errorf("the loaded CA certificate has unsupported critical extensions")
	}
	if now.Before(ca.NotBefore) {
		return fmt.Errorf("the loaded CA certificate is not valid yet")
	}
	if now.After(ca.NotAfter) {
		return fmt.Errorf("the loaded CA certificate has expired")
	}
	return nil
}

// validateCAKeyForIssuance binds the private key to the CA certificate that
// authorized the leaf profile.
func validateCAKeyForIssuance(ca *x509.Certificate, caKey crypto.PrivateKey) error {
	if ca == nil {
		return fmt.Errorf("the CA certificate is missing")
	}
	if caKey == nil {
		return fmt.Errorf("the CA key is missing")
	}

	signer, ok := caKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("the loaded CA key cannot sign certificates")
	}
	certPublicKey, err := x509.MarshalPKIXPublicKey(ca.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to encode the CA public key: %v", err)
	}
	keyPublicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("failed to encode the CA private key: %v", err)
	}
	if !bytes.Equal(certPublicKey, keyPublicKey) {
		return fmt.Errorf("the loaded CA certificate and private key do not match")
	}
	return nil
}

// verifyIssuedLeaf validates the signed certificate against the same profile
// that was authorized and against the issuing CA. This makes the final
// certificate and the trust consumer share one view of the issuance.
func verifyIssuedLeaf(der []byte, profile *leafCertificateProfile, ca *x509.Certificate) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %v", err)
	}
	if cert.IsCA {
		return nil, fmt.Errorf("generated certificate is a CA")
	}
	if cert.BasicConstraintsValid != profile.basicConstraints {
		return nil, fmt.Errorf("generated certificate basicConstraints does not match the authorized profile")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		return nil, fmt.Errorf("generated certificate is allowed to sign certificates")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		return nil, fmt.Errorf("generated certificate is allowed to sign CRLs")
	}
	if len(cert.UnhandledCriticalExtensions) != 0 {
		return nil, fmt.Errorf("generated certificate has unsupported critical extensions")
	}
	if cert.KeyUsage != profile.keyUsage {
		return nil, fmt.Errorf("generated certificate keyUsage does not match the authorized profile")
	}
	if !sameExtKeyUsages(cert.ExtKeyUsage, profile.extKeyUsage) {
		return nil, fmt.Errorf("generated certificate extendedKeyUsage does not match the authorized profile")
	}
	if len(cert.UnknownExtKeyUsage) != 0 {
		return nil, fmt.Errorf("generated certificate contains unknown extended key usage OIDs")
	}
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny {
			return nil, fmt.Errorf("generated certificate contains anyExtendedKeyUsage")
		}
	}
	for _, extension := range cert.Extensions {
		if isForbiddenIssuedExtension(extension.Id) {
			return nil, fmt.Errorf("generated certificate contains forbidden extension %s", extension.Id)
		}
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	keyUsages := append([]x509.ExtKeyUsage(nil), profile.extKeyUsage...)
	if len(keyUsages) == 0 {
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: keyUsages,
	}); err != nil {
		return nil, fmt.Errorf("generated certificate does not satisfy CA constraints (nameConstraints, extendedKeyUsage, keyUsage) or chain to the CA: %v", err)
	}
	return cert, nil
}

func sameExtKeyUsages(a, b []x509.ExtKeyUsage) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[x509.ExtKeyUsage]int, len(a))
	for _, usage := range a {
		counts[usage]++
	}
	for _, usage := range b {
		counts[usage]--
		if counts[usage] < 0 {
			return false
		}
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}
