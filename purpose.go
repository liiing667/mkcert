// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// certPurpose is the single source of truth for what a generated certificate
// is allowed to be used for. Command flags, CSR extensions, EKU/KeyUsage, and
// default output file names all go through this type so they cannot disagree
// with each other.
type certPurpose uint8

const (
	purposeServer certPurpose = 1 << iota
	purposeClient
	purposeEmail
)

const purposeTLS = purposeServer | purposeClient

var (
	oidExtensionSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidAnyExtendedKeyUsage       = asn1.ObjectIdentifier{2, 5, 29, 37, 0}

	oidExtKeyUsageServerAuth      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageEmailProtection = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
)

func (p certPurpose) has(other certPurpose) bool {
	return p&other == other
}

func (p certPurpose) tls() certPurpose {
	return p & purposeTLS
}

func (p certPurpose) empty() bool {
	return p == 0
}

func (p certPurpose) String() string {
	switch p {
	case purposeServer:
		return "server"
	case purposeClient:
		return "client"
	case purposeEmail:
		return "email"
	case purposeServer | purposeClient:
		return "server+client"
	case purposeServer | purposeEmail:
		return "server+email"
	case purposeClient | purposeEmail:
		return "client+email"
	case purposeServer | purposeClient | purposeEmail:
		return "server+client+email"
	default:
		return "none"
	}
}

func (p certPurpose) extKeyUsage() []x509.ExtKeyUsage {
	var usages []x509.ExtKeyUsage
	if p.has(purposeClient) {
		usages = append(usages, x509.ExtKeyUsageClientAuth)
	}
	if p.has(purposeServer) {
		usages = append(usages, x509.ExtKeyUsageServerAuth)
	}
	if p.has(purposeEmail) {
		usages = append(usages, x509.ExtKeyUsageEmailProtection)
	}
	return usages
}

func (p certPurpose) keyUsage() x509.KeyUsage {
	ku := x509.KeyUsageDigitalSignature
	if p.has(purposeServer) || p.has(purposeEmail) {
		ku |= x509.KeyUsageKeyEncipherment
	}
	return ku
}

func (p certPurpose) clientSuffix() string {
	if p.has(purposeClient) {
		return "-client"
	}
	return ""
}

func (m *mkcert) explicitPurpose() (certPurpose, bool) {
	var p certPurpose
	if m.server {
		p |= purposeServer
	}
	if m.client {
		p |= purposeClient
	}
	return p, !p.empty()
}

func purposeFromSANs(hasServerSAN, hasEmailSAN bool) certPurpose {
	var p certPurpose
	if hasServerSAN {
		p |= purposeServer
	}
	if hasEmailSAN {
		p |= purposeEmail
	}
	return p
}

// purposeForCertificate derives the purpose of a certificate generated from
// command-line hosts. This preserves mkcert's historical behavior: -client
// certificates for server identities are dual-purpose for service-mesh mTLS,
// while an email SAN always adds emailProtection.
func (m *mkcert) purposeForCertificate(tpl *x509.Certificate) certPurpose {
	hasServerSAN := len(tpl.IPAddresses) > 0 || len(tpl.DNSNames) > 0 || len(tpl.URIs) > 0
	hasEmailSAN := len(tpl.EmailAddresses) > 0

	command, explicit := m.explicitPurpose()
	if !explicit {
		p := purposeFromSANs(hasServerSAN, hasEmailSAN)
		if p.empty() {
			return purposeServer
		}
		return p
	}

	p := command
	if m.client && !m.server && hasServerSAN {
		p |= purposeServer
	}
	if hasEmailSAN {
		p |= purposeEmail
	}
	if p.empty() {
		return purposeServer
	}
	return p
}

// purposeForCSR derives the purpose from the command's explicit purpose and
// the extensions requested in the CSR. TLS purposes are intersected so that a
// client-only command can never turn a CSR's serverAuth request into a
// server-capable certificate; contradictory TLS roles are rejected instead of
// being unioned.
func (m *mkcert) purposeForCSR(csr *x509.CertificateRequest) (certPurpose, error) {
	hasServerSAN := len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 || len(csr.URIs) > 0
	hasEmailSAN := len(csr.EmailAddresses) > 0

	requested, requestedExplicit, err := purposeFromExtensions(csr.Extensions)
	if err != nil {
		return 0, fmt.Errorf("failed to parse the CSR extended key usage: %v", err)
	}
	command, commandExplicit := m.explicitPurpose()

	var p certPurpose
	switch {
	case commandExplicit:
		p = command
		if requestedExplicit {
			commandTLS := command.tls()
			requestedTLS := requested.tls()
			if commandTLS != 0 && requestedTLS != 0 {
				tls := commandTLS & requestedTLS
				if tls == 0 {
					return 0, fmt.Errorf("conflicting certificate purposes: command requests %s but CSR requests %s", commandTLS, requestedTLS)
				}
				p = (p &^ purposeTLS) | tls
			}
		}
	case requestedExplicit:
		p = requested
	default:
		p = purposeFromSANs(hasServerSAN, hasEmailSAN)
		if p.empty() {
			p = purposeServer
		}
	}

	if requestedExplicit {
		if requested.has(purposeEmail) {
			p |= purposeEmail
		}
	} else if hasEmailSAN {
		p |= purposeEmail
	}

	if p.empty() {
		return 0, fmt.Errorf("CSR does not request a supported certificate purpose")
	}
	return p, nil
}

func purposeFromExtensions(exts []pkix.Extension) (p certPurpose, explicit bool, err error) {
	for _, ext := range exts {
		if !ext.Id.Equal(oidExtensionExtendedKeyUsage) {
			continue
		}
		explicit = true

		var oids []asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(ext.Value, &oids)
		if err != nil {
			return 0, true, err
		}
		if len(rest) != 0 {
			return 0, true, errors.New("trailing data after extended key usage")
		}

		for _, oid := range oids {
			switch {
			case oid.Equal(oidExtKeyUsageServerAuth):
				p |= purposeServer
			case oid.Equal(oidExtKeyUsageClientAuth):
				p |= purposeClient
			case oid.Equal(oidExtKeyUsageEmailProtection):
				p |= purposeEmail
			case oid.Equal(oidAnyExtendedKeyUsage):
				// Never copy anyExtendedKeyUsage into the issued
				// certificate. It would authorize every purpose, including
				// ones neither the command nor the CSR asked for.
			default:
				// Ignore purposes mkcert does not issue (code signing,
				// timestamping, OCSP signing, and so on). They must not leak
				// into the certificate through a wholesale extension copy.
			}
		}
	}
	return p, explicit, nil
}

func findSANExtension(exts []pkix.Extension) (pkix.Extension, bool) {
	var san pkix.Extension
	found := false
	for _, ext := range exts {
		if ext.Id.Equal(oidExtensionSubjectAltName) {
			san = ext
			found = true
		}
	}
	return san, found
}
