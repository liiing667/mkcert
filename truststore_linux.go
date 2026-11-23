// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

var (
	FirefoxProfiles = []string{os.Getenv("HOME") + "/.mozilla/firefox/*",
		os.Getenv("HOME") + "/snap/firefox/common/.mozilla/firefox/*"}
	NSSBrowsers = "Firefox and/or Chrome/Chromium"

	SystemTrustFilename string
	SystemTrustCommand  []string
	CertutilInstallHelp string
)

func init() {
	switch {
	case binaryExists("apt"):
		CertutilInstallHelp = "apt install libnss3-tools"
	case binaryExists("yum"):
		CertutilInstallHelp = "yum install nss-tools"
	case binaryExists("zypper"):
		CertutilInstallHelp = "zypper install mozilla-nss-tools"
	}
	if pathExists("/etc/pki/ca-trust/source/anchors/") {
		SystemTrustFilename = "/etc/pki/ca-trust/source/anchors/%s.pem"
		SystemTrustCommand = []string{"update-ca-trust", "extract"}
	} else if pathExists("/usr/local/share/ca-certificates/") {
		SystemTrustFilename = "/usr/local/share/ca-certificates/%s.crt"
		SystemTrustCommand = []string{"update-ca-certificates"}
	} else if pathExists("/etc/ca-certificates/trust-source/anchors/") {
		SystemTrustFilename = "/etc/ca-certificates/trust-source/anchors/%s.crt"
		SystemTrustCommand = []string{"trust", "extract-compat"}
	} else if pathExists("/usr/share/pki/trust/anchors") {
		SystemTrustFilename = "/usr/share/pki/trust/anchors/%s.pem"
		SystemTrustCommand = []string{"update-ca-certificates"}
	}
}

func (m *mkcert) systemTrustFilename() string {
	return fmt.Sprintf(SystemTrustFilename, strings.Replace(m.caUniqueName(), " ", "_", -1))
}

func (m *mkcert) installPlatform(caFile string) error {
	if SystemTrustCommand == nil {
		return errStoreUnsupported
	}

	cert, err := ioutil.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("failed to read root certificate: %w", err)
	}

	cmd := commandWithSudo("tee", m.systemTrustFilename())
	cmd.Stdin = bytes.NewReader(cert)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute \"tee\": %v\n\n%s", err, out)
	}

	cmd = commandWithSudo(SystemTrustCommand...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute \"%s\": %v\n\n%s", strings.Join(SystemTrustCommand, " "), err, out)
	}

	return nil
}

func (m *mkcert) uninstallPlatform(caFile string) (bool, error) {
	if SystemTrustCommand == nil {
		return false, errStoreUnsupported
	}

	removed := false
	filename := m.systemTrustFilename()
	if pathExists(filename) {
		cmd := commandWithSudo("rm", "-f", filename)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return false, fmt.Errorf("failed to execute \"rm\": %v\n\n%s", err, out)
		}
		removed = true
	}

	// We used to install under non-unique filenames. Only remove the legacy
	// file if it still contains the CA we are uninstalling, so rotating the
	// CA doesn't delete an older generation that is still trusted.
	legacyFilename := fmt.Sprintf(SystemTrustFilename, "mkcert-rootCA")
	if legacyFilename != filename && pathExists(legacyFilename) {
		legacyCert, err := ioutil.ReadFile(legacyFilename)
		if err != nil {
			return removed, fmt.Errorf("failed to read the legacy root certificate: %w", err)
		}
		currentCert, err := ioutil.ReadFile(caFile)
		if err != nil {
			return removed, fmt.Errorf("failed to read the transaction CA certificate: %w", err)
		}
		if !bytes.Equal(legacyCert, currentCert) {
			if !removed {
				return false, errCertNotInstalled
			}
			return removed, nil
		}
		cmd := commandWithSudo("rm", "-f", legacyFilename)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return removed, fmt.Errorf("failed to execute \"rm (legacy filename)\": %v\n\n%s", err, out)
		}
		removed = true
	}

	if !removed {
		return false, errCertNotInstalled
	}

	cmd := commandWithSudo(SystemTrustCommand...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return true, fmt.Errorf("failed to execute \"%s\": %v\n\n%s", strings.Join(SystemTrustCommand, " "), err, out)
	}

	return true, nil
}
