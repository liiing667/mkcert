// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
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

func (m *mkcert) installPlatform() bool {
	if SystemTrustCommand == nil {
		log.Printf("Installing to the system store is not yet supported on this Linux 😣 but %s will still work.", NSSBrowsers)
		log.Printf("You can also manually install the root certificate at %q.", filepath.Join(m.CAROOT, rootName))
		return false
	}

	cert, err := ioutil.ReadFile(filepath.Join(m.CAROOT, rootName))
	fatalIfErr(err, "failed to read root certificate")

	cmd := commandWithSudo("tee", m.systemTrustFilename())
	cmd.Stdin = bytes.NewReader(cert)
	out, err := cmd.CombinedOutput()
	fatalIfCmdErr(err, "tee", out)

	cmd = commandWithSudo(SystemTrustCommand...)
	out, err = cmd.CombinedOutput()
	fatalIfCmdErr(err, strings.Join(SystemTrustCommand, " "), out)

	return true
}

func (m *mkcert) uninstallPlatform() bool {
	result := m.removeFromPlatform()
	if result.failed() {
		log.Fatalf("ERROR: failed to uninstall the local CA from the system trust store: %s", result.Detail)
	}
	return result.Status == resultRemoved || result.Status == resultAbsent
}

func (m *mkcert) removeFromPlatform() storeRemovalResult {
	result := storeRemovalResult{Store: storeSystem}
	if m.caCert == nil {
		result.Status = resultFailed
		result.Stage = "load CA identity"
		result.Detail = "the local CA certificate is not loaded"
		return result
	}
	if SystemTrustCommand == nil || SystemTrustFilename == "" {
		result.Status = resultUnavailable
		result.Stage = "detect system trust store"
		result.Detail = "the system trust store is not supported on this Linux"
		return result
	}

	changed := false
	filename := m.systemTrustFilename()
	exists, matches, err := certificateFileMatches(filename, m.caCert)
	if err != nil {
		result.Status = resultFailed
		result.Stage = "inspect system trust anchor"
		result.Detail = err.Error()
		return result
	}
	if exists && !matches {
		result.Status = resultFailed
		result.Stage = "inspect system trust anchor"
		result.Detail = fmt.Sprintf("%s contains a different CA", filename)
		return result
	}
	if exists {
		cmd := commandWithSudo("rm", "-f", filename)
		out, err := cmd.CombinedOutput()
		if err != nil {
			result.Status = resultFailed
			result.Stage = "remove system trust anchor"
			result.Detail = fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out)))
			return result
		}
		changed = true
	}

	// We used to install under a non-unique filename. Never remove that
	// legacy-looking file unless it contains this transaction's exact CA.
	legacyFilename := fmt.Sprintf(SystemTrustFilename, "mkcert-rootCA")
	exists, matches, err = certificateFileMatches(legacyFilename, m.caCert)
	if err != nil {
		result.Status = resultFailed
		result.Stage = "inspect legacy system trust anchor"
		result.Detail = err.Error()
		return result
	}
	if exists && !matches {
		result.Status = resultFailed
		result.Stage = "inspect legacy system trust anchor"
		result.Detail = fmt.Sprintf("%s contains a different CA", legacyFilename)
		return result
	}
	if exists {
		cmd := commandWithSudo("rm", "-f", legacyFilename)
		out, err := cmd.CombinedOutput()
		if err != nil {
			result.Status = resultFailed
			result.Stage = "remove legacy system trust anchor"
			result.Detail = fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out)))
			return result
		}
		changed = true
	}

	cmd := commandWithSudo(SystemTrustCommand...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		result.Status = resultFailed
		result.Stage = strings.Join(SystemTrustCommand, " ")
		result.Detail = fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out)))
		return result
	}
	if changed {
		result.Status = resultRemoved
	} else {
		result.Status = resultAbsent
	}
	result.Stage = "refresh system trust store"
	return result
}
