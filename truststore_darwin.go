// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"howett.net/plist"
)

var (
	FirefoxProfiles     = []string{os.Getenv("HOME") + "/Library/Application Support/Firefox/Profiles/*"}
	CertutilInstallHelp = "brew install nss"
	NSSBrowsers         = "Firefox"
)

// https://github.com/golang/go/issues/24652#issuecomment-399826583
var trustSettings []interface{}
var _, _ = plist.Unmarshal(trustSettingsData, &trustSettings)
var trustSettingsData = []byte(`
<array>
	<dict>
		<key>kSecTrustSettingsPolicy</key>
		<data>
		KoZIhvdjZAED
		</data>
		<key>kSecTrustSettingsPolicyName</key>
		<string>sslServer</string>
		<key>kSecTrustSettingsResult</key>
		<integer>1</integer>
	</dict>
	<dict>
		<key>kSecTrustSettingsPolicy</key>
		<data>
		KoZIhvdjZAEC
		</data>
		<key>kSecTrustSettingsPolicyName</key>
		<string>basicX509</string>
		<key>kSecTrustSettingsResult</key>
		<integer>1</integer>
	</dict>
</array>
`)

func (m *mkcert) installPlatform() bool {
	cmd := commandWithSudo("security", "add-trusted-cert", "-d", "-k", "/Library/Keychains/System.keychain", filepath.Join(m.CAROOT, rootName))
	out, err := cmd.CombinedOutput()
	fatalIfCmdErr(err, "security add-trusted-cert", out)

	// Make trustSettings explicit, as older Go does not know the defaults.
	// https://github.com/golang/go/issues/24652

	plistFile, err := ioutil.TempFile("", "trust-settings")
	fatalIfErr(err, "failed to create temp file")
	defer os.Remove(plistFile.Name())

	cmd = commandWithSudo("security", "trust-settings-export", "-d", plistFile.Name())
	out, err = cmd.CombinedOutput()
	fatalIfCmdErr(err, "security trust-settings-export", out)

	plistData, err := ioutil.ReadFile(plistFile.Name())
	fatalIfErr(err, "failed to read trust settings")
	var plistRoot map[string]interface{}
	_, err = plist.Unmarshal(plistData, &plistRoot)
	fatalIfErr(err, "failed to parse trust settings")

	rootSubjectASN1, _ := asn1.Marshal(m.caCert.Subject.ToRDNSequence())

	if plistRoot["trustVersion"].(uint64) != 1 {
		log.Fatalln("ERROR: unsupported trust settings version:", plistRoot["trustVersion"])
	}
	trustList := plistRoot["trustList"].(map[string]interface{})
	for key := range trustList {
		entry := trustList[key].(map[string]interface{})
		if _, ok := entry["issuerName"]; !ok {
			continue
		}
		issuerName := entry["issuerName"].([]byte)
		if !bytes.Equal(rootSubjectASN1, issuerName) {
			continue
		}
		entry["trustSettings"] = trustSettings
		break
	}

	plistData, err = plist.MarshalIndent(plistRoot, plist.XMLFormat, "\t")
	fatalIfErr(err, "failed to serialize trust settings")
	err = ioutil.WriteFile(plistFile.Name(), plistData, 0600)
	fatalIfErr(err, "failed to write trust settings")

	cmd = commandWithSudo("security", "trust-settings-import", "-d", plistFile.Name())
	out, err = cmd.CombinedOutput()
	fatalIfCmdErr(err, "security trust-settings-import", out)

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
	// security(1) removes the certificate found in the supplied file. Pin the
	// transaction to a private snapshot so a concurrent CAROOT rotation cannot
	// make it remove a different CA.
	temp, err := ioutil.TempFile("", "mkcert-uninstall-*.pem")
	if err != nil {
		result.Status = resultFailed
		result.Stage = "create CA snapshot"
		result.Detail = err.Error()
		return result
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		result.Status = resultFailed
		result.Stage = "create CA snapshot"
		result.Detail = err.Error()
		return result
	}
	if err := pem.Encode(temp, &pem.Block{Type: "CERTIFICATE", Bytes: m.caCert.Raw}); err != nil {
		temp.Close()
		result.Status = resultFailed
		result.Stage = "create CA snapshot"
		result.Detail = err.Error()
		return result
	}
	if err := temp.Close(); err != nil {
		result.Status = resultFailed
		result.Stage = "create CA snapshot"
		result.Detail = err.Error()
		return result
	}

	cmd := commandWithSudo("security", "remove-trusted-cert", "-d", tempName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		text := strings.ToLower(string(out))
		if strings.Contains(text, "could not be found") || strings.Contains(text, "not found") {
			result.Status = resultAbsent
			result.Stage = "security remove-trusted-cert"
			return result
		}
		result.Status = resultFailed
		result.Stage = "security remove-trusted-cert"
		result.Detail = fmt.Sprintf("%v: %s", err, strings.TrimSpace(string(out)))
		return result
	}
	result.Status = resultRemoved
	result.Stage = "security remove-trusted-cert"
	return result
}
