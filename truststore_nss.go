// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	hasNSS       bool
	hasCertutil  bool
	certutilPath string
	nssDBs       = []string{
		filepath.Join(os.Getenv("HOME"), ".pki/nssdb"),
		filepath.Join(os.Getenv("HOME"), "snap/chromium/current/.pki/nssdb"), // Snapcraft
		"/etc/pki/nssdb", // CentOS 7
	}
	firefoxPaths = []string{
		"/usr/bin/firefox",
		"/usr/bin/firefox-nightly",
		"/usr/bin/firefox-developer-edition",
		"/snap/firefox",
		"/Applications/Firefox.app",
		"/Applications/FirefoxDeveloperEdition.app",
		"/Applications/Firefox Developer Edition.app",
		"/Applications/Firefox Nightly.app",
		"C:\\Program Files\\Mozilla Firefox",
	}
)

func init() {
	allPaths := append(append([]string{}, nssDBs...), firefoxPaths...)
	for _, path := range allPaths {
		if pathExists(path) {
			hasNSS = true
			break
		}
	}

	switch runtime.GOOS {
	case "darwin":
		switch {
		case binaryExists("certutil"):
			certutilPath, _ = exec.LookPath("certutil")
			hasCertutil = true
		case binaryExists("/usr/local/opt/nss/bin/certutil"):
			// Check the default Homebrew path, to save executing Ruby. #135
			certutilPath = "/usr/local/opt/nss/bin/certutil"
			hasCertutil = true
		default:
			out, err := exec.Command("brew", "--prefix", "nss").Output()
			if err == nil {
				certutilPath = filepath.Join(strings.TrimSpace(string(out)), "bin", "certutil")
				hasCertutil = pathExists(certutilPath)
			}
		}

	case "linux":
		if hasCertutil = binaryExists("certutil"); hasCertutil {
			certutilPath, _ = exec.LookPath("certutil")
		}
	}
}

func (m *mkcert) checkNSS() bool {
	if !hasCertutil {
		return false
	}
	success := true
	if m.forEachNSSProfile(func(profile string) {
		err := exec.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", m.caUniqueName()).Run()
		if err != nil {
			success = false
		}
	}) == 0 {
		success = false
	}
	return success
}

func (m *mkcert) installNSS() bool {
	if m.forEachNSSProfile(func(profile string) {
		cmd := exec.Command(certutilPath, "-A", "-d", profile, "-t", "C,,", "-n", m.caUniqueName(), "-i", filepath.Join(m.CAROOT, rootName))
		out, err := execCertutil(cmd)
		fatalIfCmdErr(err, "certutil -A -d "+profile, out)
	}) == 0 {
		log.Printf("ERROR: no %s security databases found", NSSBrowsers)
		return false
	}
	if !m.checkNSS() {
		log.Printf("Installing in %s failed. Please report the issue with details about your environment at https://github.com/FiloSottile/mkcert/issues/new 👎", NSSBrowsers)
		log.Printf("Note that if you never started %s, you need to do that at least once.", NSSBrowsers)
		return false
	}
	return true
}

func (m *mkcert) uninstallNSS() {
	result := m.removeFromNSS()
	if result.failed() {
		log.Fatalf("ERROR: failed to uninstall the local CA from the %s trust store: %s", NSSBrowsers, result.Detail)
	}
}

func (m *mkcert) removeFromNSS() storeRemovalResult {
	result := storeRemovalResult{Store: storeNSS}
	if m.caCert == nil {
		result.Status = resultFailed
		result.Stage = "load CA identity"
		result.Detail = "the local CA certificate is not loaded"
		return result
	}
	if !hasCertutil {
		result.Status = resultUnavailable
		result.Stage = "find certutil"
		result.Detail = `"certutil" is not available`
		return result
	}

	profiles, removed := 0, 0
	var failures []string
	m.forEachNSSProfile(func(profile string) {
		profiles++
		out, err := exec.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", m.caUniqueName()).CombinedOutput()
		if err != nil {
			// certutil -V reports an unknown alias as "could not find
			// cert". Any other verification failure is not evidence that
			// the entry is absent, so ask for the alias explicitly before
			// deciding whether the store is already clean.
			if certutilNotFound(out) {
				return
			}
			listOut, listErr := exec.Command(certutilPath, "-L", "-d", profile, "-n", m.caUniqueName()).CombinedOutput()
			if listErr != nil {
				if certutilNotFound(listOut) {
					return
				}
				detail := fmt.Sprintf("%v", listErr)
				if text := strings.TrimSpace(string(listOut)); text != "" {
					detail += ": " + text
				}
				failures = append(failures, fmt.Sprintf("certutil -L -d %s: %s", profile, detail))
				return
			}
		}
		cmd := exec.Command(certutilPath, "-D", "-d", profile, "-n", m.caUniqueName())
		out, err = execCertutil(cmd)
		if err != nil {
			detail := fmt.Sprintf("%v", err)
			if text := strings.TrimSpace(string(out)); text != "" {
				detail += ": " + text
			}
			failures = append(failures, fmt.Sprintf("certutil -D -d %s: %s", profile, detail))
			return
		}
		removed++
	})

	if len(failures) > 0 {
		result.Status = resultFailed
		result.Stage = "certutil -D"
		result.Detail = strings.Join(failures, "; ")
		return result
	}
	if removed > 0 {
		result.Status = resultRemoved
		result.Stage = "certutil -D"
		return result
	}
	if profiles == 0 {
		result.Stage = "no NSS security databases found"
	} else {
		result.Stage = "NSS trust entry already absent"
	}
	result.Status = resultAbsent
	return result
}

func certutilNotFound(out []byte) bool {
	text := strings.ToLower(string(out))
	return strings.Contains(text, "could not find cert") ||
		strings.Contains(text, "certificate not found") ||
		strings.Contains(text, "not found") ||
		strings.Contains(text, "no such") ||
		strings.Contains(text, "does not exist")
}

// execCertutil will execute a "certutil" command and if needed re-execute
// the command with commandWithSudo to work around file permissions.
func execCertutil(cmd *exec.Cmd) ([]byte, error) {
	out, err := cmd.CombinedOutput()
	if err != nil && bytes.Contains(out, []byte("SEC_ERROR_READ_ONLY")) && runtime.GOOS != "windows" {
		origArgs := cmd.Args[1:]
		cmd = commandWithSudo(cmd.Path)
		cmd.Args = append(cmd.Args, origArgs...)
		out, err = cmd.CombinedOutput()
	}
	return out, err
}

func (m *mkcert) forEachNSSProfile(f func(profile string)) (found int) {
	var profiles []string
	profiles = append(profiles, nssDBs...)
	for _, ff := range FirefoxProfiles {
		pp, _ := filepath.Glob(ff)
		profiles = append(profiles, pp...)
	}
	for _, profile := range profiles {
		if stat, err := os.Stat(profile); err != nil || !stat.IsDir() {
			continue
		}
		if pathExists(filepath.Join(profile, "cert9.db")) {
			f("sql:" + profile)
			found++
		} else if pathExists(filepath.Join(profile, "cert8.db")) {
			f("dbm:" + profile)
			found++
		}
	}
	return
}
