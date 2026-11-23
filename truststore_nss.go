// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
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
	found, err := m.forEachNSSProfile(func(profile string) error {
		err := exec.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", m.caUniqueName()).Run()
		if err != nil {
			success = false
		}
		return nil
	})
	return err == nil && found > 0 && success
}

func (m *mkcert) installNSS(caFile string) error {
	found, err := m.forEachNSSProfile(func(profile string) error {
		cmd := exec.Command(certutilPath, "-A", "-d", profile, "-t", "C,,", "-n", m.caUniqueName(), "-i", caFile)
		out, err := execCertutil(cmd)
		if err != nil {
			return fmt.Errorf("certutil -A -d %s: %v\n\n%s", profile, err, out)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if found == 0 {
		return errNoNSSProfiles
	}
	if !m.checkNSS() {
		return errNSSVerification
	}
	return nil
}

func (m *mkcert) uninstallNSS(alias string) (int, error) {
	removed := 0
	_, err := m.forEachNSSProfile(func(profile string) error {
		err := exec.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", alias).Run()
		if err != nil {
			return nil
		}
		cmd := exec.Command(certutilPath, "-D", "-d", profile, "-n", alias)
		out, err := execCertutil(cmd)
		if err != nil {
			return fmt.Errorf("certutil -D -d %s: %v\n\n%s", profile, err, out)
		}
		removed++
		return nil
	})
	return removed, err
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

func (m *mkcert) forEachNSSProfile(f func(profile string) error) (found int, err error) {
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
			if err := f("sql:" + profile); err != nil {
				return found, err
			}
			found++
		} else if pathExists(filepath.Join(profile, "cert8.db")) {
			if err := f("dbm:" + profile); err != nil {
				return found, err
			}
			found++
		}
	}
	return found, nil
}
