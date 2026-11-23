// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	hasJava    bool
	hasKeytool bool

	javaHome    string
	cacertsPath string
	keytoolPath string
	storePass   string = "changeit"
)

func init() {
	if runtime.GOOS == "windows" {
		keytoolPath = filepath.Join("bin", "keytool.exe")
	} else {
		keytoolPath = filepath.Join("bin", "keytool")
	}

	if v := os.Getenv("JAVA_HOME"); v != "" {
		hasJava = true
		javaHome = v

		if pathExists(filepath.Join(v, keytoolPath)) {
			hasKeytool = true
			keytoolPath = filepath.Join(v, keytoolPath)
		}

		if pathExists(filepath.Join(v, "lib", "security", "cacerts")) {
			cacertsPath = filepath.Join(v, "lib", "security", "cacerts")
		}

		if pathExists(filepath.Join(v, "jre", "lib", "security", "cacerts")) {
			cacertsPath = filepath.Join(v, "jre", "lib", "security", "cacerts")
		}
	}
}

func (m *mkcert) checkJava() (bool, error) {
	if !hasKeytool || cacertsPath == "" {
		return false, nil
	}

	// exists returns true if the given x509.Certificate's fingerprint
	// is in the keytool -list output
	exists := func(c *x509.Certificate, h hash.Hash, keytoolOutput []byte) bool {
		h.Write(c.Raw)
		fp := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
		return bytes.Contains(keytoolOutput, []byte(fp))
	}

	keytoolOutput, err := exec.Command(keytoolPath, "-list", "-keystore", cacertsPath, "-storepass", storePass).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("keytool -list: %v\n\n%s", err, keytoolOutput)
	}
	// keytool outputs SHA1 and SHA256 (Java 9+) certificates in uppercase hex
	// with each octet pair delimitated by ":". Drop them from the keytool output
	keytoolOutput = bytes.Replace(keytoolOutput, []byte(":"), nil, -1)

	// pre-Java 9 uses SHA1 fingerprints
	s1, s256 := sha1.New(), sha256.New()
	return exists(m.caCert, s1, keytoolOutput) || exists(m.caCert, s256, keytoolOutput), nil
}

func (m *mkcert) installJava(caFile string) error {
	args := []string{
		"-importcert", "-noprompt",
		"-keystore", cacertsPath,
		"-storepass", storePass,
		"-file", caFile,
		"-alias", m.caUniqueName(),
	}

	out, err := execKeytool(exec.Command(keytoolPath, args...))
	if err != nil {
		return fmt.Errorf("keytool -importcert: %v\n\n%s", err, out)
	}
	return nil
}

func (m *mkcert) uninstallJava(alias string) (bool, error) {
	args := []string{
		"-delete",
		"-alias", alias,
		"-keystore", cacertsPath,
		"-storepass", storePass,
	}
	out, err := execKeytool(exec.Command(keytoolPath, args...))
	if bytes.Contains(out, []byte("does not exist")) {
		return false, nil // cert didn't exist
	}
	if err != nil {
		return false, fmt.Errorf("keytool -delete: %v\n\n%s", err, out)
	}
	return true, nil
}

// execKeytool will execute a "keytool" command and if needed re-execute
// the command with commandWithSudo to work around file permissions.
func execKeytool(cmd *exec.Cmd) ([]byte, error) {
	out, err := cmd.CombinedOutput()
	if err != nil && bytes.Contains(out, []byte("java.io.FileNotFoundException")) && runtime.GOOS != "windows" {
		origArgs := cmd.Args[1:]
		cmd = commandWithSudo(cmd.Path)
		cmd.Args = append(cmd.Args, origArgs...)
		cmd.Env = []string{
			"JAVA_HOME=" + javaHome,
		}
		out, err = cmd.CombinedOutput()
	}
	return out, err
}
