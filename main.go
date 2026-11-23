// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command mkcert is a simple zero-config tool to make development certificates.
package main

import (
	"crypto"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sync"

	"golang.org/x/net/idna"
)

const shortUsage = `Usage of mkcert:

	$ mkcert -install
	Install the local CA in the system trust store.

	$ mkcert example.org
	Generate "example.org.pem" and "example.org-key.pem".

	$ mkcert example.com myapp.dev localhost 127.0.0.1 ::1
	Generate "example.com+4.pem" and "example.com+4-key.pem".

	$ mkcert "*.example.it"
	Generate "_wildcard.example.it.pem" and "_wildcard.example.it-key.pem".

	$ mkcert -uninstall
	Uninstall the local CA (but do not delete it).

`

const advancedUsage = `Advanced options:

	-cert-file FILE, -key-file FILE, -p12-file FILE
	    Customize the output paths.

	-client
	    Generate a certificate for client authentication.

	-ecdsa
	    Generate a certificate with an ECDSA key.

	-pkcs12
	    Generate a ".p12" PKCS #12 file, also know as a ".pfx" file,
	    containing certificate and key for legacy applications.

	-csr CSR
	    Generate a certificate based on the supplied CSR. Conflicts with
	    all other flags and arguments except -install and -cert-file.

	-CAROOT
	    Print the CA certificate and key storage location.

	$CAROOT (environment variable)
	    Set the CA certificate and key storage location. (This allows
	    maintaining multiple local CAs in parallel.)

	$TRUST_STORES (environment variable)
	    A comma-separated list of trust stores to install the local
	    root CA into. Options are: "system", "java" and "nss" (includes
	    Firefox). Autodetected by default.

`

// Version can be set at link time to override debug.BuildInfo.Main.Version,
// which is "(devel)" when building from within the module. See
// golang.org/issue/29814 and golang.org/issue/29228.
var Version string

func main() {
	if len(os.Args) == 1 {
		fmt.Print(shortUsage)
		return
	}
	log.SetFlags(0)
	var (
		installFlag   = flag.Bool("install", false, "")
		uninstallFlag = flag.Bool("uninstall", false, "")
		pkcs12Flag    = flag.Bool("pkcs12", false, "")
		ecdsaFlag     = flag.Bool("ecdsa", false, "")
		clientFlag    = flag.Bool("client", false, "")
		helpFlag      = flag.Bool("help", false, "")
		carootFlag    = flag.Bool("CAROOT", false, "")
		csrFlag       = flag.String("csr", "", "")
		certFileFlag  = flag.String("cert-file", "", "")
		keyFileFlag   = flag.String("key-file", "", "")
		p12FileFlag   = flag.String("p12-file", "", "")
		versionFlag   = flag.Bool("version", false, "")
	)
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), shortUsage)
		fmt.Fprintln(flag.CommandLine.Output(), `For more options, run "mkcert -help".`)
	}
	flag.Parse()
	if *helpFlag {
		fmt.Print(shortUsage)
		fmt.Print(advancedUsage)
		return
	}
	if *versionFlag {
		if Version != "" {
			fmt.Println(Version)
			return
		}
		if buildInfo, ok := debug.ReadBuildInfo(); ok {
			fmt.Println(buildInfo.Main.Version)
			return
		}
		fmt.Println("(unknown)")
		return
	}
	if *carootFlag {
		if *installFlag || *uninstallFlag {
			log.Fatalln("ERROR: you can't set -[un]install and -CAROOT at the same time")
		}
		fmt.Println(getCAROOT())
		return
	}
	if *installFlag && *uninstallFlag {
		log.Fatalln("ERROR: you can't set -install and -uninstall at the same time")
	}
	if *csrFlag != "" && (*pkcs12Flag || *ecdsaFlag || *clientFlag) {
		log.Fatalln("ERROR: can only combine -csr with -install and -cert-file")
	}
	if *csrFlag != "" && flag.NArg() != 0 {
		log.Fatalln("ERROR: can't specify extra arguments when using -csr")
	}
	(&mkcert{
		installMode: *installFlag, uninstallMode: *uninstallFlag, csrPath: *csrFlag,
		pkcs12: *pkcs12Flag, ecdsa: *ecdsaFlag, client: *clientFlag,
		certFile: *certFileFlag, keyFile: *keyFileFlag, p12File: *p12FileFlag,
	}).Run(flag.Args())
}

const rootName = "rootCA.pem"
const rootKeyName = "rootCA-key.pem"

type mkcert struct {
	installMode, uninstallMode bool
	pkcs12, ecdsa, client      bool
	keyFile, certFile, p12File string
	csrPath                    string

	CAROOT string
	caCert *x509.Certificate
	caKey  crypto.PrivateKey

	// The system cert pool is only loaded once. After installing the root, checks
	// will keep failing until the next execution. TODO: maybe execve?
	// https://github.com/golang/go/issues/24540 (thanks, myself)
	ignoreCheckFailure bool
}

func (m *mkcert) Run(args []string) {
	m.CAROOT = getCAROOT()
	if m.CAROOT == "" {
		log.Fatalln("ERROR: failed to find the default CA location, set one as the CAROOT env var")
	}
	fatalIfErr(os.MkdirAll(m.CAROOT, 0755), "failed to create the CAROOT")
	m.loadCA()

	if m.installMode {
		if err := m.install(); err != nil {
			log.Fatalf("ERROR: %v", err)
		}
		if len(args) == 0 {
			return
		}
	} else if m.uninstallMode {
		if err := m.uninstall(); err != nil {
			log.Fatalf("ERROR: %v", err)
		}
		return
	} else {
		var warning bool
		if storeEnabled("system") && !m.checkPlatform() {
			warning = true
			log.Println("Note: the local CA is not installed in the system trust store.")
		}
		if storeEnabled("nss") && hasNSS && CertutilInstallHelp != "" && !m.checkNSS() {
			warning = true
			log.Printf("Note: the local CA is not installed in the %s trust store.", NSSBrowsers)
		}
		if storeEnabled("java") && hasJava {
			if installed, err := m.checkJava(); err != nil || !installed {
				warning = true
				log.Println("Note: the local CA is not installed in the Java trust store.")
			}
		}
		if warning {
			log.Println("Run \"mkcert -install\" for certificates to be trusted automatically ⚠️")
		}
	}

	if m.csrPath != "" {
		m.makeCertFromCSR()
		return
	}

	if len(args) == 0 {
		flag.Usage()
		return
	}

	hostnameRegexp := regexp.MustCompile(`(?i)^(\*\.)?[0-9a-z_-]([0-9a-z._-]*[0-9a-z_-])?$`)
	for i, name := range args {
		if ip := net.ParseIP(name); ip != nil {
			continue
		}
		if email, err := mail.ParseAddress(name); err == nil && email.Address == name {
			continue
		}
		if uriName, err := url.Parse(name); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			continue
		}
		punycode, err := idna.ToASCII(name)
		if err != nil {
			log.Fatalf("ERROR: %q is not a valid hostname, IP, URL or email: %s", name, err)
		}
		args[i] = punycode
		if !hostnameRegexp.MatchString(punycode) {
			log.Fatalf("ERROR: %q is not a valid hostname, IP, URL or email", name)
		}
	}

	m.makeCert(args)
}

func getCAROOT() string {
	if env := os.Getenv("CAROOT"); env != "" {
		return env
	}

	var dir string
	switch {
	case runtime.GOOS == "windows":
		dir = os.Getenv("LocalAppData")
	case os.Getenv("XDG_DATA_HOME") != "":
		dir = os.Getenv("XDG_DATA_HOME")
	case runtime.GOOS == "darwin":
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, "Library", "Application Support")
	default: // Unix
		dir = os.Getenv("HOME")
		if dir == "" {
			return ""
		}
		dir = filepath.Join(dir, ".local", "share")
	}
	return filepath.Join(dir, "mkcert")
}

func (m *mkcert) install() error {
	tx, err := newTrustTransaction(m, false)
	if err != nil {
		return err
	}
	defer tx.close()

	for _, store := range tx.stores {
		switch store {
		case trustStoreSystem:
			m.installSystem(tx)
		case trustStoreNSS:
			m.installNSSStore(tx)
		case trustStoreJava:
			m.installJavaStore(tx)
		}
	}
	return tx.reportInstall()
}

func (m *mkcert) installSystem(tx *trustTransaction) {
	if m.checkPlatform() {
		tx.record(trustStoreSystem, outcomeAlreadyInstalled, nil)
		log.Print("The local CA is already installed in the system trust store! 👍")
		return
	}

	if err := m.installPlatform(tx.caFile); err != nil {
		if errors.Is(err, errStoreUnsupported) {
			tx.record(trustStoreSystem, outcomeUnavailable, err)
			log.Printf("Installing to the system store is not yet supported on this Linux 😣 but %s will still work.", NSSBrowsers)
			log.Printf("You can also manually install the root certificate at %q.", filepath.Join(m.CAROOT, rootName))
			return
		}
		tx.record(trustStoreSystem, outcomeFailed, err)
		log.Printf("Warning: failed to install the local CA in the system trust store: %v ⚠️", err)
		return
	}

	tx.record(trustStoreSystem, outcomeInstalled, nil)
	m.ignoreCheckFailure = true // the system cert pool is loaded only once per process
	log.Print("The local CA is now installed in the system trust store! ⚡️")
}

func (m *mkcert) installNSSStore(tx *trustTransaction) {
	if !hasNSS {
		tx.record(trustStoreNSS, outcomeUnavailable, errors.New("NSS is not available"))
		if tx.explicit {
			log.Printf("Warning: %s is not available, so the CA can't be automatically installed in its trust store! ⚠️", NSSBrowsers)
		}
		return
	}
	if !hasCertutil {
		tx.record(trustStoreNSS, outcomeUnavailable, errors.New("certutil is not available"))
		if CertutilInstallHelp == "" {
			log.Printf(`Note: %s support is not available on your platform. ℹ️`, NSSBrowsers)
		} else {
			log.Printf(`Warning: "certutil" is not available, so the CA can't be automatically installed in %s! ⚠️`, NSSBrowsers)
			log.Printf(`Install "certutil" with "%s" and re-run "mkcert -install" 👈`, CertutilInstallHelp)
		}
		return
	}
	if m.checkNSS() {
		tx.record(trustStoreNSS, outcomeAlreadyInstalled, nil)
		log.Printf("The local CA is already installed in the %s trust store! 👍", NSSBrowsers)
		return
	}

	if err := m.installNSS(tx.caFile); err != nil {
		if m.checkNSS() {
			tx.record(trustStoreNSS, outcomeInstalled, err)
			log.Printf("Warning: certutil reported an error, but the local CA is present in the %s trust store: %v ⚠️", NSSBrowsers, err)
			return
		}
		if errors.Is(err, errNoNSSProfiles) {
			tx.record(trustStoreNSS, outcomeUnavailable, err)
			log.Printf("ERROR: no %s security databases found", NSSBrowsers)
		} else {
			tx.record(trustStoreNSS, outcomeFailed, err)
			log.Printf("Installing in %s failed. Please report the issue with details about your environment at https://github.com/FiloSottile/mkcert/issues/new 👎", NSSBrowsers)
			log.Printf("Note that if you never started %s, you need to do that at least once.", NSSBrowsers)
			log.Printf("Warning: failed to install the local CA in the %s trust store: %v ⚠️", NSSBrowsers, err)
		}
		return
	}

	tx.record(trustStoreNSS, outcomeInstalled, nil)
	log.Printf("The local CA is now installed in the %s trust store (requires browser restart)! 🦊", NSSBrowsers)
}

func (m *mkcert) installJavaStore(tx *trustTransaction) {
	if !hasJava {
		tx.record(trustStoreJava, outcomeUnavailable, errors.New("Java is not available"))
		if tx.explicit {
			log.Println(`Warning: Java is not available, so the CA can't be automatically installed in Java's trust store! ⚠️`)
		}
		return
	}
	if !hasKeytool {
		tx.record(trustStoreJava, outcomeUnavailable, errors.New("keytool is not available"))
		log.Println(`Warning: "keytool" is not available, so the CA can't be automatically installed in Java's trust store! ⚠️`)
		return
	}
	if cacertsPath == "" {
		tx.record(trustStoreJava, outcomeUnavailable, errors.New("the Java cacerts file is not available"))
		log.Println(`Warning: the Java "cacerts" trust store is not available, so the CA can't be automatically installed! ⚠️`)
		return
	}
	if installed, err := m.checkJava(); err == nil && installed {
		tx.record(trustStoreJava, outcomeAlreadyInstalled, nil)
		log.Println("The local CA is already installed in Java's trust store! 👍")
		return
	}

	if err := m.installJava(tx.caFile); err != nil {
		if installed, verifyErr := m.checkJava(); verifyErr == nil && installed {
			tx.record(trustStoreJava, outcomeInstalled, err)
			log.Printf("Warning: keytool reported an error, but the local CA is present in Java's trust store: %v ⚠️", err)
			return
		}
		tx.record(trustStoreJava, outcomeFailed, err)
		log.Printf("Warning: failed to install the local CA in Java's trust store: %v ⚠️", err)
		return
	}
	installed, err := m.checkJava()
	if err != nil {
		tx.record(trustStoreJava, outcomeFailed, err)
		log.Printf("Warning: Java's trust store could not be verified after the import: %v ⚠️", err)
		return
	}
	if !installed {
		tx.record(trustStoreJava, outcomeFailed, errors.New("the CA was not found in Java's trust store after the import"))
		log.Println("Warning: the local CA was not found in Java's trust store after the import! ⚠️")
		return
	}

	tx.record(trustStoreJava, outcomeInstalled, nil)
	log.Println("The local CA is now installed in Java's trust store! ☕️")
}

func (m *mkcert) uninstall() error {
	tx, err := newTrustTransaction(m, true)
	if err != nil {
		return err
	}
	defer tx.close()

	for _, store := range tx.stores {
		switch store {
		case trustStoreSystem:
			m.uninstallSystem(tx)
		case trustStoreNSS:
			m.uninstallNSSStore(tx)
		case trustStoreJava:
			m.uninstallJavaStore(tx)
		}
	}
	return tx.reportUninstall()
}

func (m *mkcert) uninstallSystem(tx *trustTransaction) {
	removed, err := m.uninstallPlatform(tx.caFile)
	if err != nil {
		switch {
		case errors.Is(err, errStoreUnsupported):
			tx.record(trustStoreSystem, outcomeUnavailable, err)
		case errors.Is(err, errCertNotInstalled):
			tx.record(trustStoreSystem, outcomeNotInstalled, err)
			log.Print("The local CA is not installed in the system trust store. 🤷")
		default:
			tx.record(trustStoreSystem, outcomeFailed, err)
			log.Printf("Warning: failed to uninstall the local CA from the system trust store: %v ⚠️", err)
		}
		return
	}
	if !removed {
		tx.record(trustStoreSystem, outcomeNotInstalled, nil)
		log.Print("The local CA is not installed in the system trust store. 🤷")
		return
	}
	tx.record(trustStoreSystem, outcomeUninstalled, nil)
	log.Print("The local CA is now uninstalled from the system trust store(s)! 👋")
}

func (m *mkcert) uninstallNSSStore(tx *trustTransaction) {
	if !hasNSS {
		tx.record(trustStoreNSS, outcomeUnavailable, errors.New("NSS is not available"))
		return
	}
	if !hasCertutil {
		tx.record(trustStoreNSS, outcomeUnavailable, errors.New("certutil is not available"))
		if CertutilInstallHelp != "" {
			log.Print("")
			log.Printf(`Warning: "certutil" is not available, so the CA can't be automatically uninstalled from %s (if it was ever installed)! ⚠️`, NSSBrowsers)
			log.Printf(`You can install "certutil" with "%s" and re-run "mkcert -uninstall" 👈`, CertutilInstallHelp)
			log.Print("")
		}
		return
	}

	removed, err := m.uninstallNSS(tx.caName)
	if err != nil {
		if !m.checkNSS() {
			tx.record(trustStoreNSS, outcomeNotInstalled, err)
			log.Printf("Warning: certutil reported an error, but the local CA is not present in the %s trust store: %v ⚠️", NSSBrowsers, err)
			return
		}
		tx.record(trustStoreNSS, outcomeFailed, err)
		log.Printf("Warning: failed to uninstall the local CA from the %s trust store: %v ⚠️", NSSBrowsers, err)
		return
	}
	if removed == 0 {
		tx.record(trustStoreNSS, outcomeNotInstalled, nil)
		log.Printf("The local CA is not installed in the %s trust store. 🤷", NSSBrowsers)
		return
	}
	tx.record(trustStoreNSS, outcomeUninstalled, nil)
	log.Printf("The local CA is now uninstalled from the %s trust store(s)! 👋", NSSBrowsers)
}

func (m *mkcert) uninstallJavaStore(tx *trustTransaction) {
	if !hasJava {
		tx.record(trustStoreJava, outcomeUnavailable, errors.New("Java is not available"))
		return
	}
	if !hasKeytool {
		tx.record(trustStoreJava, outcomeUnavailable, errors.New("keytool is not available"))
		log.Print("")
		log.Println(`Warning: "keytool" is not available, so the CA can't be automatically uninstalled from Java's trust store (if it was ever installed)! ⚠️`)
		log.Print("")
		return
	}
	if cacertsPath == "" {
		tx.record(trustStoreJava, outcomeUnavailable, errors.New("the Java cacerts file is not available"))
		log.Println(`Warning: the Java "cacerts" trust store is not available, so the CA can't be automatically uninstalled! ⚠️`)
		return
	}
	if installed, err := m.checkJava(); err == nil && !installed {
		tx.record(trustStoreJava, outcomeNotInstalled, nil)
		log.Println("The local CA is not installed in Java's trust store. 🤷")
		return
	}

	removed, err := m.uninstallJava(tx.caName)
	if err != nil {
		if installed, verifyErr := m.checkJava(); verifyErr == nil && !installed {
			tx.record(trustStoreJava, outcomeNotInstalled, err)
			log.Printf("Warning: keytool reported an error, but the local CA is not present in Java's trust store: %v ⚠️", err)
			return
		}
		tx.record(trustStoreJava, outcomeFailed, err)
		log.Printf("Warning: failed to uninstall the local CA from Java's trust store: %v ⚠️", err)
		return
	}
	if !removed {
		tx.record(trustStoreJava, outcomeNotInstalled, nil)
		log.Println("The local CA is not installed in Java's trust store. 🤷")
		return
	}
	tx.record(trustStoreJava, outcomeUninstalled, nil)
	log.Println("The local CA is now uninstalled from Java's trust store! ☕️")
}

func (m *mkcert) checkPlatform() bool {
	if m.ignoreCheckFailure {
		return true
	}

	_, err := m.caCert.Verify(x509.VerifyOptions{})
	return err == nil
}

func storeEnabled(name string) bool {
	for _, store := range selectedTrustStores() {
		if string(store) == name {
			return true
		}
	}
	return false
}

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s", msg, err)
	}
}

func fatalIfCmdErr(err error, cmd string, out []byte) {
	if err != nil {
		log.Fatalf("ERROR: failed to execute \"%s\": %s\n\n%s\n", cmd, err, out)
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func binaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

var sudoWarningOnce sync.Once

func commandWithSudo(cmd ...string) *exec.Cmd {
	if u, err := user.Current(); err == nil && u.Uid == "0" {
		return exec.Command(cmd[0], cmd[1:]...)
	}
	if !binaryExists("sudo") {
		sudoWarningOnce.Do(func() {
			log.Println(`Warning: "sudo" is not available, and mkcert is not running as root. The (un)install operation might fail. ⚠️`)
		})
		return exec.Command(cmd[0], cmd[1:]...)
	}
	return exec.Command("sudo", append([]string{"--prompt=Sudo password:", "--"}, cmd...)...)
}
