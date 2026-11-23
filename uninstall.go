// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

const (
	uninstallJournalName    = ".mkcert-uninstall.json"
	uninstallJournalVersion = 1
)

const (
	storeSystem = "system"
	storeNSS    = "nss"
	storeJava   = "java"
)

const (
	resultRemoved     = "removed"
	resultAbsent      = "absent"
	resultFailed      = "failed"
	resultUnavailable = "unavailable"
)

// storeRemovalResult is the evidence for one store in a revocation
// transaction. It is written to the journal after every attempt so a restart
// can report what happened without guessing from the final trust store state.
type storeRemovalResult struct {
	Store  string `json:"store"`
	Serial string `json:"serial"`
	Status string `json:"status"`
	Stage  string `json:"stage,omitempty"`
	Detail string `json:"detail,omitempty"`
}

func (r storeRemovalResult) succeeded() bool {
	return r.Status == resultRemoved || r.Status == resultAbsent
}

func (r storeRemovalResult) failed() bool {
	return r.Status == resultFailed
}

// revocationJournal binds the CA snapshot, the target store set and the
// per-store evidence to one uninstall attempt. In particular, resuming an
// interrupted uninstall never falls back to whatever rootCA.pem happens to
// contain at restart time.
type revocationJournal struct {
	Version     int                           `json:"version"`
	Serial      string                        `json:"serial"`
	Fingerprint string                        `json:"fingerprint"`
	Certificate string                        `json:"certificate"`
	Stores      []string                      `json:"stores"`
	Results     map[string]storeRemovalResult `json:"results,omitempty"`
	Files       *storeRemovalResult           `json:"files,omitempty"`
}

type caSnapshot struct {
	Cert        *x509.Certificate
	Certificate string
	Serial      string
	Fingerprint string
}

func newCASnapshot(cert *x509.Certificate, certPEM []byte) *caSnapshot {
	sum := sha256.Sum256(cert.Raw)
	return &caSnapshot{
		Cert:        cert,
		Certificate: string(certPEM),
		Serial:      cert.SerialNumber.String(),
		Fingerprint: hex.EncodeToString(sum[:]),
	}
}

func (m *mkcert) uninstall() {
	journal, snapshot, err := m.beginUninstall()
	if err != nil {
		log.Fatalf("ERROR: failed to prepare the CA uninstall: %v", err)
	}
	if journal == nil {
		log.Print("No local CA to uninstall.")
		return
	}
	m.caCert = snapshot.Cert

	incomplete, commandFailure := false, false
	for _, store := range journal.Stores {
		result := m.uninstallStore(store, snapshot.Serial)
		journal.Results[store] = result
		if err := writeRevocationJournal(m.CAROOT, journal); err != nil {
			log.Fatalf("ERROR: failed to record the CA uninstall: %v", err)
		}

		log.Print(formatStoreRemovalResult(result))
		if !result.succeeded() {
			incomplete = true
		}
		if result.failed() {
			commandFailure = true
		}
		if result.Status == resultUnavailable {
			printUnavailableStoreHelp(store)
		}
	}

	if len(journal.Stores) == 0 {
		incomplete = true
	}
	if incomplete {
		log.Printf("Uninstall incomplete for CA serial %s; the local CA files were kept so it can be retried.", snapshot.Serial)
		if commandFailure {
			log.Fatalf("ERROR: failed to uninstall CA serial %s from all enabled trust stores", snapshot.Serial)
		}
		return
	}

	removed, different, err := m.removeCAFiles(snapshot)
	if err != nil {
		failure := storeRemovalResult{
			Store: "files", Serial: snapshot.Serial, Status: resultFailed,
			Stage: "remove local CA files", Detail: err.Error(),
		}
		journal.Files = &failure
		_ = writeRevocationJournal(m.CAROOT, journal)
		log.Print(formatStoreRemovalResult(failure))
		log.Fatalf("ERROR: failed to remove the local CA files for serial %s: %v", snapshot.Serial, err)
	}

	if different {
		// The requested CA was revoked, but CAROOT now belongs to another CA.
		// Keep that CA and its files entirely out of this transaction.
		log.Printf("Uninstalled CA serial %s from the selected trust stores; a different local CA remains in %q and was not modified.", snapshot.Serial, m.CAROOT)
		journal.Files = &storeRemovalResult{
			Store: "files", Serial: snapshot.Serial, Status: resultAbsent,
			Stage: "different local CA retained",
		}
		if err := writeRevocationJournal(m.CAROOT, journal); err != nil {
			log.Fatalf("ERROR: failed to record the CA uninstall: %v", err)
		}
	} else {
		status := resultAbsent
		if removed {
			status = resultRemoved
		}
		journal.Files = &storeRemovalResult{
			Store: "files", Serial: snapshot.Serial, Status: status,
			Stage: "remove local CA files",
		}
		if err := writeRevocationJournal(m.CAROOT, journal); err != nil {
			log.Fatalf("ERROR: failed to record the CA uninstall: %v", err)
		}
	}

	if err := os.Remove(filepath.Join(m.CAROOT, uninstallJournalName)); err != nil && !os.IsNotExist(err) {
		log.Fatalf("ERROR: failed to finish the CA uninstall: %v", err)
	}

	if !different {
		printCompletedUninstall(journal.Stores)
	}
}

func (m *mkcert) uninstallStore(store, serial string) storeRemovalResult {
	result := storeRemovalResult{Store: store, Serial: serial}
	switch store {
	case storeSystem:
		result = m.removeFromPlatform()
	case storeNSS:
		if !hasCertutil {
			result.Status = resultUnavailable
			result.Stage = "find certutil"
			result.Detail = `"certutil" is not available`
			break
		}
		result = m.removeFromNSS()
	case storeJava:
		if !hasKeytool {
			result.Status = resultUnavailable
			result.Stage = "find keytool"
			result.Detail = `"keytool" is not available`
			break
		}
		result = m.removeFromJava()
	default:
		result.Status = resultFailed
		result.Stage = "resolve trust store"
		result.Detail = "unknown trust store"
	}
	result.Store = store
	result.Serial = serial
	return result
}

func (m *mkcert) beginUninstall() (*revocationJournal, *caSnapshot, error) {
	journal, err := readRevocationJournal(m.CAROOT)
	if err != nil {
		return nil, nil, err
	}
	if journal != nil {
		cert, err := parseJournalCertificate(journal)
		if err != nil {
			return nil, nil, err
		}
		return journal, newCASnapshot(cert, []byte(journal.Certificate)), nil
	}

	if m.caCert != nil {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.caCert.Raw})
		snapshot := newCASnapshot(m.caCert, certPEM)
		journal = &revocationJournal{
			Version:     uninstallJournalVersion,
			Serial:      snapshot.Serial,
			Fingerprint: snapshot.Fingerprint,
			Certificate: snapshot.Certificate,
			Stores:      m.uninstallTargetStores(),
			Results:     make(map[string]storeRemovalResult),
		}
		if err := writeRevocationJournal(m.CAROOT, journal); err != nil {
			return nil, nil, err
		}
		return journal, snapshot, nil
	}

	certPath := filepath.Join(m.CAROOT, rootName)
	if !pathExists(certPath) {
		return nil, nil, nil
	}
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read the CA certificate: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("failed to read the CA certificate: unexpected content")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse the CA certificate: %w", err)
	}

	snapshot := newCASnapshot(cert, certPEM)
	journal = &revocationJournal{
		Version:     uninstallJournalVersion,
		Serial:      snapshot.Serial,
		Fingerprint: snapshot.Fingerprint,
		Certificate: string(certPEM),
		Stores:      m.uninstallTargetStores(),
		Results:     make(map[string]storeRemovalResult),
	}
	if err := writeRevocationJournal(m.CAROOT, journal); err != nil {
		return nil, nil, err
	}
	return journal, snapshot, nil
}

func (m *mkcert) uninstallTargetStores() []string {
	var stores []string
	if storeEnabled(storeSystem) {
		stores = append(stores, storeSystem)
	}
	if storeEnabled(storeNSS) && hasNSS {
		stores = append(stores, storeNSS)
	}
	if storeEnabled(storeJava) && hasJava {
		stores = append(stores, storeJava)
	}
	return stores
}

func readRevocationJournal(caroot string) (*revocationJournal, error) {
	data, err := ioutil.ReadFile(filepath.Join(caroot, uninstallJournalName))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read the uninstall journal: %w", err)
	}

	var journal revocationJournal
	if err := json.Unmarshal(data, &journal); err != nil {
		return nil, fmt.Errorf("failed to parse the uninstall journal: %w", err)
	}
	if journal.Version != uninstallJournalVersion {
		return nil, fmt.Errorf("unsupported uninstall journal version %d", journal.Version)
	}
	if journal.Certificate == "" {
		return nil, errors.New("uninstall journal has no CA certificate")
	}
	if _, err := parseJournalCertificate(&journal); err != nil {
		return nil, err
	}
	if journal.Results == nil {
		journal.Results = make(map[string]storeRemovalResult)
	}

	seen := make(map[string]bool)
	for _, store := range journal.Stores {
		switch store {
		case storeSystem, storeNSS, storeJava:
		default:
			return nil, fmt.Errorf("uninstall journal contains unknown trust store %q", store)
		}
		if seen[store] {
			return nil, fmt.Errorf("uninstall journal contains duplicate trust store %q", store)
		}
		seen[store] = true
	}
	return &journal, nil
}

func parseJournalCertificate(journal *revocationJournal) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(journal.Certificate))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("uninstall journal contains an invalid CA certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("uninstall journal contains an invalid CA certificate: %w", err)
	}
	if journal.Serial != "" && journal.Serial != cert.SerialNumber.String() {
		return nil, fmt.Errorf("uninstall journal serial %q does not match its certificate", journal.Serial)
	}
	sum := sha256.Sum256(cert.Raw)
	if journal.Fingerprint != "" && journal.Fingerprint != hex.EncodeToString(sum[:]) {
		return nil, errors.New("uninstall journal certificate fingerprint does not match")
	}
	return cert, nil
}

func writeRevocationJournal(caroot string, journal *revocationJournal) error {
	if journal.Results == nil {
		journal.Results = make(map[string]storeRemovalResult)
	}
	data, err := json.MarshalIndent(journal, "", "\t")
	if err != nil {
		return fmt.Errorf("failed to serialize the uninstall journal: %w", err)
	}
	data = append(data, '\n')

	temp, err := ioutil.TempFile(caroot, ".mkcert-uninstall-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create the uninstall journal: %w", err)
	}
	tempName := temp.Name()
	cleanup := func(cause error) error {
		temp.Close()
		os.Remove(tempName)
		return cause
	}
	if err := temp.Chmod(0600); err != nil {
		return cleanup(err)
	}
	if _, err := temp.Write(data); err != nil {
		return cleanup(err)
	}
	if err := temp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := temp.Close(); err != nil {
		os.Remove(tempName)
		return err
	}
	if err := os.Rename(tempName, filepath.Join(caroot, uninstallJournalName)); err != nil {
		os.Remove(tempName)
		return fmt.Errorf("failed to commit the uninstall journal: %w", err)
	}
	return nil
}

func formatStoreRemovalResult(result storeRemovalResult) string {
	line := fmt.Sprintf("Uninstall store=%s serial=%s status=%s", result.Store, result.Serial, result.Status)
	if result.Stage != "" {
		line += " stage=" + result.Stage
	}
	if result.Detail != "" {
		line += ": " + result.Detail
	}
	return line
}

func printUnavailableStoreHelp(store string) {
	switch store {
	case storeNSS:
		if CertutilInstallHelp == "" {
			log.Printf(`Note: %s support is not available on your platform. ℹ️`, NSSBrowsers)
			return
		}
		log.Printf(`Warning: "certutil" is not available, so the CA can't be automatically uninstalled from %s (if it was ever installed)! ⚠️`, NSSBrowsers)
		log.Printf(`You can install "certutil" with "%s" and re-run "mkcert -uninstall" 👈`, CertutilInstallHelp)
	case storeJava:
		log.Println(`Warning: "keytool" is not available, so the CA can't be automatically uninstalled from Java's trust store (if it was ever installed)! ⚠️`)
	}
}

func printCompletedUninstall(stores []string) {
	enabled := make(map[string]bool)
	for _, store := range stores {
		enabled[store] = true
	}
	if enabled[storeSystem] {
		log.Print("The local CA is now uninstalled from the system trust store(s)! 👋")
	}
	if enabled[storeNSS] {
		log.Printf("The local CA is now uninstalled from the %s trust store(s)! 👋", NSSBrowsers)
	}
	if enabled[storeJava] {
		log.Println("The local CA is now uninstalled from Java's trust store! ☕️")
	}
	log.Print("")
}

// removeCAFiles removes only the CA files that are byte-for-byte tied to the
// revocation transaction. A CA rotated into CAROOT after the transaction
// started is left completely untouched.
func (m *mkcert) removeCAFiles(snapshot *caSnapshot) (removed, different bool, err error) {
	certPath := filepath.Join(m.CAROOT, rootName)
	keyPath := filepath.Join(m.CAROOT, rootKeyName)

	for _, path := range []string{certPath, keyPath} {
		staged := filepath.Join(m.CAROOT, "."+filepath.Base(path)+".uninstall-"+snapshot.Fingerprint[:16])
		if err := os.Remove(staged); err != nil && !os.IsNotExist(err) {
			return false, false, fmt.Errorf("failed to clean an interrupted uninstall of %s: %w", path, err)
		}
	}

	certExists, certMatches, err := certificateFileMatches(certPath, snapshot.Cert)
	if err != nil {
		return false, false, err
	}
	keyExists, keyMatches, err := privateKeyFileMatches(keyPath, snapshot.Cert)
	if err != nil {
		return false, false, err
	}
	if (certExists && !certMatches) || (keyExists && !keyMatches) {
		return false, true, nil
	}
	if !certExists && !keyExists {
		return false, false, nil
	}

	type stagedFile struct{ from, to string }
	var staged []stagedFile
	rollback := func(cause error) (bool, bool, error) {
		for i := len(staged) - 1; i >= 0; i-- {
			if err := os.Rename(staged[i].to, staged[i].from); err != nil {
				return false, false, fmt.Errorf("%v; failed to restore %s: %v", cause, staged[i].from, err)
			}
		}
		return false, false, cause
	}

	stage := func(path string) error {
		if !pathExists(path) {
			return nil
		}
		to := filepath.Join(m.CAROOT, "."+filepath.Base(path)+".uninstall-"+snapshot.Fingerprint[:16])
		if pathExists(to) {
			if err := os.Remove(to); err != nil {
				return fmt.Errorf("failed to clear stale uninstall file %s: %w", to, err)
			}
		}
		if err := os.Rename(path, to); err != nil {
			return fmt.Errorf("failed to stage %s for removal: %w", path, err)
		}
		staged = append(staged, stagedFile{from: path, to: to})
		return nil
	}

	if certExists {
		if err := stage(certPath); err != nil {
			return rollback(err)
		}
	}
	if keyExists {
		if err := stage(keyPath); err != nil {
			return rollback(err)
		}
	}

	for _, file := range staged {
		if err := os.Remove(file.to); err != nil {
			return false, false, fmt.Errorf("failed to remove %s: %w", file.from, err)
		}
	}
	return len(staged) > 0, false, nil
}

func certificateFileMatches(path string, want *x509.Certificate) (exists, matches bool, err error) {
	data, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("failed to read %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return true, false, fmt.Errorf("%s does not contain a CA certificate", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true, false, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	return true, bytes.Equal(cert.Raw, want.Raw), nil
}

func privateKeyFileMatches(path string, cert *x509.Certificate) (exists, matches bool, err error) {
	data, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("failed to read %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return true, false, fmt.Errorf("%s does not contain a private key", path)
	}

	var key interface{}
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		err = fmt.Errorf("unexpected private key type %q", block.Type)
	}
	if err != nil {
		return true, false, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return true, false, fmt.Errorf("%s does not contain a usable private key", path)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return true, false, fmt.Errorf("failed to encode the public key from %s: %w", path, err)
	}
	return true, bytes.Equal(publicKey, cert.RawSubjectPublicKeyInfo), nil
}
