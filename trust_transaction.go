// Copyright 2026 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

// A trustTransaction freezes the CA identity and the set of trust stores for
// one install or uninstall operation. Every store in the transaction consumes
// the same CA bytes, and every result is recorded before anything is reported.
type trustTransaction struct {
	ca        *x509.Certificate
	caName    string
	caSHA256  string
	caPEM     []byte
	caFile    string
	stores    []trustStore
	results   map[trustStore]storeResult
	uninstall bool
	explicit  bool
}

type trustStore string

const (
	trustStoreSystem trustStore = "system"
	trustStoreNSS    trustStore = "nss"
	trustStoreJava   trustStore = "java"
)

var allTrustStores = []trustStore{trustStoreSystem, trustStoreNSS, trustStoreJava}

type storeOutcome int

const (
	outcomeUnavailable storeOutcome = iota
	outcomeInstalled
	outcomeAlreadyInstalled
	outcomeUninstalled
	outcomeNotInstalled
	outcomeFailed
)

type storeResult struct {
	store   trustStore
	outcome storeOutcome
	err     error
}

var (
	errStoreUnsupported = errors.New("trust store is not supported")
	errCertNotInstalled = errors.New("certificate is not installed")
	errNoNSSProfiles    = errors.New("no NSS security databases found")
	errNSSVerification  = errors.New("NSS trust store verification failed")
)

func newTrustTransaction(m *mkcert, uninstall bool) (*trustTransaction, error) {
	if m.caCert == nil {
		return nil, errors.New("the CA certificate is not loaded")
	}

	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: m.caCert.Raw,
	})
	sum := sha256.Sum256(m.caCert.Raw)
	tx := &trustTransaction{
		ca:        m.caCert,
		caName:    m.caUniqueName(),
		caSHA256:  hex.EncodeToString(sum[:]),
		caPEM:     caPEM,
		stores:    selectedTrustStores(),
		results:   make(map[trustStore]storeResult),
		uninstall: uninstall,
		explicit:  strings.TrimSpace(os.Getenv("TRUST_STORES")) != "",
	}
	if len(tx.stores) == 0 {
		// Keep the historical behavior of TRUST_STORES=none (and unknown
		// names): the trust-store phase is a no-op, while certificate
		// issuance can still proceed.
		return tx, nil
	}

	// Commands such as security(1), certutil(1) and keytool(1) take a file
	// path. Give all of them a private, immutable snapshot so rotating
	// rootCA.pem in CAROOT can't make the stores consume different CAs.
	f, err := ioutil.TempFile("", "mkcert-ca-*.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to create a temporary CA certificate: %w", err)
	}
	tx.caFile = f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			f.Close()
			os.Remove(tx.caFile)
		}
	}()

	if err := f.Chmod(0644); err != nil {
		return nil, fmt.Errorf("failed to set permissions on the temporary CA certificate: %w", err)
	}
	if _, err := f.Write(caPEM); err != nil {
		return nil, fmt.Errorf("failed to write the temporary CA certificate: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("failed to close the temporary CA certificate: %w", err)
	}
	cleanup = false
	return tx, nil
}

func (tx *trustTransaction) close() {
	if tx.caFile != "" {
		os.Remove(tx.caFile)
	}
}

func (tx *trustTransaction) record(store trustStore, outcome storeOutcome, err error) {
	tx.results[store] = storeResult{store: store, outcome: outcome, err: err}
}

func selectedTrustStores() []trustStore {
	value := strings.TrimSpace(os.Getenv("TRUST_STORES"))
	if value == "" {
		return append([]trustStore(nil), allTrustStores...)
	}

	enabled := make(map[trustStore]bool)
	for _, raw := range strings.Split(value, ",") {
		switch store := trustStore(strings.TrimSpace(raw)); store {
		case trustStoreSystem, trustStoreNSS, trustStoreJava:
			enabled[store] = true
		}
	}

	var stores []trustStore
	for _, store := range allTrustStores {
		if enabled[store] {
			stores = append(stores, store)
		}
	}
	return stores
}

func displayTrustStore(store trustStore) string {
	switch store {
	case trustStoreSystem:
		return "system"
	case trustStoreNSS:
		return NSSBrowsers
	case trustStoreJava:
		return "Java"
	default:
		return string(store)
	}
}

func displayTrustStores(stores []string) string {
	if len(stores) == 0 {
		return "none"
	}
	return strings.Join(stores, ", ")
}

func (tx *trustTransaction) namedStores(outcomes ...storeOutcome) []string {
	var stores []string
	for _, store := range tx.stores {
		result, ok := tx.results[store]
		if !ok {
			continue
		}
		for _, outcome := range outcomes {
			if result.outcome == outcome {
				stores = append(stores, displayTrustStore(store))
				break
			}
		}
	}
	return stores
}

func (tx *trustTransaction) reportInstall() error {
	failed := tx.namedStores(outcomeFailed)
	installedNow := tx.namedStores(outcomeInstalled)
	alreadyInstalled := tx.namedStores(outcomeAlreadyInstalled)
	installed := append(append([]string{}, installedNow...), alreadyInstalled...)

	if len(failed) > 0 {
		log.Printf("Warning: the local CA installation is incomplete; failed: %s ⚠️", displayTrustStores(failed))
		return fmt.Errorf("failed to install the local CA in %s", displayTrustStores(failed))
	}
	if len(installed) == len(tx.stores) {
		if len(tx.stores) > 1 {
			if len(installedNow) == 0 {
				log.Print("The local CA is already installed in all selected trust stores! 👍")
			} else {
				log.Print("The local CA is now installed in all selected trust stores! 🎉")
			}
		}
		return nil
	}
	return nil
}

func (tx *trustTransaction) reportUninstall() error {
	failed := tx.namedStores(outcomeFailed)
	uninstalled := tx.namedStores(outcomeUninstalled)
	notInstalled := tx.namedStores(outcomeNotInstalled)

	if len(failed) > 0 {
		log.Printf("Warning: the local CA uninstall is incomplete; failed: %s ⚠️", displayTrustStores(failed))
		return fmt.Errorf("failed to uninstall the local CA from %s", displayTrustStores(failed))
	}
	if len(uninstalled) == len(tx.stores) {
		if len(tx.stores) > 1 {
			log.Print("The local CA is now uninstalled from all selected trust stores! 👋")
		}
		return nil
	}
	if len(uninstalled) == 0 && len(notInstalled) > 0 {
		log.Print("The local CA is not installed in any of the selected trust stores. 🤷")
	}
	return nil
}
