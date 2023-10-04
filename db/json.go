package db

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// JSONRecord is an individual certificate that has been signed by the
// Certificate Authority.
type JSONRecord struct {
	Serial      string    `json:"serial"`
	Fingerprint string    `json:"fingerprint"`
	CommonName  string    `json:"commonName"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	DNSNames    []string  `json:"dnsNames,omitempty"`
}

// JSON is a DB implementation backed by an append-only newline delimited JSON
// file.
type JSON struct {
	path  string
	write sync.Mutex
}

func NewJSON(path string) (*JSON, error) {
	return &JSON{path: path}, nil
}

func (j *JSON) AppendCertificate(ctx context.Context, cert *x509.Certificate) error {
	j.write.Lock()
	defer j.write.Unlock()

	record := &JSONRecord{
		Serial:      hex.EncodeToString(cert.SerialNumber.Bytes()),
		Fingerprint: sha256fingerprint(cert),
		CommonName:  cert.Subject.CommonName,
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		DNSNames:    cert.DNSNames,
	}

	file, err := os.OpenFile(j.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	err = json.NewEncoder(file).Encode(record)
	if err != nil {
		return fmt.Errorf("could not marshal record: %w", err)
	}

	return nil
}

func sha256fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "SHA256:" + base64.StdEncoding.EncodeToString(sum[:])
}
