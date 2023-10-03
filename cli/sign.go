package cli

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/go-piv/piv-go/piv"
	"github.com/spf13/cobra"
)

var (
	csrPath     string
	isCA        bool
	serverAuth  bool
	clientAuth  bool
	validityStr string
)

var signCSR = &cobra.Command{
	Use:   "sign",
	Short: "sign a certificate signing request",

	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := readConfig()
		if err != nil {
			return fmt.Errorf("could not read config: %w", err)
		}

		validity, err := time.ParseDuration(validityStr)
		if err != nil {
			return fmt.Errorf("invalid validity duration: %w", err)
		}

		slot, ok := getSlot(cfg.Slot)
		if !ok {
			return fmt.Errorf("unknown slot type %q", cfg.Slot)
		}

		csr, err := readCSR(csrPath)
		if err != nil {
			return fmt.Errorf("could not read certificate request: %w", err)
		}

		caCert, err := key.Certificate(slot)
		if errors.Is(err, piv.ErrNotFound) {
			return fmt.Errorf("no certificate authority configured on slot %q", cfg.Slot)
		} else if err != nil {
			return fmt.Errorf("could not get certificate authority: %w", err)
		}

		caPrivateKey, err := key.PrivateKey(slot, caCert.PublicKey, piv.KeyAuth{
			PINPrompt: func() (string, error) {
				pin, err := readPIN()
				if err != nil {
					return pin, err
				}

				// this is a workaround to display this prompt after the PIN prompt.
				fmt.Print("Please touch your YubiKey...\n\n")

				return pin, nil
			},
		})
		if err != nil {
			return fmt.Errorf("could not get private key signer: %w", err)
		}

		serialNumber, err := randomSerial()
		if err != nil {
			return fmt.Errorf("could not generate random serial: %w", err)
		}

		cert := &x509.Certificate{
			Version:               1,
			SerialNumber:          serialNumber,
			Issuer:                caCert.Subject,
			Subject:               csr.Subject,
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(validity),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  isCA,
			DNSNames:              csr.DNSNames,
			IPAddresses:           csr.IPAddresses,
			URIs:                  csr.URIs,
			EmailAddresses:        csr.EmailAddresses,
		}

		if isCA {
			cert.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}

		if serverAuth {
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		}

		if clientAuth {
			cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		}

		certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, csr.PublicKey, caPrivateKey)
		if err != nil {
			return fmt.Errorf("could not sign certificate: %w", err)
		}

		pem.Encode(os.Stdout, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		})

		return nil
	},
}

func init() {
	signCSR.Flags().StringVar(&csrPath, "csr", "csr.pem", "path to certificate signing request file")
	signCSR.Flags().BoolVar(&isCA, "ca", false, "enable certificate as intermediate of certificate authority")
	signCSR.Flags().BoolVar(&serverAuth, "server", false, "enable server authentication usage for key")
	signCSR.Flags().BoolVar(&clientAuth, "client", false, "enable client authentication for key")
	signCSR.Flags().StringVar(&validityStr, "validity", "8766h", "maximum period before certificate expires")
}

func readCSR(path string) (*x509.CertificateRequest, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("could not decode PEM block")
	} else if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("expected CERTIFICATE REQUEST, got %q", block.Type)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	return csr, nil
}

// randomSerial generates a random 16-byte big.Int to be used for the serial
// number of a Certificate.
func randomSerial() (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("could not read random source: %w", err)
	}

	return new(big.Int).SetBytes(b), nil
}
