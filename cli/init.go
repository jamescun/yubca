package cli

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/go-piv/piv-go/piv"
	"github.com/spf13/cobra"

	"github.com/jamescun/yubca/config"
)

var initCA = &cobra.Command{
	Use:   "init",
	Short: "initialize certificate authority",

	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := readConfig()
		if err != nil {
			return fmt.Errorf("could not read config: %w", err)
		}

		slot, ok := getSlot(cfg.Slot)
		if !ok {
			return fmt.Errorf("unknown slot type %q", cfg.Slot)
		}

		algo, ok := getAlgorithm(cfg.Algorithm)
		if !ok {
			return fmt.Errorf("unknown algorithm %q", cfg.Algorithm)
		}

		validity, err := time.ParseDuration(cfg.Validity)
		if err != nil {
			return fmt.Errorf("invalid validity duration: %w", err)
		}

		mgmt, err := readManagementKey()
		if err != nil {
			return fmt.Errorf("could not read management key: %w", err)
		}

		// check there isn't an existing certificate authority on the slot.
		_, err = key.Certificate(slot)
		if err == nil {
			return fmt.Errorf("a certificate authority is already configured on slot %q", cfg.Slot)
		}

		publicKey, err := key.GenerateKey(mgmt, slot, piv.Key{
			Algorithm:   algo,
			PINPolicy:   piv.PINPolicyAlways,
			TouchPolicy: piv.TouchPolicyAlways,
		})
		if err != nil {
			return fmt.Errorf("could not generate public key: %w", err)
		}

		privateKey, err := key.PrivateKey(slot, publicKey, piv.KeyAuth{
			PINPrompt: func() (string, error) {
				pin, err := readPIN()
				if err != nil {
					return pin, err
				}

				// this is a workaround to display this prompt after the PIN prompt.
				fmt.Println("Please touch your YubiKey...")

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
			Issuer:                getDN(cfg.Subject),
			Subject:               getDN(cfg.Subject),
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(validity),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			CRLDistributionPoints: cfg.CRL,
		}

		certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, publicKey, privateKey)
		if err != nil {
			return fmt.Errorf("could not sign certificate: %w", err)
		}

		signedCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return fmt.Errorf("could not parse signed certificate: %w", err)
		}

		err = key.SetCertificate(mgmt, slot, signedCert)
		if err != nil {
			return fmt.Errorf("could not set certificate on slot %q: %w", cfg.Slot, err)
		}

		fmt.Println("Done!")

		return nil
	},
}

func getAlgorithm(algo string) (piv.Algorithm, bool) {
	switch algo {
	case "ec256", "EC256":
		return piv.AlgorithmEC256, true

	case "ec384", "EC384":
		return piv.AlgorithmEC384, true

	case "ed25519", "ED25519":
		return piv.AlgorithmEd25519, true

	case "rsa1024", "RSA1024":
		return piv.AlgorithmRSA1024, true

	case "rsa2048", "RSA2048":
		return piv.AlgorithmRSA2048, true

	default:
		return 0, false
	}
}

func getDN(dn *config.DN) pkix.Name {
	return pkix.Name{
		Country:            dn.C,
		Organization:       dn.O,
		OrganizationalUnit: dn.OU,
		Province:           dn.ST,
		Locality:           dn.L,
		CommonName:         dn.CN,
	}
}
