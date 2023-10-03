package cli

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/go-piv/piv-go/piv"
	"github.com/spf13/cobra"
)

var inspectCA = &cobra.Command{
	Use:   "inspect",
	Short: "view metadata about a certificate authority",

	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := readConfig()
		if err != nil {
			return fmt.Errorf("could not read config: %w", err)
		}

		slot, ok := getSlot(cfg.Slot)
		if !ok {
			return fmt.Errorf("unknown slot type %q", cfg.Slot)
		}

		cert, err := key.Certificate(slot)
		if errors.Is(err, piv.ErrNotFound) {
			return fmt.Errorf("no certificate authority configured on slot %q", cfg.Slot)
		} else if err != nil {
			return fmt.Errorf("could not get certificate authority: %w", err)
		}

		printCertificate(os.Stdout, cert)

		return nil
	},
}

func printCertificate(w io.Writer, cert *x509.Certificate) {
	fmt.Fprintf(w, "Version:        %d\nSerial:         %x\n", cert.Version, cert.SerialNumber.Bytes())
	fmt.Fprintf(w, "Issuer:         %s\nSubject:        %s\n", pkixStr(cert.Issuer), pkixStr(cert.Subject))
	fmt.Fprintf(w, "Algorithm:      %s\n", cert.SignatureAlgorithm.String())

	publicKey, _ := sha256publicKey(cert.PublicKey)
	fingerprint, _ := sha256certificate(cert)
	fmt.Fprintf(w, "Public Key:     %s\nFingerprint:    %s\n", publicKey, fingerprint)

	if len(cert.AuthorityKeyId) > 0 {
		fmt.Fprintf(w, "AuthorityKeyID: %x\n", cert.AuthorityKeyId)
	}

	if len(cert.SubjectKeyId) > 0 {
		fmt.Fprintf(w, "SubjectKeyID:   %x\n", cert.SubjectKeyId)
	}

	if len(cert.CRLDistributionPoints) > 0 {
		fmt.Fprintln(w, "CRL URLs:")

		for _, crl := range cert.CRLDistributionPoints {
			fmt.Fprintf(w, "  %s\n", crl)
		}
	}
}

func pkixStr(name pkix.Name) string {
	str := "CN=" + name.CommonName

	for _, l := range name.Locality {
		str = "L=" + l + ", " + str
	}

	for _, st := range name.Province {
		str = "ST=" + st + ", " + str
	}

	for _, ou := range name.OrganizationalUnit {
		str = "OU=" + ou + ", " + str
	}

	for _, o := range name.Organization {
		str = "O=" + o + ", " + str
	}

	for _, c := range name.Country {
		str = "C=" + c + ", " + str
	}

	return str
}

func sha256certificate(cert *x509.Certificate) (string, error) {
	sum := sha256.Sum256(cert.Raw)
	return "SHA256:" + base64.StdEncoding.EncodeToString(sum[:]), nil
}

func sha256publicKey(pub crypto.PublicKey) (string, error) {
	bytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", nil
	}

	sum := sha256.Sum256(bytes)

	return "SHA256:" + base64.StdEncoding.EncodeToString(sum[:]), nil
}
