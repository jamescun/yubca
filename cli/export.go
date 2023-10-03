package cli

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/go-piv/piv-go/piv"
	"github.com/spf13/cobra"
)

var (
	exportCA        bool
	exportPublicKey bool
)

var export = &cobra.Command{
	Use:   "export",
	Short: "export certificate authority certificate or public key",

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
		}

		if exportCA {
			pem.Encode(os.Stdout, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})
		}

		if exportPublicKey {
			bytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				return fmt.Errorf("could not marshal public key: %w", err)
			}

			pem.Encode(os.Stdout, &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: bytes,
			})
		}

		return nil
	},
}

func init() {
	export.Flags().BoolVar(&exportCA, "ca", false, "export certificate authority certificate")
	export.Flags().BoolVar(&exportPublicKey, "public-key", false, "export certificate authority public key")
}
