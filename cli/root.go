package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/go-piv/piv-go/piv"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jamescun/yubca/config"
)

var (
	configFile string
	keyID      int
)

var key *piv.YubiKey

var root = &cobra.Command{
	Use:   "yubca command",
	Short: "yubca manages a certificate authority on a yubikey",

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		cards, err := piv.Cards()
		if err != nil {
			return fmt.Errorf("could not list keys: %w", err)
		}

		if len(cards) < 1 {
			return fmt.Errorf("no keys found")
		}

		if keyID >= len(cards) {
			return fmt.Errorf("key id %d not found", keyID)
		}

		key, err = piv.Open(cards[keyID])
		if err != nil {
			return fmt.Errorf("could not connect to key: %w", err)
		}

		return nil
	},
}

func init() {
	root.PersistentFlags().StringVar(&configFile, "config", "ca.json", "path to certificate authority json configuration")
	root.PersistentFlags().IntVar(&keyID, "key-id", 0, "id of yubikey to operate certificate authority from")

	root.AddCommand(initCA)
	root.AddCommand(inspectCA)
	root.AddCommand(export)
	root.AddCommand(signCSR)
}

// Root returns the root of the command line interface to be executed.
func Root() *cobra.Command {
	return root
}

func readConfig() (*config.CA, error) {
	cfg := new(config.CA)

	file, err := os.OpenFile(configFile, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	dec := json.NewDecoder(file)
	dec.DisallowUnknownFields()

	err = dec.Decode(cfg)
	if err != nil {
		return nil, err
	}

	err = cfg.Validate()
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func readPassword(prompt string) (string, error) {
	fmt.Printf("%s: ", prompt)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", fmt.Errorf("stdin: %w", err)
	}
	fmt.Printf("\n")

	return string(bytes.TrimSpace(pass)), nil
}

func readPIN() (string, error) {
	pin, err := readPassword("PIN (leave blank for default)")
	if err != nil {
		return piv.DefaultPIN, err
	}

	if pin == "" {
		return piv.DefaultPIN, nil
	}

	return pin, nil
}

func readManagementKey() ([24]byte, error) {
	key, err := readPassword("Management Key (leave blank for default)")
	if err != nil {
		return piv.DefaultManagementKey, err
	}

	if key == "" {
		return piv.DefaultManagementKey, nil
	}

	return piv.DefaultManagementKey, nil
}

func getSlot(slotType string) (piv.Slot, bool) {
	switch slotType {
	case "9a":
		return piv.SlotAuthentication, true

	case "9c":
		return piv.SlotSignature, true

	case "9e":
		return piv.SlotCardAuthentication, true

	case "9d":
		return piv.SlotKeyManagement, true

	default:
		return piv.Slot{}, false
	}
}
