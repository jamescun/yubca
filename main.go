package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/jamescun/yubca/cli"
	"github.com/jamescun/yubca/config"
)

var (
	// Version is the semantic release of this build of yubca.
	Version = "0.0.0"

	// Revision is the commit reference of Git at build time.
	Revision = "dev"
)

func main() {
	ctx := context.Background()

	if err := cli.Root().ExecuteContext(ctx); err != nil {
		var ve *config.ValidationError
		if errors.As(err, &ve) {
			fmt.Fprintf(os.Stderr, "Invalid Configuration!\nField: %s\nMessage: %s\nHelp: %s\n", ve.Field, ve.Message, ve.Help)
			os.Exit(2)
		} else {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}
	}
}
