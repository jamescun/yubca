package db

import (
	"context"
	"crypto/x509"
)

// DB is an index of the certificates signed by a Certificate Authority.
type DB interface {
	AppendCertificate(ctx context.Context, cert *x509.Certificate) error
}
