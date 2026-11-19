package internal_agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/certificate"
	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"github.com/compute-blade-community/compute-blade-agent/pkg/util"
	"github.com/sierrasoftworks/humane-errors-go"
	"go.uber.org/zap"
)

const certDir = "/etc/compute-blade-agent"

var (
	caPath         = filepath.Join(certDir, "ca.pem")
	caKeyPath      = filepath.Join(certDir, "ca-key.pem")
	serverCertPath = filepath.Join(certDir, "server.pem")
	serverKeyPath  = filepath.Join(certDir, "server-key.pem")
)

// GenerateClientCert creates a client certificate signed by a CA with the specified common name.
// It validates the CA certificate and private key before generating the client certificate.
// Returns CA certificate, client certificate, private key in PEM format, and any error encountered.
func GenerateClientCert(commonName string) (caPEM, certPEM, keyPEM []byte, herr humane.Error) {
	caCert, caKey, herr := certificate.LoadAndValidateCertificate(caPath, caKeyPath)
	if herr != nil {
		return nil, nil, nil, humane.Wrap(herr, "No valid CA found to sign the client certificate")
	}

	certDER, keyDER, herr := certificate.GenerateCertificate(
		commonName,
		certificate.WithClientUsage(),
		certificate.WithCaCert(caCert),
		certificate.WithCaKey(caKey),
	)
	if herr != nil {
		return nil, nil, nil, humane.Wrap(herr, "failed to generate client certificate")
	}

	// Load CA PEM
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, nil, nil, humane.Wrap(err, "failed to read CA",
			fmt.Sprintf("ensure the certificate file %s exists and is readable by the agent user", caPath),
		)
	}

	// Convert DER to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return caPEM, certPEM, keyPEM, nil
}

// EnsureServerCertificate ensures the presence of a valid server certificate and CA, generating them if necessary.
func EnsureServerCertificate(ctx context.Context) (tls.Certificate, *x509.CertPool, humane.Error) {
	// If Keys already exist, there is nothing to do :)
	if util.FileExists(caPath) && util.FileExists(caKeyPath) && util.FileExists(serverCertPath) && util.FileExists(serverKeyPath) {
		if _, _, err := certificate.LoadAndValidateCertificate(caPath, caKeyPath); err != nil {
			return tls.Certificate{}, nil, err
		}

		cert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
		if err != nil {
			return tls.Certificate{}, nil, humane.Wrap(err, "failed to load existing server cert",
				"this should never happen",
				"please report this as a bug to https://github.com/compute-blade-community/compute-blade-agent/issues",
			)
		}

		pool, herr := certificate.GetCertPoolFrom(caPath)
		if herr != nil {
			return tls.Certificate{}, nil, herr
		}

		return cert, pool, nil
	}

	// We need a CA
	if err := ensureCA(ctx); err != nil {
		return tls.Certificate{}, nil, err
	}

	// But more importantly: a valid CA
	caCert, caKey, herr := certificate.LoadAndValidateCertificate(caPath, caKeyPath)
	if herr != nil {
		return tls.Certificate{}, nil, herr
	}

	// Generate Server Keys
	log.FromContext(ctx).Debug("Generating new server certificate...")
	serverCertDER, serverKeyDER, herr := certificate.GenerateCertificate(
		"Compute Blade Agent",
		certificate.WithServerUsage(),
		certificate.WithCaCert(caCert),
		certificate.WithCaKey(caKey),
	)
	if herr != nil {
		return tls.Certificate{}, nil, herr
	}

	if err := certificate.WriteCertificate(serverCertPath, serverKeyPath, serverCertDER, serverKeyDER); err != nil {
		return tls.Certificate{}, nil, err
	}

	log.FromContext(ctx).Info("Generated new server certificates",
		zap.String("cert", serverCertPath),
		zap.String("key", serverKeyPath),
		zap.String("ca", caPath),
	)

	cert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return tls.Certificate{}, nil, humane.Wrap(err, "failed to parse generated server certificate",
			"this should never happen",
			"please report this as a bug to https://github.com/compute-blade-community/compute-blade-agent/issues",
		)
	}

	pool, herr := certificate.GetCertPoolFrom(caPath)
	if herr != nil {
		return tls.Certificate{}, nil, herr
	}

	return cert, pool, nil
}

// ensureCA ensures that a valid Certificate Authority (CA) certificate and private key exist or generates new ones.
func ensureCA(ctx context.Context) humane.Error {
	if util.FileExists(caPath) && util.FileExists(caKeyPath) {
		_, _, err := certificate.LoadAndValidateCertificate(caPath, caKeyPath)
		if err != nil {
			return err
		}

		return nil
	}

	log.FromContext(ctx).Info("Generating new CA for compute-blade-agent")

	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return humane.Wrap(err, "failed to generate CA key")
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Compute Blade CA"}, CommonName: "Compute Blade Agent Root CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return humane.Wrap(err, "failed to create CA certificate",
			"this should never happen",
			"please report this as a bug to https://github.com/compute-blade-community/compute-blade-agent/issues",
		)
	}

	caKeyBytes, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return humane.Wrap(err, "failed to marshal CA private key",
			"this should never happen",
			"please report this as a bug to https://github.com/compute-blade-community/compute-blade-agent/issues",
		)
	}

	if err := os.MkdirAll(certDir, 0600); err != nil {
		return humane.Wrap(err, "failed to create cert directory",
			"ensure the directory you are trying to create exists and is writable by the agent user",
		)
	}

	if err := certificate.WriteCertificate(caPath, caKeyPath, caCertDER, caKeyBytes); err != nil {
		return err
	}

	return nil
}
