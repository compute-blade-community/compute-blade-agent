package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/sierrasoftworks/humane-errors-go"
	"github.com/uptime-induestries/compute-blade-agent/pkg/log"
	"go.uber.org/zap"
)

const (
	certDir        = "/etc/compute-blade-agent"
	caFile         = "ca.pem"
	serverCertFile = "server.pem"
	serverKeyFile  = "server-key.pem"
)

func getTLSCerts(ctx context.Context) (tls.Certificate, *x509.CertPool, humane.Error) {
	caPath, serverCertPath, serverKeyPath, herr := ensureTLSCerts(ctx)
	if herr != nil {
		return tls.Certificate{}, nil, humane.Wrap(herr, "failed to load server key pair",
			"ensure the server's certificate and private key are accessible",
		)
	}

	cert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return tls.Certificate{}, nil, humane.Wrap(err, "failed to load server key pair",
			"ensure the server's certificate and private key are accessible",
		)
	}

	// Load CA cert
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return tls.Certificate{}, nil, humane.Wrap(err, "failed to load CA cert",
			"ensure the server's CA is accessible",
		)
	}

	// Create a certificate pool from the CA
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		return tls.Certificate{}, nil, humane.New("failed to append CA cert to pool",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	return cert, certPool, nil
}

// ensureTLSCerts generates and writes necessary TLS certificates and keys if they do not already exist.
// It returns paths to the CA certificate, the server certificate, the server key, or an error if encountered.
func ensureTLSCerts(ctx context.Context) (string, string, string, humane.Error) {
	caPath := filepath.Join(certDir, caFile)
	serverCertPath := filepath.Join(certDir, serverCertFile)
	serverKeyPath := filepath.Join(certDir, serverKeyFile)

	// Check if files already exist
	if fileExists(caPath) && fileExists(serverCertPath) && fileExists(serverKeyPath) {
		return caPath, serverCertPath, serverKeyPath, nil
	}

	log.FromContext(ctx).Info("Generating TLS certificates for compute-blade-agent")

	// Generate CA private key
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return "", "", "", humane.Wrap(err, "failed to generate CA key",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Compute Blade CA"},
			CommonName:   "Compute Blade Agent Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	// Create self-signed CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", humane.Wrap(err, "failed to create CA cert",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	// Generate server private key
	serverKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return "", "", "", humane.Wrap(err, "failed to create server key",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Compute Blade Agent"},
			CommonName:   "localhost",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(3 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
		IPAddresses: nil, // Add IPs here if needed
	}

	// Sign server certificate with the CA
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", humane.Wrap(err, "failed to create server cert",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	// Write files
	if err := os.MkdirAll(certDir, 0600); err != nil {
		return "", "", "", humane.Wrap(err, "failed to create cert dir",
			"ensure the directory you are trying to create exists and is writable by the agent user",
		)
	}

	// Save CA cert
	if err := writePEM(caPath, "CERTIFICATE", caCertDER); err != nil {
		return "", "", "", humane.Wrap(err, "failed to write CA cert",
			"ensure the directory you are trying to create exists and is writable by the agent user",
		)
	}

	// Save server cert
	if err := writePEM(serverCertPath, "CERTIFICATE", serverCertDER); err != nil {
		return "", "", "", humane.Wrap(err, "failed to write server cert",
			"ensure the directory you are trying to create exists and is writable by the agent user",
		)
	}

	// Save server key
	serverKeyBytes, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return "", "", "", humane.Wrap(err, "failed to marshal server key",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	if err := writePEM(serverKeyPath, "EC PRIVATE KEY", serverKeyBytes); err != nil {
		return "", "", "", humane.Wrap(err, "failed to write server key",
			"ensure the directory you are trying to create exists and is writable by the agent user",
		)
	}

	log.FromContext(ctx).Info("Finished generating TLS certificates for compute-blade-agent",
		zap.String("ca", caPath),
		zap.String("server", serverCertPath),
		zap.String("server-key", serverKeyPath))
	return caPath, serverCertPath, serverKeyPath, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func writePEM(path, typ string, bytes []byte) error {
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  typ,
		Bytes: bytes,
	})
	return os.WriteFile(path, pemData, 0600)
}
