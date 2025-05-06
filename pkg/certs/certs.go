package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/sierrasoftworks/humane-errors-go"
	"github.com/uptime-induestries/compute-blade-agent/pkg/bladectlconfig"
	"github.com/uptime-induestries/compute-blade-agent/pkg/log"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const certDir = "/etc/compute-blade-agent"

var (
	caPath         = filepath.Join(certDir, "ca.pem")
	caKeyPath      = filepath.Join(certDir, "ca-key.pem")
	serverCertPath = filepath.Join(certDir, "server.pem")
	serverKeyPath  = filepath.Join(certDir, "server-key.pem")
)

// GenerateClientCert generates a client certificate, private key, and CA certificate for secure communication.
// It takes the client's Common Name as input and returns the certificates and key in PEM encoded format, or an error.
func GenerateClientCert(commonName string) (caPEM, certPEM, keyPEM []byte, herr humane.Error) {
	caCert, caKey, herr := loadCA()
	if herr != nil {
		return nil, nil, nil, herr
	}

	clientKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, humane.Wrap(err, "failed to create client certificate",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	clientKeyBytes, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		return nil, nil, nil, humane.Wrap(err, "failed to marshal client private key",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyBytes})
	caPEM, err = os.ReadFile(caPath) // public CA cert (not the key)
	if err != nil {
		return nil, nil, nil, humane.Wrap(err, "failed to read CA certificate",
			"ensure the directory you are trying to create exists and is writable by the agent user",
		)
	}

	return caPEM, certPEM, keyPEM, nil
}

// GenerateServerCert generates a server TLS certificate and returns it along with a loaded CA certificate pool or an error.
func GenerateServerCert(ctx context.Context, serverAddr string) (tls.Certificate, *x509.CertPool, humane.Error) {
	// We need a CA
	if err := ensureCA(ctx); err != nil {
		return tls.Certificate{}, nil, err
	}

	// If Keys already exist, there is nothing to do :)
	if fileExists(serverCertPath) && fileExists(serverKeyPath) {
		cert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
		if err != nil {
			return tls.Certificate{}, nil, humane.Wrap(err, "failed to load existing server cert",
				"ensure the directory you are trying to create exists and is writable by the agent user",
			)
		}

		pool, herr := loadCertPool()
		if herr != nil {
			return tls.Certificate{}, nil, herr
		}

		return cert, pool, nil
	}

	// Generate Server Keys
	log.FromContext(ctx).Debug("Generating new server certificate...")
	_, serverCertDER, serverKeyDER, herr := GenerateClientCert("Compute Blade Agent")
	if herr != nil {
		return tls.Certificate{}, nil, herr
	}

	if err := writePEM(serverCertPath, "CERTIFICATE", serverCertDER); err != nil {
		return tls.Certificate{}, nil, err
	}
	if err := writePEM(serverKeyPath, "EC PRIVATE KEY", serverKeyDER); err != nil {
		return tls.Certificate{}, nil, err
	}

	log.FromContext(ctx).Info("Generated new server certificates",
		zap.String("cert", serverCertPath),
		zap.String("key", serverKeyPath),
		zap.String("ca", caPath),
	)

	cert, err := tls.X509KeyPair(serverCertDER, serverKeyDER)
	if err != nil {
		return tls.Certificate{}, nil, humane.Wrap(err, "failed to parse generated server certificate",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	pool, herr := loadCertPool()
	if herr != nil {
		return tls.Certificate{}, nil, herr
	}

	// Generate localhost keys
	log.FromContext(ctx).Debug("Generating new local client certificate...")
	caPEM, clientCertDER, clientKeyDER, herr := GenerateClientCert("localhost")
	if herr != nil {
		return tls.Certificate{}, nil, herr
	}

	hostname, err := os.Hostname()
	if err != nil {
		return tls.Certificate{}, nil, humane.Wrap(err, "failed to extract hostname",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	// Write local bladectl config
	_, grpcApiPort, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return tls.Certificate{}, nil, humane.Wrap(err, "failed to extract port from gRPC address",
			"check your gRPC address is correct in your agent config",
		)
	}

	bladectlConfig := NewBladectlConfig(hostname, grpcApiPort, caPEM, clientCertDER, clientKeyDER)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return tls.Certificate{}, nil, humane.Wrap(err, "Failed to extract home directory",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	configDir := filepath.Join(homeDir, ".bladectl")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return tls.Certificate{}, nil, humane.Wrap(err, "Failed to create config directory",
			"ensure the home-directory is writable by the agent user",
		)
	}

	configPath := filepath.Join(configDir, "config")
	data, err := yaml.Marshal(&bladectlConfig)
	if err != nil {
		return tls.Certificate{}, nil, humane.Wrap(err, "Failed to marshal YAML config",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return tls.Certificate{}, nil, humane.Wrap(err, "Failed to write bladectl config file",
			"ensure the home-directory is writable by the agent user",
		)
	}

	return cert, pool, nil
}

func NewBladectlConfig(bladeName, apiPort string, caPEM []byte, clientCertDER []byte, clientKeyDER []byte) bladectlconfig.BladectlConfig {
	return bladectlconfig.BladectlConfig{
		Blades: []bladectlconfig.NamedBlade{
			{
				Name: bladeName,
				Blade: bladectlconfig.Blade{
					Server:                   fmt.Sprintf("https://localhost:%s", apiPort),
					CertificateAuthorityData: base64.StdEncoding.EncodeToString(caPEM),
					Certificate: bladectlconfig.Certificate{
						ClientCertificateData: base64.StdEncoding.EncodeToString(clientCertDER),
						ClientKeyData:         base64.StdEncoding.EncodeToString(clientKeyDER),
					},
				},
			},
		},
		CurrentBlade: bladeName,
	}
}

// ensureCA ensures that the CA certificate and key exist, creating a new one if not found, and returns any error encountered.
func ensureCA(ctx context.Context) humane.Error {
	if fileExists(caPath) && fileExists(caKeyPath) {
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
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	caKeyBytes, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return humane.Wrap(err, "failed to marshal CA private key",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	if err := os.MkdirAll(certDir, 0600); err != nil {
		return humane.Wrap(err, "failed to create cert directory",
			"ensure the directory you are trying to create exists and is writable by the agent user",
		)
	}

	if err := writePEM(caPath, "CERTIFICATE", caCertDER); err != nil {
		return humane.Wrap(err, "failed to write CA certificate",
			"ensure the directory you are trying to create exists and is writable by the agent user",
		)
	}

	if err := writePEM(caKeyPath, "EC PRIVATE KEY", caKeyBytes); err != nil {
		return humane.Wrap(err, "failed to write CA private key",
			"ensure the directory you are trying to create exists and is writable by the agent user",
		)
	}

	return nil
}

// loadCA loads a CA certificate and private key from predefined file paths and returns them along with any error encountered.
func loadCA() (*x509.Certificate, *ecdsa.PrivateKey, humane.Error) {
	certPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, nil, humane.Wrap(err, "failed to read CA certificate")
	}
	keyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, nil, humane.Wrap(err, "failed to read CA key")
	}

	certBlock, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, humane.Wrap(err, "failed to parse CA certificate")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, humane.Wrap(err, "failed to parse CA key")
	}

	return cert, key, nil
}

// loadCertPool loads a CA certificate from a predefined path and returns an x509.CertPool instance or an error.
func loadCertPool() (*x509.CertPool, humane.Error) {
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, humane.Wrap(err, "failed to read CA certificate",
			"ensure the directory you are trying to create exists and is writable by the agent user",
		)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, humane.New("failed to append CA certificate to pool",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	return pool, nil
}

// fileExists checks if a file exists at the given path and returns true if it does, false otherwise.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// writePEM writes a PEM-encoded block with the given type and bytes to the specified file path, returning any error encountered.
func writePEM(path, typ string, bytes []byte) humane.Error {
	pemData := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: bytes})
	err := os.WriteFile(path, pemData, 0600)

	return humane.Wrap(err, "failed to write PEM file",
		"ensure the directory you are trying to create exists and is writable by the agent user",
	)
}
