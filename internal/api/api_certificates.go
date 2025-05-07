package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/sierrasoftworks/humane-errors-go"
	"github.com/uptime-industries/compute-blade-agent/pkg/bladectlconfig"
	"github.com/uptime-industries/compute-blade-agent/pkg/certificate"
	"github.com/uptime-industries/compute-blade-agent/pkg/log"
	"github.com/uptime-industries/compute-blade-agent/pkg/util"
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

// GenerateClientCert creates a client certificate signed by a CA with the specified common name.
// It validates the CA certificate and private key before generating the client certificate.
// Returns CA certificate, client certificate, private key in PEM format, and any error encountered.
func GenerateClientCert(commonName string) (caPEM, certPEM, keyPEM []byte, herr humane.Error) {
	caCert, caKey, err := certificate.LoadAndValidateCertificate(caPath, caKeyPath)
	if err != nil {
		return nil, nil, nil, humane.Wrap(err, "No valid CA found to sign the client certificate")
	}

	return certificate.GenerateCertificate(certificate.WithCommonName(commonName),
		certificate.WithClientUsage(),
		certificate.WithCaCert(caCert),
		certificate.WithCaKey(caKey),
		certificate.WithOutputFormatPEM(),
	)
}

func EnsureAuthenticatedBladectlConfig(ctx context.Context, serverAddr string, serverMode ListenMode) humane.Error {
	configDir, herr := bladectlconfig.EnsureBladectlConfigHome()
	if herr != nil {
		return herr
	}

	configPath := filepath.Join(configDir, "config.yaml")

	if util.FileExists(configPath) {
		// Load and decode bladectl config
		configBytes, err := os.ReadFile(configPath)
		if err != nil {
			return humane.Wrap(err, "failed to read bladectl config",
				fmt.Sprintf("ensure the config file %s exists and is readable by the agent user", configPath),
			)
		}

		var bladectlConfig bladectlconfig.BladectlConfig
		if err := yaml.Unmarshal(configBytes, &bladectlConfig); err != nil {
			return humane.Wrap(err, "failed to parse bladectl config",
				"this should never happen",
				"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
				"ensure your config file is valid YAML",
			)
		}

		blade, herr := bladectlConfig.FindBlade("")
		if herr != nil {
			return herr
		}

		certData, err := base64.StdEncoding.DecodeString(blade.Certificate.ClientCertificateData)
		if err != nil {
			return humane.Wrap(err, "failed to decode client certificate data",
				"this should never happen",
				"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
				"ensure your config file is valid YAML",
			)
		}

		keyData, err := base64.StdEncoding.DecodeString(blade.Certificate.ClientKeyData)
		if err != nil {
			return humane.Wrap(err, "failed to decode client certificate key data",
				"this should never happen",
				"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
				"ensure your config file is valid YAML",
			)
		}

		if _, _, err := certificate.ValidateCertificate(
			certificate.WithCertData(certData),
			certificate.WithCertKey(keyData),
		); err != nil {
			return err
		}

		return nil
	}

	// Generate localhost keys
	log.FromContext(ctx).Debug("Generating new local client certificate...")

	caPEM, clientCertDER, clientKeyDER, herr := GenerateClientCert("localhost")
	if herr != nil {
		return herr
	}

	if serverMode == ModeTcp {
		_, grpcApiPort, err := net.SplitHostPort(serverAddr)
		if err != nil {
			return humane.Wrap(err, "failed to extract port from gRPC address",
				"check your gRPC address is correct in your agent config",
			)
		}

		serverAddr = fmt.Sprintf("localhost:%s", grpcApiPort)
	}

	bladectlConfig := bladectlconfig.NewAuthenticatedBladectlConfig(serverAddr, caPEM, clientCertDER, clientKeyDER)
	data, err := yaml.Marshal(&bladectlConfig)
	if err != nil {
		return humane.Wrap(err, "Failed to marshal YAML config",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return humane.Wrap(err, "Failed to write bladectl config file",
			"ensure the home-directory is writable by the agent user",
		)
	}

	log.FromContext(ctx).Info("Generated new local bladectl config",
		zap.String("path", configPath),
		zap.String("server", serverAddr),
		zap.Bool("authenticated", true),
	)

	return nil
}

func EnsureUnauthenticatedBladectlConfig(ctx context.Context, serverAddr string, serverMode ListenMode) humane.Error {
	configDir, herr := bladectlconfig.EnsureBladectlConfigHome()
	if herr != nil {
		return herr
	}

	configPath := filepath.Join(configDir, "config.yaml")
	if util.FileExists(configPath) {
		return nil
	}

	// Generate localhost keys
	log.FromContext(ctx).Debug("Generating new local bladectl config...")

	if serverMode == ModeTcp {
		_, grpcApiPort, err := net.SplitHostPort(serverAddr)
		if err != nil {
			return humane.Wrap(err, "failed to extract port from gRPC address",
				"check your gRPC address is correct in your agent config",
			)
		}

		serverAddr = fmt.Sprintf("localhost:%s", grpcApiPort)
	}

	bladectlConfig := bladectlconfig.NewBladectlConfig(serverAddr)
	data, err := yaml.Marshal(&bladectlConfig)
	if err != nil {
		return humane.Wrap(err, "Failed to marshal YAML config",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return humane.Wrap(err, "Failed to write bladectl config file",
			"ensure the home-directory is writable by the agent user",
		)
	}

	log.FromContext(ctx).Info("Generated new local bladectl config",
		zap.String("path", configPath),
		zap.String("server", serverAddr),
		zap.Bool("authenticated", false),
	)

	return nil
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
				"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
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
	_, serverCertPEM, serverKeyPEM, herr := certificate.GenerateCertificate(
		certificate.WithCommonName("Compute Blade Agent"),
		certificate.WithServerUsage(),
		certificate.WithCaCert(caCert),
		certificate.WithCaKey(caKey),
		certificate.WithOutputFormatPEM(),
	)
	if herr != nil {
		return tls.Certificate{}, nil, herr
	}

	if err := certificate.WriteCertificate(caPath, caKeyPath,
		certificate.WithInputFormatPEM(),
		certificate.WithOutputFormatPEM(),
		certificate.WithCertData(serverCertPEM),
		certificate.WithCertKey(serverKeyPEM),
	); err != nil {
		return tls.Certificate{}, nil, err
	}

	log.FromContext(ctx).Info("Generated new server certificates",
		zap.String("cert", serverCertPath),
		zap.String("key", serverKeyPath),
		zap.String("ca", caPath),
	)

	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return tls.Certificate{}, nil, humane.Wrap(err, "failed to parse generated server certificate",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
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

	if err := certificate.WriteCertificate(caPath, caKeyPath,
		certificate.WithInputFormatPEM(),
		certificate.WithOutputFormatPEM(),
		certificate.WithCertData(caCertDER),
		certificate.WithCertKey(caKeyBytes),
	); err != nil {
		return err
	}

	return nil
}
