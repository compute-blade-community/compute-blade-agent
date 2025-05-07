package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/sierrasoftworks/humane-errors-go"
	"github.com/uptime-industries/compute-blade-agent/pkg/util"
)

// LoadAndValidateCertificate loads and validates a certificate and its private key from the provided file paths.
// It reads, decodes, and parses the certificate and private key, ensuring the public key matches the private key.
// Returns the parsed X.509 certificate, ECDSA private key, and a humane.Error if any error occurs during processing.
func LoadAndValidateCertificate(certPath, keyPath string) (cert *x509.Certificate, key *ecdsa.PrivateKey, herr humane.Error) {
	// Load and decode CA cert
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, humane.Wrap(err, "failed to read certificate",
			fmt.Sprintf("ensure the certificate file %s exists and is readable by the agent user", certPath),
		)
	}

	// Load and decode CA key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, humane.Wrap(err, "failed to read private key",
			fmt.Sprintf("ensure the key file %s exists and is readable by the agent user", keyPath),
		)
	}

	return ValidateCertificate(
		WithCertData(certPEM),
		WithCertKey(keyPEM),
	)
}

func ValidateCertificate(opts ...Option) (cert *x509.Certificate, key *ecdsa.PrivateKey, herr humane.Error) {
	options := &options{}

	for _, opt := range opts {
		opt(options)
	}

	certBlock, _ := pem.Decode(options.CertData)
	if certBlock == nil {
		return nil, nil, humane.New("failed to decode certificate",
			"Verify if the certificate is valid by run the following command:",
			"openssl x509 -in /path/to/certificate.pem -text -noout",
		)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, humane.New("failed to parse certificate",
			"Verify if the certificate is valid by run the following command:",
			"openssl x509 -in /path/to/certificate.pem -text -noout",
		)
	}

	keyBlock, _ := pem.Decode(options.KeyData)
	if keyBlock == nil {
		return nil, nil, humane.New("failed to decode certificate",
			"Verify if the key-file is valid by run the following command:",
			"openssl ec -in /path/to/keyfile.pem -check",
		)
	}
	key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, humane.Wrap(err, "failed to parse private key",
			"Verify if the key-file is valid by run the following command:",
			"openssl ec -in /path/to/keyfile.pem -check",
		)
	}

	// Compare public keys
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || certPub.X.Cmp(key.X) != 0 || certPub.Y.Cmp(key.Y) != 0 {
		return nil, nil, humane.New("private key does not match certificate",
			"Verify the certificate and private key match.",
			"To verify on the CLI, use:",
			fmt.Sprintf("cmp <(openssl x509 -in %s -pubkey -noout -outform PEM) <(openssl ec -in %s -pubout -outform PEM) && echo \"✅ Certificate and key match\" || echo \"❌ Mismatch\"",
				"/path/to/certificate.pem",
				"/path/to/keyfile.pem",
			),
		)
	}

	return cert, key, nil
}

// GenerateCertificate generates a certificate and private key based on the provided options.
// It supports usage for both client and server certificates and outputs data in PEM or DER formats.
// Returns the CA certificate used for signing, the generated certificate, and private key as byte slices
// in the output format requested, or an error if processing fails.
func GenerateCertificate(opts ...Option) (caPEM, certPEM, keyPEM []byte, herr humane.Error) {
	options := &options{}

	for _, opt := range opts {
		opt(options)
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, nil, nil, humane.Wrap(err, "failed to extract hostname",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	var extKeyUsage []x509.ExtKeyUsage
	var hostIps []net.IP

	// If we generate server certificates
	switch options.Usage {
	case UsageClient:
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	case UsageServer:
		// make sure to use the correct key-usage
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

		// And add all the host-ips
		if hostIps, err = util.GetHostIPs(); err != nil {
			return nil, nil, nil, humane.Wrap(err, "failed to extract server IPs",
				"this should never happen",
				"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
			)
		}

	default:
		return nil, nil, nil, humane.New(fmt.Sprintf("invalid certificate usage %s", options.Usage.String()),
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: options.CommonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: extKeyUsage,
		DNSNames:    []string{"localhost", hostname, fmt.Sprintf("%s.local", hostname)},
		IPAddresses: hostIps,
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, nil, humane.Wrap(err, "failed to generate client key",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, options.CaCert, &clientKey.PublicKey, options.CaKey)
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

	switch options.OutputFormat {
	case FormatPEM:
		caCertPEM, err := x509.CreateCertificate(rand.Reader, options.CaCert, options.CaCert, &options.CaCert.PublicKey, options.CaKey)
		if err != nil {
			return nil, nil, nil, humane.Wrap(err, "failed to marshal client private key",
				"this should never happen",
				"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
			)
		}

		caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertPEM})
		certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyBytes})

		return caPEM, certPEM, keyPEM, nil

	case FormatDER:
		return certDER, certDER, clientKeyBytes, nil

	default:
		return nil, nil, nil, humane.New(fmt.Sprintf("invalid output format %s", options.OutputFormat.String()),
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}
}

// WriteCertificate writes the given certificate and key data to the specified file paths with optional configuration.
// It supports different input and output formats such as PEM and DER for the conversion process.
// Returns a humane.Error if the write operation fails or an invalid format combination is detected.
func WriteCertificate(certPath, keyPath string, opts ...Option) humane.Error {
	options := options{}
	for _, opt := range opts {
		opt(&options)
	}

	var (
		certData []byte
		keyData  []byte
	)

	switch options.OutputFormat {
	case FormatPEM:
		switch options.InputFormat {
		case FormatDER:
			certData = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: options.CertData})
			keyData = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: options.KeyData})

		case FormatPEM:
			// Nothing to do
			certData = options.CertData
			keyData = options.KeyData

		default:
			return humane.New(fmt.Sprintf("invalid input/output format combination (input: %s, output: %s)",
				options.InputFormat.String(), options.OutputFormat.String()),
				"this should never happen",
				"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
			)
		}

	case FormatDER:
		switch options.InputFormat {
		case FormatPEM:
			certBlock, _ := pem.Decode(options.CertData)
			keyBlock, _ := pem.Decode(options.KeyData)

			if certBlock == nil {
				return humane.New("failed to decode certificate")
			}

			if keyBlock == nil {
				return humane.New("failed to decode certificate")
			}

			certData = certBlock.Bytes
			keyData = keyBlock.Bytes

		case FormatDER:
			// Nothing to do
			certData = options.CertData
			keyData = options.KeyData

		default:
			return humane.New(fmt.Sprintf("invalid input/output format combination (input: %s, output: %s)",
				options.InputFormat.String(), options.OutputFormat.String()),
				"this should never happen",
				"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
			)
		}

	default:
		return humane.New(fmt.Sprintf("invalid input/output format combination (input: %s, output: %s)",
			options.InputFormat.String(), options.OutputFormat.String()),
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
		)
	}

	if err := os.WriteFile(certPath, certData, 0600); err != nil {
		return humane.Wrap(err, "failed to write certificate file",
			"ensure the directory you are trying to create exists and is writable by the agent user",
		)
	}

	if err := os.WriteFile(keyPath, keyData, 0600); err != nil {
		return humane.Wrap(err, "failed to write key file",
			"ensure the directory you are trying to create exists and is writable by the agent user",
		)
	}

	return nil
}

// GetCertPoolFrom reads a CA certificate from a given path and initializes a x509.CertPool with its contents.
// Returns the initialized certificate pool or a descriptive error if reading or appending the certificate fails.
func GetCertPoolFrom(caPath string) (pool *x509.CertPool, herr humane.Error) {
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, humane.Wrap(err, "failed to read CA certificate",
			"ensure the directory you are trying to create exists and is writable by the agent user",
		)
	}

	pool = x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, humane.New("failed to append CA certificate to pool",
			"this should never happen",
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
			"Verify if the CA certificate is valid by run the following command:",
			fmt.Sprintf("openssl x509 -in %s -text -noout", caPath),
		)
	}

	return pool, nil
}
