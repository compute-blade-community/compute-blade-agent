package certificate

import (
	"crypto/ecdsa"
	"crypto/x509"
)

type options struct {
	CaCert     *x509.Certificate
	CaKey      *ecdsa.PrivateKey
	CommonName string
	Usage      Usage
	CertData   []byte
	KeyData    []byte
}

type Option func(*options)

func WithCommonName(name string) Option {
	return func(o *options) {
		o.CommonName = name
	}
}

func WithUsage(usage Usage) Option {
	return func(o *options) {
		o.Usage = usage
	}
}

func WithClientUsage() Option {
	return WithUsage(UsageClient)
}

func WithServerUsage() Option {
	return WithUsage(UsageServer)
}

func WithCaCert(cert *x509.Certificate) Option {
	return func(o *options) {
		o.CaCert = cert
	}
}

func WithCaKey(key *ecdsa.PrivateKey) Option {
	return func(o *options) {
		o.CaKey = key
	}
}

func WithCertData(data []byte) Option {
	return func(o *options) {
		o.CertData = data
	}
}

func WithCertKey(data []byte) Option {
	return func(o *options) {
		o.KeyData = data
	}
}
