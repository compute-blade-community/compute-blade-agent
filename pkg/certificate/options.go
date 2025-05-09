package certificate

import (
	"crypto/ecdsa"
	"crypto/x509"
)

type options struct {
	CaCert *x509.Certificate
	CaKey  *ecdsa.PrivateKey
	Usage  Usage
}

type Option func(*options)

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
