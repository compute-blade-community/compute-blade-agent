package certificate

import "fmt"

// Usage defines the intended purpose of a certificate, such as client or server usage.
type Usage int

func (c Usage) String() string {
	switch c {
	case UsageClient:
		return "client"

	case UsageServer:
		return "server"

	default:
		return fmt.Sprintf("CertificateUsage(%d)", c)
	}
}

const (
	UsageClient Usage = iota // Certificate is for Client
	UsageServer              // Certificate is for Server
)

// Format represents the encoding format of a certificate, such as PEM or DER.
type Format int

func (c Format) String() string {
	switch c {
	case FormatPEM:
		return "pem"

	case FormatDER:
		return "der"

	default:
		return fmt.Sprintf("CertificateFormat(%d)", c)
	}
}

const (
	FormatPEM Format = iota // PEM Encoded Certificate
	FormatDER               // DER Encoded Certificate
)
