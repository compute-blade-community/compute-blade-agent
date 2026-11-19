package config

import (
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sierrasoftworks/humane-errors-go"
	"github.com/spechtlabs/go-otel-utils/otelzap"
)

type BladectlConfig struct {
	Blades       []NamedBlade `yaml:"blades" mapstructure:"blades"`
	CurrentBlade string       `yaml:"current-blade" mapstructure:"current-blade"`
}

type NamedBlade struct {
	Name  string `yaml:"name" mapstructure:"name"`
	Blade Blade  `yaml:"blade" mapstructure:"blade"`
}

type Blade struct {
	Server      string      `yaml:"server" mapstructure:"server"`
	Certificate Certificate `yaml:"cert,omitempty" mapstructure:"cert,omitempty"`
}

type Certificate struct {
	CertificateAuthorityData string `yaml:"certificate-authority-data,omitempty" mapstructure:"certificate-authority-data,omitempty"`
	ClientCertificateData    string `yaml:"client-certificate-data,omitempty" mapstructure:"client-certificate-data,omitempty"`
	ClientKeyData            string `yaml:"client-key-data,omitempty" mapstructure:"client-key-data,omitempty"`
}

func (c *BladectlConfig) FindBlade(name string) (*NamedBlade, humane.Error) {
	if len(name) == 0 {
		name = c.CurrentBlade
	}

	for _, blade := range c.Blades {
		if blade.Name == name {
			return &blade, nil
		}
	}

	return nil, humane.New("current blade not found in configuration",
		"ensure you have a current-blade set in your configuration file, or use the --current-blade flag to specify one",
		"make sure you have a blade with the name you specified in the blades configuration",
	)
}

func NewAuthenticatedBladectlConfig(server string, caPEM []byte, clientCertDER []byte, clientKeyDER []byte) *BladectlConfig {
	cfg := NewBladectlConfig(server)
	cfg.Blades[0].Blade.Certificate.CertificateAuthorityData = base64.StdEncoding.EncodeToString(caPEM)
	cfg.Blades[0].Blade.Certificate.ClientCertificateData = base64.StdEncoding.EncodeToString(clientCertDER)
	cfg.Blades[0].Blade.Certificate.ClientKeyData = base64.StdEncoding.EncodeToString(clientKeyDER)
	return cfg
}

func NewBladectlConfig(server string) *BladectlConfig {
	hostname, err := os.Hostname()
	if err != nil {
		otelzap.L().WithError(err).Fatal("Failed to extract hostname")
	}

	return &BladectlConfig{
		Blades: []NamedBlade{
			{
				Name: hostname,
				Blade: Blade{
					Server: server,
				},
			},
		},
		CurrentBlade: hostname,
	}
}

func EnsureBladectlConfigHome() (string, humane.Error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", humane.Wrap(err, "Failed to extract home directory",
			"this should never happen",
			"please report this as a bug to https://github.com/compute-blade-community/compute-blade-agent/issues",
		)
	}

	configDir := filepath.Join(homeDir, ".config", "bladectl")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", humane.Wrap(err, "Failed to create config directory",
			"ensure the home-directory is writable by the agent user",
		)
	}

	return configDir, nil
}

// DiscoveryResult describes what MergeDiscovered did with a discovered blade
type DiscoveryResult int

const (
	// DiscoveryUnchanged means the blade is configured with the discovered address already
	DiscoveryUnchanged DiscoveryResult = iota
	// DiscoveryUpdated means the server address of a configured blade was updated
	DiscoveryUpdated
	// DiscoveryAdded means the blade was added to the configuration
	DiscoveryAdded
	// DiscoveryNeedsCredentials means the blade requires mTLS and isn't configured yet. Its client certificate has to
	// be copied from the blade (~/.config/bladectl/config.yaml), it can't be added automatically.
	DiscoveryNeedsCredentials
	// DiscoveryLocal means the blade is configured with a local address (unix socket or localhost), which is kept
	DiscoveryLocal
)

// Discovered is a blade found on the network
type Discovered struct {
	// Name is the blade's name (its hostname)
	Name string
	// Server is the address to reach its API at, e.g. blade-pi1.local:8081
	Server string
	// Addresses are the blade's IP addresses
	Addresses []net.IP
	// Authenticated is true if the API requires mTLS client certificates
	Authenticated bool
}

// MergeDiscovered adds or updates a blade found via discovery. Blades are matched by name. A configured server
// address is kept as long as it still points at the blade, even if it's written differently than the discovered one.
func (c *BladectlConfig) MergeDiscovered(found Discovered) DiscoveryResult {
	for idx := range c.Blades {
		blade := &c.Blades[idx].Blade
		if c.Blades[idx].Name != found.Name {
			continue
		}
		if isLocalServer(blade.Server) {
			return DiscoveryLocal
		}
		if pointsToSameBlade(blade.Server, found) {
			return DiscoveryUnchanged
		}
		blade.Server = found.Server
		return DiscoveryUpdated
	}

	if found.Authenticated {
		return DiscoveryNeedsCredentials
	}

	c.Blades = append(c.Blades, NamedBlade{Name: found.Name, Blade: Blade{Server: found.Server}})
	if c.CurrentBlade == "" {
		c.CurrentBlade = found.Name
	}
	return DiscoveryAdded
}

// pointsToSameBlade reports whether a configured server address reaches the discovered blade: same port, and either
// one of the blade's IP addresses or the same host name, possibly in another domain (blade-pi1 resolved via the DNS
// search domain, blade-pi1.local via mDNS, blade-pi1.example.net via DNS).
func pointsToSameBlade(server string, found Discovered) bool {
	host, port, err := net.SplitHostPort(server)
	foundHost, foundPort, foundErr := net.SplitHostPort(found.Server)
	if err != nil || foundErr != nil {
		return server == found.Server
	}
	if port != foundPort {
		return false
	}

	if ip := net.ParseIP(host); ip != nil {
		return slices.ContainsFunc(found.Addresses, ip.Equal)
	}

	host, foundHost = normalizeHost(host), normalizeHost(foundHost)
	if host == foundHost {
		return true
	}
	shortName, _, _ := strings.Cut(host, ".")
	foundShortName, _, _ := strings.Cut(foundHost, ".")
	return shortName == foundShortName
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// isLocalServer reports whether a server address points to the local machine
func isLocalServer(server string) bool {
	if strings.HasPrefix(server, "/") || strings.HasPrefix(server, "unix:") {
		return true
	}
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
