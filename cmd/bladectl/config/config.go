package config

import (
	"encoding/base64"
	"os"
	"path/filepath"

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

func (c *BladectlConfig) FindBlade(name string) (*Blade, humane.Error) {
	if len(name) == 0 {
		name = c.CurrentBlade
	}

	for _, blade := range c.Blades {
		if blade.Name == name {
			return &blade.Blade, nil
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
			"please report this as a bug to https://github.com/uptime-industries/compute-blade-agent/issues",
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
