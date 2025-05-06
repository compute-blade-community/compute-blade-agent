package bladectlconfig

import (
	"github.com/sierrasoftworks/humane-errors-go"
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
	Server                   string      `yaml:"server" mapstructure:"server"`
	CertificateAuthorityData string      `yaml:"certificate-authority-data,omitempty" mapstructure:"certificate-authority-data,omitempty"`
	Certificate              Certificate `yaml:"cert,omitempty" mapstructure:"cert,omitempty"`
}

type Certificate struct {
	ClientCertificateData string `yaml:"client-certificate-data" mapstructure:"client-certificate-data"`
	ClientKeyData         string `yaml:"client-key-data" mapstructure:"client-key-data"`
}

func FindCurrentBlade(config BladectlConfig) (*Blade, humane.Error) {
	for _, blade := range config.Blades {
		if blade.Name == config.CurrentBlade {
			return &blade.Blade, nil
		}
	}

	return nil, humane.New("current blade not found in configuration",
		"ensure you have a current-blade set in your configuration file, or use the --current-blade flag to specify one",
		"make sure you have a blade with the name you specified in the blades configuration",
	)
}
