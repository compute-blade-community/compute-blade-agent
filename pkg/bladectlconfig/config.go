package bladectlconfig

type BladectlConfig struct {
	Blades       []NamedBlade `yaml:"blades"`
	CurrentBlade string       `yaml:"current-blade"`
}

type NamedBlade struct {
	Name  string `yaml:"name"`
	Blade Blade  `yaml:"blade"`
}

type Blade struct {
	Server                   string      `yaml:"server"`
	CertificateAuthorityData string      `yaml:"certificate-authority-data,omitempty"`
	Certificate              Certificate `yaml:"cert,omitempty"`
}

type Certificate struct {
	ClientCertificateData string `yaml:"client-certificate-data"`
	ClientKeyData         string `yaml:"client-key-data"`
}
