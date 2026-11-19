package internal_agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/compute-blade-community/compute-blade-agent/cmd/bladectl/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestLocalEntryFits(t *testing.T) {
	t.Parallel()

	socket := config.Blade{Server: "/tmp/compute-blade-agent.sock"}
	tcp := config.Blade{Server: "localhost:8081"}
	edited := config.Blade{Server: "blade-pi1:8081"}
	withBrokenCredentials := config.Blade{Server: "localhost:8081", Certificate: config.Certificate{
		ClientCertificateData: "bm90IGEgY2VydA==", ClientKeyData: "bm90IGEga2V5",
	}}

	tests := []struct {
		name          string
		blade         config.Blade
		listen        string
		mode          ListenMode
		authenticated bool
		fits          bool
	}{
		{"socket entry, unix mode", socket, "/tmp/compute-blade-agent.sock", ModeUnix, false, true},
		{"socket entry, other socket", socket, "/run/cba.sock", ModeUnix, false, false},
		{"socket entry, tcp mode", socket, ":8081", ModeTcp, false, false},
		{"socket entry, tcp mode with mTLS", socket, ":8081", ModeTcp, true, false},
		{"tcp entry, tcp mode", tcp, ":8081", ModeTcp, false, true},
		{"edited host name is kept", edited, ":8081", ModeTcp, false, true},
		{"tcp entry, other port", tcp, ":9000", ModeTcp, false, false},
		{"tcp entry, unix mode", tcp, "/tmp/compute-blade-agent.sock", ModeUnix, false, false},
		{"tcp entry without credentials, mTLS", tcp, ":8081", ModeTcp, true, false},
		{"invalid credentials, mTLS", withBrokenCredentials, ":8081", ModeTcp, true, false},
		{"credentials, no mTLS", withBrokenCredentials, ":8081", ModeTcp, false, false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.fits, localEntryFits(tt.blade, tt.listen, tt.mode, tt.authenticated), tt.name)
	}
}

// Without mTLS no CA is involved, so the whole function can run against a temporary home directory.
func TestEnsureLocalBladectlConfig_SwitchesModeAndKeepsOtherBlades(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	hostname, err := os.Hostname()
	require.NoError(t, err)

	path := filepath.Join(home, ".config", "bladectl", "config.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	initial := config.BladectlConfig{
		Blades: []config.NamedBlade{
			{Name: "other-blade", Blade: config.Blade{Server: "other-blade:8081"}},
			{Name: hostname, Blade: config.Blade{Server: "/tmp/compute-blade-agent.sock"}},
		},
		CurrentBlade: hostname,
	}
	raw, err := yaml.Marshal(&initial)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))

	require.Nil(t, EnsureLocalBladectlConfig(context.Background(), ":8081", ModeTcp, false))

	var cfg config.BladectlConfig
	raw, err = os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(raw, &cfg))

	require.Len(t, cfg.Blades, 2)
	assert.Equal(t, "other-blade:8081", cfg.Blades[0].Blade.Server)
	assert.Equal(t, "localhost:8081", cfg.Blades[1].Blade.Server)
	assert.Equal(t, hostname, cfg.CurrentBlade)

	// a second start with the same settings leaves the file alone
	before, err := os.Stat(path)
	require.NoError(t, err)
	require.Nil(t, EnsureLocalBladectlConfig(context.Background(), ":8081", ModeTcp, false))
	after, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, before.ModTime(), after.ModTime())
}

func TestEnsureLocalBladectlConfig_CreatesConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	require.Nil(t, EnsureLocalBladectlConfig(context.Background(), "/tmp/compute-blade-agent.sock", ModeUnix, false))

	raw, err := os.ReadFile(filepath.Join(home, ".config", "bladectl", "config.yaml"))
	require.NoError(t, err)
	var cfg config.BladectlConfig
	require.NoError(t, yaml.Unmarshal(raw, &cfg))
	require.Len(t, cfg.Blades, 1)
	assert.Equal(t, "/tmp/compute-blade-agent.sock", cfg.Blades[0].Blade.Server)
	assert.Equal(t, cfg.Blades[0].Name, cfg.CurrentBlade)
}
