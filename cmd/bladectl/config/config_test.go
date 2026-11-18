package config_test

import (
	"testing"

	"github.com/compute-blade-community/compute-blade-agent/cmd/bladectl/config"
	"github.com/stretchr/testify/assert"
)

func TestMergeDiscovered(t *testing.T) {
	t.Parallel()

	cfg := &config.BladectlConfig{
		Blades: []config.NamedBlade{
			{Name: "local", Blade: config.Blade{Server: "/tmp/compute-blade-agent.sock"}},
			{Name: "loopback", Blade: config.Blade{Server: "127.0.0.1:8081"}},
			{Name: "blade-pi1", Blade: config.Blade{Server: "192.168.1.10:8081", Certificate: config.Certificate{ClientKeyData: "key"}}},
			{Name: "blade-pi2", Blade: config.Blade{Server: "blade-pi2.local:8081"}},
		},
		CurrentBlade: "local",
	}

	assert.Equal(t, config.DiscoveryLocal, cfg.MergeDiscovered("local", "local.local:8081", false))
	assert.Equal(t, config.DiscoveryLocal, cfg.MergeDiscovered("loopback", "loopback.local:8081", false))
	assert.Equal(t, config.DiscoveryUnchanged, cfg.MergeDiscovered("blade-pi2", "blade-pi2.local:8081", false))

	// address updated, credentials kept
	assert.Equal(t, config.DiscoveryUpdated, cfg.MergeDiscovered("blade-pi1", "blade-pi1.local:8081", true))
	assert.Equal(t, "blade-pi1.local:8081", cfg.Blades[2].Blade.Server)
	assert.Equal(t, "key", cfg.Blades[2].Blade.Certificate.ClientKeyData)

	// unknown blades: added if unauthenticated, otherwise credentials are needed
	assert.Equal(t, config.DiscoveryAdded, cfg.MergeDiscovered("blade-pi3", "blade-pi3.local:8081", false))
	assert.Equal(t, config.DiscoveryNeedsCredentials, cfg.MergeDiscovered("blade-pi4", "blade-pi4.local:8081", true))

	assert.Len(t, cfg.Blades, 5)
	assert.Equal(t, "local", cfg.CurrentBlade)
}

func TestMergeDiscovered_SetsCurrentBlade(t *testing.T) {
	t.Parallel()

	cfg := &config.BladectlConfig{}
	assert.Equal(t, config.DiscoveryAdded, cfg.MergeDiscovered("blade-pi1", "blade-pi1.local:8081", false))
	assert.Equal(t, "blade-pi1", cfg.CurrentBlade)
}
