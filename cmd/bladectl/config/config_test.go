package config_test

import (
	"net"
	"testing"

	"github.com/compute-blade-community/compute-blade-agent/cmd/bladectl/config"
	"github.com/stretchr/testify/assert"
)

func found(name string, authenticated bool, addresses ...string) config.Discovered {
	d := config.Discovered{Name: name, Server: name + ".local:8081", Authenticated: authenticated}
	for _, addr := range addresses {
		d.Addresses = append(d.Addresses, net.ParseIP(addr))
	}
	return d
}

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

	assert.Equal(t, config.DiscoveryLocal, cfg.MergeDiscovered(found("local", false)))
	assert.Equal(t, config.DiscoveryLocal, cfg.MergeDiscovered(found("loopback", false)))
	assert.Equal(t, config.DiscoveryUnchanged, cfg.MergeDiscovered(found("blade-pi2", false)))

	// the blade's IP address changed: address updated, credentials kept
	assert.Equal(t, config.DiscoveryUpdated, cfg.MergeDiscovered(found("blade-pi1", true, "192.168.1.11")))
	assert.Equal(t, "blade-pi1.local:8081", cfg.Blades[2].Blade.Server)
	assert.Equal(t, "key", cfg.Blades[2].Blade.Certificate.ClientKeyData)

	// unknown blades: added if unauthenticated, otherwise credentials are needed
	assert.Equal(t, config.DiscoveryAdded, cfg.MergeDiscovered(found("blade-pi3", false)))
	assert.Equal(t, config.DiscoveryNeedsCredentials, cfg.MergeDiscovered(found("blade-pi4", true)))

	assert.Len(t, cfg.Blades, 5)
	assert.Equal(t, "local", cfg.CurrentBlade)
}

func TestMergeDiscovered_KeepsServersThatReachTheBlade(t *testing.T) {
	t.Parallel()

	for _, server := range []string{
		"blade-pi1:8081",             // DNS search domain, e.g. MagicDNS
		"BLADE-PI1.local.:8081",      // case and trailing dot
		"blade-pi1.example.net:8081", // regular DNS
		"192.168.1.10:8081",          // one of the blade's addresses
		"[fd00::10]:8081",            // IPv6 address
	} {
		cfg := &config.BladectlConfig{Blades: []config.NamedBlade{{Name: "blade-pi1", Blade: config.Blade{Server: server}}}}
		assert.Equal(t, config.DiscoveryUnchanged, cfg.MergeDiscovered(found("blade-pi1", true, "192.168.1.10", "fd00::10")), server)
		assert.Equal(t, server, cfg.Blades[0].Blade.Server, server)
	}

	for _, server := range []string{
		"blade-pi1:9090",    // different port
		"blade-pi2:8081",    // another blade
		"192.168.1.99:8081", // not one of the blade's addresses
	} {
		cfg := &config.BladectlConfig{Blades: []config.NamedBlade{{Name: "blade-pi1", Blade: config.Blade{Server: server}}}}
		assert.Equal(t, config.DiscoveryUpdated, cfg.MergeDiscovered(found("blade-pi1", true, "192.168.1.10")), server)
	}
}

func TestMergeDiscovered_SetsCurrentBlade(t *testing.T) {
	t.Parallel()

	cfg := &config.BladectlConfig{}
	assert.Equal(t, config.DiscoveryAdded, cfg.MergeDiscovered(found("blade-pi1", false)))
	assert.Equal(t, "blade-pi1", cfg.CurrentBlade)
}
