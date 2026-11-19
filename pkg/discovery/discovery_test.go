package discovery_test

import (
	"net"
	"testing"

	"github.com/compute-blade-community/compute-blade-agent/pkg/discovery"
	"github.com/libp2p/zeroconf/v2"
	"github.com/stretchr/testify/assert"
)

func TestAdvertisement_TXT(t *testing.T) {
	t.Parallel()

	assert.Equal(t, []string{"version=v1.2.3", "api=v1alpha1", "auth=mtls"},
		discovery.Advertisement{Version: "v1.2.3", Authenticated: true}.TXT())
	assert.Equal(t, []string{"version=dev", "api=v1alpha1", "auth=none"},
		discovery.Advertisement{Version: "dev"}.TXT())
}

func TestFromServiceEntry(t *testing.T) {
	t.Parallel()

	entry := &zeroconf.ServiceEntry{
		ServiceRecord: zeroconf.ServiceRecord{Instance: "blade-pi1"},
		HostName:      "blade-pi1.local.",
		Port:          8081,
		Text:          discovery.Advertisement{Version: "v1.2.3", Authenticated: true}.TXT(),
		AddrIPv4:      []net.IP{net.ParseIP("192.168.1.10")},
		AddrIPv6:      []net.IP{net.ParseIP("fe80::1")},
	}

	blade := discovery.FromServiceEntry(entry)
	assert.Equal(t, "blade-pi1", blade.Name)
	assert.Equal(t, "blade-pi1.local", blade.Host)
	assert.Equal(t, "blade-pi1.local:8081", blade.Server())
	assert.Equal(t, "v1.2.3", blade.Version)
	assert.Equal(t, "v1alpha1", blade.API)
	assert.True(t, blade.Authenticated)
	assert.Len(t, blade.Addresses, 2)
}

func TestFromServiceEntry_MissingFields(t *testing.T) {
	t.Parallel()

	blade := discovery.FromServiceEntry(&zeroconf.ServiceEntry{
		ServiceRecord: zeroconf.ServiceRecord{Instance: `blade\ 2`},
		Port:          8081,
		Text:          []string{"garbage", "auth=none"},
	})
	assert.Equal(t, "blade 2", blade.Name)
	assert.Equal(t, "blade 2.local", blade.Host)
	assert.False(t, blade.Authenticated)
	assert.Empty(t, blade.Version)
}
