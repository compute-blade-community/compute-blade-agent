package util_test

import (
	"testing"

	"github.com/compute-blade-community/compute-blade-agent/pkg/util"
	"github.com/stretchr/testify/assert"
)

func TestGetHostIPs_ReturnsNonLoopbackIPs(t *testing.T) {
	ips, err := util.GetHostIPs()
	assert.NoError(t, err)

	for _, ip := range ips {
		assert.False(t, ip.IsLoopback(), "Should not return loopback IPs")
		assert.False(t, ip.IsUnspecified(), "Should not return unspecified IPs")
	}
}
