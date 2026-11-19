package internal_agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGrpcPort(t *testing.T) {
	t.Parallel()

	for listen, want := range map[string]int{
		":8081":         8081,
		"0.0.0.0:8081":  8081,
		"[::]:9000":     9000,
		"127.0.0.1:443": 443,
	} {
		got, err := grpcPort(listen)
		require.NoError(t, err, listen)
		assert.Equal(t, want, got, listen)
	}

	for _, listen := range []string{"/tmp/compute-blade-agent.sock", ":http", ":0", "8081"} {
		_, err := grpcPort(listen)
		assert.Error(t, err, listen)
	}
}
