package health_test

import (
	"testing"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/health"
	"github.com/stretchr/testify/assert"
)

func TestFlagDetector(t *testing.T) {
	t.Parallel()

	d := health.FlagDetector{ClearAfter: 30 * time.Second}
	t0 := time.Unix(1000, 0)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }

	assert.Equal(t, health.Unchanged, d.Observe(at(0), false))
	assert.Equal(t, health.Raised, d.Observe(at(2), true))
	assert.True(t, d.Active())

	// flag goes away, but not for long enough
	assert.Equal(t, health.Unchanged, d.Observe(at(4), false))
	assert.Equal(t, health.Unchanged, d.Observe(at(30), false))

	// flag seen again restarts the clear timer
	assert.Equal(t, health.Unchanged, d.Observe(at(31), true))
	assert.Equal(t, health.Unchanged, d.Observe(at(60), false))
	assert.True(t, d.Active())

	assert.Equal(t, health.Cleared, d.Observe(at(61), false))
	assert.False(t, d.Active())
	assert.Equal(t, health.Unchanged, d.Observe(at(90), false))
}
