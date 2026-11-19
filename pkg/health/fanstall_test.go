package health_test

import (
	"testing"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/health"
	"github.com/stretchr/testify/assert"
)

func newFanStallDetector() *health.FanStallDetector {
	return &health.FanStallDetector{Config: health.FanStallConfig{
		Enabled:     true,
		MinPercent:  20,
		MinRPM:      100,
		GracePeriod: 15 * time.Second,
	}}
}

func TestFanStallDetector_RaisesAfterGracePeriod(t *testing.T) {
	t.Parallel()

	d := newFanStallDetector()
	t0 := time.Unix(1000, 0)

	assert.Equal(t, health.Unchanged, d.Observe(t0, 50, 0))
	assert.Equal(t, health.Unchanged, d.Observe(t0.Add(10*time.Second), 50, 0))
	assert.False(t, d.Active())

	assert.Equal(t, health.Raised, d.Observe(t0.Add(15*time.Second), 50, 0))
	assert.True(t, d.Active())

	// stays raised without re-reporting
	assert.Equal(t, health.Unchanged, d.Observe(t0.Add(20*time.Second), 50, 0))

	// clears as soon as the fan spins again
	assert.Equal(t, health.Cleared, d.Observe(t0.Add(25*time.Second), 50, 1200))
	assert.False(t, d.Active())
}

func TestFanStallDetector_SpinUpWithinGracePeriod(t *testing.T) {
	t.Parallel()

	d := newFanStallDetector()
	t0 := time.Unix(1000, 0)

	assert.Equal(t, health.Unchanged, d.Observe(t0, 40, 0))
	assert.Equal(t, health.Unchanged, d.Observe(t0.Add(5*time.Second), 40, 800))
	// a later dip starts a new grace period
	assert.Equal(t, health.Unchanged, d.Observe(t0.Add(10*time.Second), 40, 0))
	assert.Equal(t, health.Unchanged, d.Observe(t0.Add(20*time.Second), 40, 0))
	assert.Equal(t, health.Raised, d.Observe(t0.Add(25*time.Second), 40, 0))
}

func TestFanStallDetector_IgnoresLowCommandedSpeed(t *testing.T) {
	t.Parallel()

	d := newFanStallDetector()
	t0 := time.Unix(1000, 0)

	for i := 0; i < 10; i++ {
		assert.Equal(t, health.Unchanged, d.Observe(t0.Add(time.Duration(i)*10*time.Second), 10, 0))
	}
	assert.False(t, d.Active())
}

func TestFanStallDetector_LowSpeedResetsSuspicion(t *testing.T) {
	t.Parallel()

	d := newFanStallDetector()
	t0 := time.Unix(1000, 0)

	assert.Equal(t, health.Unchanged, d.Observe(t0, 50, 0))
	// commanded below MinPercent: can't judge, suspicion is dropped
	assert.Equal(t, health.Unchanged, d.Observe(t0.Add(10*time.Second), 10, 0))
	// grace period starts over
	assert.Equal(t, health.Unchanged, d.Observe(t0.Add(20*time.Second), 50, 0))
	assert.Equal(t, health.Unchanged, d.Observe(t0.Add(30*time.Second), 50, 0))
	assert.Equal(t, health.Raised, d.Observe(t0.Add(35*time.Second), 50, 0))
}

func TestFanStallDetector_StallKeptWhileUnjudgeable(t *testing.T) {
	t.Parallel()

	d := newFanStallDetector()
	t0 := time.Unix(1000, 0)

	d.Observe(t0, 50, 0)
	assert.Equal(t, health.Raised, d.Observe(t0.Add(15*time.Second), 50, 0))

	// commanded speed drops below MinPercent: we can't tell whether the fan works, keep the stall
	assert.Equal(t, health.Unchanged, d.Observe(t0.Add(20*time.Second), 0, 0))
	assert.True(t, d.Active())
}
