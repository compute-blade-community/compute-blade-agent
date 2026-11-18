package health_test

import (
	"testing"

	"github.com/compute-blade-community/compute-blade-agent/pkg/health"
	"github.com/stretchr/testify/assert"
)

func TestThresholdDetector(t *testing.T) {
	t.Parallel()

	d := health.ThresholdDetector{Threshold: 60, Hysteresis: 5}

	steps := []struct {
		value  float64
		want   health.Transition
		active bool
	}{
		{40, health.Unchanged, false},
		{59.9, health.Unchanged, false},
		{60, health.Raised, true},
		{70, health.Unchanged, true},
		{56, health.Unchanged, true}, // inside hysteresis band
		{55, health.Unchanged, true}, // exactly threshold-hysteresis is still active
		{54.9, health.Cleared, false},
		{50, health.Unchanged, false},
		{61, health.Raised, true},
	}

	for _, s := range steps {
		assert.Equal(t, s.want, d.Observe(s.value), "value %v", s.value)
		assert.Equal(t, s.active, d.Active(), "value %v", s.value)
	}
}

func TestThresholdDetector_Reset(t *testing.T) {
	t.Parallel()

	d := health.ThresholdDetector{Threshold: 60, Hysteresis: 5}
	assert.Equal(t, health.Raised, d.Observe(65))

	d.Reset()
	assert.False(t, d.Active())

	// Still above the threshold, so the next observation raises again
	assert.Equal(t, health.Raised, d.Observe(65))
}
