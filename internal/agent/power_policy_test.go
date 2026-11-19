package internal_agent

import (
	"context"
	"errors"
	"testing"

	"github.com/compute-blade-community/compute-blade-agent/pkg/cpufreq"
	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal"
	"github.com/compute-blade-community/compute-blade-agent/pkg/health"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCPU records applied limits
type fakeCPU struct {
	applied  []cpufreq.Limits
	applyErr error
}

func (f *fakeCPU) Validate(l cpufreq.Limits) error {
	if l.Governor == "turbo" {
		return errors.New("no such governor")
	}
	return nil
}

func (f *fakeCPU) Apply(l cpufreq.Limits) error {
	if f.applyErr != nil {
		return f.applyErr
	}
	f.applied = append(f.applied, l)
	return nil
}

func (f *fakeCPU) Restore() error { return f.Apply(cpufreq.Limits{}) }

func (f *fakeCPU) last() cpufreq.Limits { return f.applied[len(f.applied)-1] }

var (
	limitedPowerLimits = cpufreq.Limits{Governor: "conservative", MaxFreqKHz: 1_200_000}
	undervoltageLimits = cpufreq.Limits{Governor: "powersave", MaxFreqKHz: 1_500_000}
)

func TestPowerPolicy_Desired(t *testing.T) {
	t.Parallel()

	p, err := newPowerPolicy(&fakeCPU{}, limitedPowerLimits, undervoltageLimits)
	require.NoError(t, err)

	limits, reasons := p.desired(false, false)
	assert.True(t, limits.IsZero())
	assert.Empty(t, reasons)

	limits, reasons = p.desired(true, false)
	assert.Equal(t, limitedPowerLimits, limits)
	assert.Equal(t, []string{powerLimitReasonLimitedPower}, reasons)

	// both: under-voltage governor wins, lowest frequency cap wins
	limits, reasons = p.desired(true, true)
	assert.Equal(t, cpufreq.Limits{Governor: "powersave", MaxFreqKHz: 1_200_000}, limits)
	assert.Equal(t, []string{powerLimitReasonUndervoltage, powerLimitReasonLimitedPower}, reasons)
}

func TestPowerPolicy_UnconfiguredReasonIsIgnored(t *testing.T) {
	t.Parallel()

	p, err := newPowerPolicy(&fakeCPU{}, cpufreq.Limits{}, undervoltageLimits)
	require.NoError(t, err)

	limits, reasons := p.desired(true, false)
	assert.True(t, limits.IsZero())
	assert.Empty(t, reasons)
}

func TestPowerPolicy_InvalidGovernor(t *testing.T) {
	t.Parallel()

	_, err := newPowerPolicy(&fakeCPU{}, cpufreq.Limits{Governor: "turbo"}, cpufreq.Limits{})
	assert.Error(t, err)
}

func TestEvaluatePowerPolicy(t *testing.T) {
	t.Parallel()

	cpu := &fakeCPU{}
	p, err := newPowerPolicy(cpu, limitedPowerLimits, undervoltageLimits)
	require.NoError(t, err)

	blade := &hal.ComputeBladeHalMock{}
	blade.On("GetPowerStatus").Return(hal.PowerStatus(hal.PowerPoe802at), nil)
	a := &computeBladeAgent{
		blade:                blade,
		eventChan:            make(chan events.Message, 10),
		powerPolicy:          p,
		undervoltageDetector: &health.FlagDetector{},
	}
	ctx := context.Background()

	// PoE+ and no under-voltage: nothing to do
	a.evaluatePowerPolicy(ctx)
	assert.Empty(t, cpu.applied)
	assert.Empty(t, drainEvents(a.eventChan))

	// under-voltage raised: limit applied once
	a.undervoltageDetector.Observe(timeZero, true)
	a.evaluatePowerPolicy(ctx)
	a.evaluatePowerPolicy(ctx)
	require.Len(t, cpu.applied, 1)
	assert.Equal(t, undervoltageLimits, cpu.last())

	msgs := drainEvents(a.eventChan)
	require.Len(t, msgs, 1)
	assert.Equal(t, events.Event(events.PowerLimitEvent), msgs[0].Event)
	assert.Equal(t, events.PowerLimitDetails{
		Reasons: []string{powerLimitReasonUndervoltage}, Governor: "powersave", MaxFreqMHz: 1500,
	}, msgs[0].Details)

	// under-voltage cleared: limit lifted
	a.undervoltageDetector = &health.FlagDetector{}
	a.evaluatePowerPolicy(ctx)
	assert.True(t, cpu.last().IsZero())
	msgs = drainEvents(a.eventChan)
	require.Len(t, msgs, 1)
	assert.Equal(t, events.Event(events.PowerLimitClearEvent), msgs[0].Event)

	// after stop, nothing is applied anymore
	require.NoError(t, p.stop())
	applied := len(cpu.applied)
	a.undervoltageDetector.Observe(timeZero, true)
	a.evaluatePowerPolicy(ctx)
	assert.Len(t, cpu.applied, applied)
}

func TestEvaluatePowerPolicy_RetriesFailedApply(t *testing.T) {
	t.Parallel()

	cpu := &fakeCPU{applyErr: errors.New("read-only file system")}
	p, err := newPowerPolicy(cpu, limitedPowerLimits, cpufreq.Limits{})
	require.NoError(t, err)

	blade := &hal.ComputeBladeHalMock{}
	blade.On("GetPowerStatus").Return(hal.PowerStatus(hal.PowerPoeOrUsbC), nil)
	a := &computeBladeAgent{blade: blade, eventChan: make(chan events.Message, 10), powerPolicy: p}

	a.evaluatePowerPolicy(context.Background())
	assert.Empty(t, drainEvents(a.eventChan))

	cpu.applyErr = nil
	a.evaluatePowerPolicy(context.Background())
	require.Len(t, cpu.applied, 1)
	assert.Equal(t, limitedPowerLimits, cpu.last())
}
