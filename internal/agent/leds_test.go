package internal_agent

import (
	"context"
	"testing"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/agent"
	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
	"github.com/compute-blade-community/compute-blade-agent/pkg/fancontroller"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
	"github.com/compute-blade-community/compute-blade-agent/pkg/health"
	"github.com/compute-blade-community/compute-blade-agent/pkg/ledengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeLedEngine records the last pattern it was asked to show
type fakeLedEngine struct {
	pattern ledengine.BlinkPattern
}

func (f *fakeLedEngine) SetPattern(p ledengine.BlinkPattern) error {
	f.pattern = p
	return nil
}

func (f *fakeLedEngine) Run(context.Context) error { return nil }

func newLedTestAgent(t *testing.T, indicators map[string]agent.IndicatorConfig) (*computeBladeAgent, error) {
	t.Helper()

	a := &computeBladeAgent{
		config: agent.ComputeBladeAgentConfig{
			IdleLedColor:     led.Color{Green: 16},
			IdentifyLedColor: led.Color{Red: 16, Blue: 16},
			CriticalLedColor: led.Color{Red: 64},
			Indicators:       indicators,
		},
		edgeLedEngine: &fakeLedEngine{},
		topLedEngine:  &fakeLedEngine{},
		state:         agent.NewComputeBladeState(),
		eventChan:     make(chan events.Message, 10),
		eventBus:      events.New(),
	}
	return a, a.setupLeds()
}

var fanStallIndicator = agent.IndicatorConfig{
	Led:      agent.IndicatorLedTop,
	Color:    led.Color{Red: 64, Green: 24},
	Pattern:  ledengine.PatternFastBlink,
	Priority: 30,
}

func TestSetupLeds_ValidIndicator(t *testing.T) {
	t.Parallel()

	a, err := newLedTestAgent(t, map[string]agent.IndicatorConfig{events.ConditionFanStall: fanStallIndicator})
	require.NoError(t, err)
	assert.True(t, a.topLeds.Defined(events.ConditionFanStall))
	assert.False(t, a.edgeLeds.Defined(events.ConditionFanStall))
}

func TestSetupLeds_DisabledIndicator(t *testing.T) {
	t.Parallel()

	cfg := fanStallIndicator
	cfg.Led = agent.IndicatorLedNone
	a, err := newLedTestAgent(t, map[string]agent.IndicatorConfig{events.ConditionFanStall: cfg})
	require.NoError(t, err)
	assert.False(t, a.topLeds.Defined(events.ConditionFanStall))

	// no indicator configured: raising the condition is a no-op
	assert.NoError(t, a.setIndicator(events.ConditionFanStall, true))
}

func TestSetupLeds_InvalidIndicators(t *testing.T) {
	t.Parallel()

	badLed := fanStallIndicator
	badLed.Led = "bottom"
	badPattern := fanStallIndicator
	badPattern.Pattern = "disco"
	badPriority := fanStallIndicator
	badPriority.Priority = ledPriorityIdentify

	for name, indicators := range map[string]map[string]agent.IndicatorConfig{
		"unknown condition": {"fan_on_fire": fanStallIndicator},
		"invalid led":       {events.ConditionFanStall: badLed},
		"invalid pattern":   {events.ConditionFanStall: badPattern},
		"priority too high": {events.ConditionFanStall: badPriority},
	} {
		_, err := newLedTestAgent(t, indicators)
		assert.Error(t, err, name)
	}
}

func TestHandleEvent_FanStallIndicatorBelowCritical(t *testing.T) {
	t.Parallel()

	a, err := newLedTestAgent(t, map[string]agent.IndicatorConfig{events.ConditionFanStall: fanStallIndicator})
	require.NoError(t, err)

	blade := &hal.ComputeBladeHalMock{}
	blade.On("SetStealthMode", false).Return(nil)
	blade.On("SetFanSpeed", uint8(100)).Return(nil)
	a.blade = blade
	a.fanController = newTestFanController(t)
	// a fan speed override set via the API must survive critical mode
	a.fanController.Override(&fancontroller.FanOverrideOpts{Percent: 60})

	ctx := context.Background()
	require.NoError(t, a.handleEvent(ctx, events.NewMessage(events.FanStallEvent, events.FanDetails{TargetPercent: 50})))
	assert.Equal(t, events.ConditionFanStall, a.topLeds.Shown())
	assert.True(t, a.state.ConditionActive(events.ConditionFanStall))

	// critical mode takes over the top LED and hands it back to the stall indicator when cleared
	require.NoError(t, a.handleEvent(ctx, events.NewMessage(events.CriticalEvent, nil)))
	assert.Equal(t, ledLayerCritical, a.topLeds.Shown())

	blade.On("SetStealthMode", a.config.StealthModeEnabled).Return(nil)
	require.NoError(t, a.handleEvent(ctx, events.NewMessage(events.CriticalResetEvent, nil)))
	assert.Equal(t, events.ConditionFanStall, a.topLeds.Shown())
	assert.Equal(t, uint8(60), a.fanController.GetFanSpeedPercent(40))

	require.NoError(t, a.handleEvent(ctx, events.NewMessage(events.FanStallClearEvent, events.FanDetails{TargetPercent: 50, RPM: 1500})))
	assert.Equal(t, "", a.topLeds.Shown())
	assert.False(t, a.state.ConditionActive(events.ConditionFanStall))
}

func TestEvaluateFanStall_EmitsEvents(t *testing.T) {
	t.Parallel()

	blade := &hal.ComputeBladeHalMock{}
	blade.On("GetFanRPM").Return(float64(0), nil)

	a := &computeBladeAgent{
		blade:     blade,
		eventChan: make(chan events.Message, 10),
		fanStallDetector: &health.FanStallDetector{Config: health.FanStallConfig{
			Enabled: true, MinPercent: 20, MinRPM: 100, GracePeriod: 0,
		}},
	}

	a.evaluateFanStall(context.Background(), 60)

	select {
	case msg := <-a.eventChan:
		assert.Equal(t, events.Event(events.FanStallEvent), msg.Event)
		assert.Equal(t, events.FanDetails{TargetPercent: 60, RPM: 0}, msg.Details)
	case <-time.After(time.Second):
		t.Fatal("expected a fan stall event")
	}
}

func newTestFanController(t *testing.T) fancontroller.FanController {
	t.Helper()
	fc, err := fancontroller.NewLinearFanController(fancontroller.Config{
		Steps: []fancontroller.Step{{Temperature: 40, Percent: 40}, {Temperature: 60, Percent: 100}},
	})
	require.NoError(t, err)
	return fc
}
