package internal_agent

import (
	"context"
	"testing"
	"time"

	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal"
	"github.com/compute-blade-community/compute-blade-agent/pkg/health"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func drainEvents(ch chan events.Message) []events.Message {
	var msgs []events.Message
	for {
		select {
		case msg := <-ch:
			msgs = append(msgs, msg)
		case <-time.After(10 * time.Millisecond):
			return msgs
		}
	}
}

func TestEvaluateThrottleStatus(t *testing.T) {
	t.Parallel()

	blade := &hal.ComputeBladeHalMock{}
	a := &computeBladeAgent{
		blade:                blade,
		eventChan:            make(chan events.Message, 10),
		undervoltageDetector: &health.FlagDetector{ClearAfter: 0},
		throttlingDetector:   &health.FlagDetector{ClearAfter: 0},
	}
	ctx := context.Background()

	// under-voltage that caps the ARM frequency raises both conditions
	call := blade.On("GetThrottleStatus").Return(hal.ThrottleUnderVoltage|hal.ThrottleArmFreqCapped, nil)
	assert.True(t, a.evaluateThrottleStatus(ctx))

	msgs := drainEvents(a.eventChan)
	require.Len(t, msgs, 2)
	assert.Equal(t, events.Event(events.UndervoltageEvent), msgs[0].Event)
	assert.Equal(t, events.Event(events.ThrottledEvent), msgs[1].Event)
	assert.Equal(t, events.ThrottleDetails{Flags: 0x3}, msgs[0].Details)

	// flags gone: both clear (ClearAfter is 0)
	call.Unset()
	blade.On("GetThrottleStatus").Return(hal.ThrottleUnderVoltageOccurred|hal.ThrottleArmFreqCappedOccurred, nil)
	assert.True(t, a.evaluateThrottleStatus(ctx))

	msgs = drainEvents(a.eventChan)
	require.Len(t, msgs, 2)
	assert.Equal(t, events.Event(events.UndervoltageClearEvent), msgs[0].Event)
	assert.Equal(t, events.Event(events.ThrottledClearEvent), msgs[1].Event)
}

func TestEvaluateThrottleStatus_NotSupported(t *testing.T) {
	t.Parallel()

	blade := &hal.ComputeBladeHalMock{}
	blade.On("GetThrottleStatus").Return(hal.ThrottleStatus(0), hal.ErrNotSupported)
	a := &computeBladeAgent{
		blade:                blade,
		eventChan:            make(chan events.Message, 10),
		undervoltageDetector: &health.FlagDetector{},
	}

	assert.False(t, a.evaluateThrottleStatus(context.Background()))
	assert.Empty(t, drainEvents(a.eventChan))
}

func TestToProtoEvent_ThrottleDetails(t *testing.T) {
	t.Parallel()

	msg := events.NewMessage(events.UndervoltageEvent, events.ThrottleDetails{
		Flags: uint32(hal.ThrottleUnderVoltage | hal.ThrottleSoftTempLimit | hal.ThrottleThrottledOccurred),
	})
	ev, err := toProtoEvent(msg, "blade")
	require.NoError(t, err)
	assert.Equal(t, bladeapiv1alpha1.Event_UNDERVOLTAGE, ev.GetEvent())

	details := ev.GetThrottle()
	require.NotNil(t, details)
	assert.True(t, details.GetUnderVoltage())
	assert.True(t, details.GetSoftTempLimit())
	assert.False(t, details.GetThrottled(), "occurred-since-boot bit must not count as currently throttled")
	assert.False(t, details.GetArmFreqCapped())
}

var timeZero = time.Unix(0, 0)
