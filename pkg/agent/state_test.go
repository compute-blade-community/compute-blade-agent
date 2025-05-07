package agent_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/uptime-industries/compute-blade-agent/pkg/agent"
	"github.com/uptime-industries/compute-blade-agent/pkg/events"
)

func TestNewComputeBladeState(t *testing.T) {
	t.Parallel()

	state := agent.NewComputeBladeState()
	assert.NotNil(t, state)
}

func TestComputeBladeState_RegisterEventIdentify(t *testing.T) {
	t.Parallel()

	state := agent.NewComputeBladeState()

	// Identify event
	state.RegisterEvent(events.IdentifyEvent)
	assert.True(t, state.IdentifyActive())
	state.RegisterEvent(events.IdentifyConfirmEvent)
	assert.False(t, state.IdentifyActive())
}

func TestComputeBladeState_RegisterEventCritical(t *testing.T) {
	t.Parallel()

	state := agent.NewComputeBladeState()

	// critical event
	state.RegisterEvent(events.CriticalEvent)
	assert.True(t, state.CriticalActive())
	state.RegisterEvent(events.CriticalResetEvent)
	assert.False(t, state.CriticalActive())
}

func TestComputeBladeState_RegisterEventMixed(t *testing.T) {
	t.Parallel()

	state := agent.NewComputeBladeState()

	// Send a bunch of events
	state.RegisterEvent(events.CriticalEvent)
	state.RegisterEvent(events.CriticalResetEvent)
	state.RegisterEvent(events.NoopEvent)
	state.RegisterEvent(events.CriticalEvent)
	state.RegisterEvent(events.NoopEvent)
	state.RegisterEvent(events.IdentifyEvent)
	state.RegisterEvent(events.IdentifyEvent)
	state.RegisterEvent(events.CriticalResetEvent)
	state.RegisterEvent(events.IdentifyEvent)

	assert.False(t, state.CriticalActive())
	assert.True(t, state.IdentifyActive())
}

func TestComputeBladeState_WaitForIdentifyConfirm_NoTimeout(t *testing.T) {
	t.Parallel()

	state := agent.NewComputeBladeState()

	// send identify event
	t.Log("Setting identify event")
	state.RegisterEvent(events.IdentifyEvent)
	assert.True(t, state.IdentifyActive())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx := context.Background()

		// Block until identify status is cleared
		t.Log("Waiting for identify confirm")
		err := state.WaitForIdentifyConfirm(ctx)
		assert.NoError(t, err)
	}()

	// Give goroutine time to start
	time.Sleep(50 * time.Millisecond)

	// confirm event
	state.RegisterEvent(events.IdentifyConfirmEvent)
	t.Log("Identify event confirmed")

	wg.Wait()
}

func TestComputeBladeState_WaitForIdentifyConfirm_Timeout(t *testing.T) {
	t.Parallel()

	state := agent.NewComputeBladeState()

	// send identify event
	t.Log("Setting identify event")
	state.RegisterEvent(events.IdentifyEvent)
	assert.True(t, state.IdentifyActive())

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Block until identify status is cleared
		t.Log("Waiting for identify confirm")
		err := state.WaitForIdentifyConfirm(ctx)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	}()

	// Give goroutine time to start.
	time.Sleep(50 * time.Millisecond)

	// confirm event
	state.RegisterEvent(events.IdentifyConfirmEvent)
	t.Log("Identify event confirmed")

	wg.Wait()
}

func TestComputeBladeState_WaitForCriticalClear_NoTimeout(t *testing.T) {
	t.Parallel()

	state := agent.NewComputeBladeState()

	// send critical event
	t.Log("Setting critical event")
	state.RegisterEvent(events.CriticalEvent)
	assert.True(t, state.CriticalActive())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx := context.Background()

		// Block until critical status is cleared
		t.Log("Waiting for critical confirm")
		err := state.WaitForCriticalClear(ctx)
		assert.NoError(t, err)
	}()

	// Give goroutine time to start
	time.Sleep(50 * time.Millisecond)

	// confirm event
	state.RegisterEvent(events.CriticalResetEvent)
	t.Log("critical event confirmed")

	wg.Wait()
}

func TestComputeBladeState_WaitForCriticalClear_Timeout(t *testing.T) {
	t.Parallel()

	state := agent.NewComputeBladeState()

	// send critical event
	t.Log("Setting critical event")
	state.RegisterEvent(events.CriticalEvent)
	assert.True(t, state.CriticalActive())

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Block until critical status is cleared
		t.Log("Waiting for critical confirm")
		err := state.WaitForCriticalClear(ctx)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	}()

	// Give goroutine time to start.
	time.Sleep(50 * time.Millisecond)

	// confirm event
	state.RegisterEvent(events.CriticalResetEvent)
	t.Log("critical event confirmed")

	wg.Wait()
}
