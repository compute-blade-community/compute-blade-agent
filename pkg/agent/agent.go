package agent

import (
	"context"

	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
)

// ComputeBladeAgent implements the core-logic of the agent. It is responsible for handling events and interfacing with the hardware.
type ComputeBladeAgent interface {
	// RunAsync dispatches the agent until the context is canceled or an error occurs
	RunAsync(ctx context.Context, cancel context.CancelCauseFunc)
	// Run dispatches the agent and blocks until the context is canceled or an error occurs
	Run(ctx context.Context) error
	// EmitEvent emits an event to the agent
	EmitEvent(ctx context.Context, event events.Event) error
	// SetFanSpeed sets the fan speed in percent
	SetFanSpeed(_ context.Context, speed uint8) error
	// SetStealthMode sets the stealth mode
	SetStealthMode(_ context.Context, enabled bool) error
	// WaitForIdentifyConfirm blocks until the user confirms the identify mode
	WaitForIdentifyConfirm(ctx context.Context) error
}
