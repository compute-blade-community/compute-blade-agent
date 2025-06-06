package agent

import (
	"context"

	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
)

// ComputeBladeAgent implements the core-logic of the agent. It is responsible for handling events and interfacing with the hardware.
// any ComputeBladeAgent must also be a bladeapiv1alpha1.BladeAgentServiceServer to handle the gRPC API requests.
type ComputeBladeAgent interface {
	bladeapiv1alpha1.BladeAgentServiceServer
	// RunAsync dispatches the agent until the context is canceled or an error occurs
	RunAsync(ctx context.Context, cancel context.CancelCauseFunc)
	// Run dispatches the agent and blocks until the context is canceled or an error occurs
	Run(ctx context.Context) error
	// GracefulStop gracefully stops the gRPC server, ensuring all in-progress RPCs are completed before shutting down.
	GracefulStop(ctx context.Context) error
}
