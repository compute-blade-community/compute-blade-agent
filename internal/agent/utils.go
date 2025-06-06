package internal_agent

import (
	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fromProto converts a `bladeapiv1alpha1.Event` into a corresponding `events.Event` type.
// Returns an error if the event type is invalid.
func fromProto(event bladeapiv1alpha1.Event) (events.Event, error) {
	switch event {
	case bladeapiv1alpha1.Event_IDENTIFY:
		return events.IdentifyEvent, nil
	case bladeapiv1alpha1.Event_IDENTIFY_CONFIRM:
		return events.IdentifyConfirmEvent, nil
	case bladeapiv1alpha1.Event_CRITICAL:
		return events.CriticalEvent, nil
	case bladeapiv1alpha1.Event_CRITICAL_RESET:
		return events.CriticalResetEvent, nil
	default:
		return events.NoopEvent, status.Errorf(codes.InvalidArgument, "invalid event type")
	}
}
