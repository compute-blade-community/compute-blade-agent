package internal_agent

import (
	"fmt"

	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
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

// toProtoEventType maps an internal event to its public API representation.
// Returns false for internal-only events that are not published.
func toProtoEventType(event events.Event) (bladeapiv1alpha1.Event, bool) {
	switch event {
	case events.IdentifyEvent:
		return bladeapiv1alpha1.Event_IDENTIFY, true
	case events.IdentifyConfirmEvent:
		return bladeapiv1alpha1.Event_IDENTIFY_CONFIRM, true
	case events.CriticalEvent:
		return bladeapiv1alpha1.Event_CRITICAL, true
	case events.CriticalResetEvent:
		return bladeapiv1alpha1.Event_CRITICAL_RESET, true
	case events.EdgeButtonEvent:
		return bladeapiv1alpha1.Event_BUTTON_PRESS, true
	case events.FanStallEvent:
		return bladeapiv1alpha1.Event_FAN_STALL, true
	case events.FanStallClearEvent:
		return bladeapiv1alpha1.Event_FAN_STALL_CLEAR, true
	case events.UndervoltageEvent:
		return bladeapiv1alpha1.Event_UNDERVOLTAGE, true
	case events.UndervoltageClearEvent:
		return bladeapiv1alpha1.Event_UNDERVOLTAGE_CLEAR, true
	case events.ThrottledEvent:
		return bladeapiv1alpha1.Event_THROTTLED, true
	case events.ThrottledClearEvent:
		return bladeapiv1alpha1.Event_THROTTLED_CLEAR, true
	case events.PowerLimitEvent:
		return bladeapiv1alpha1.Event_POWER_LIMIT, true
	case events.PowerLimitClearEvent:
		return bladeapiv1alpha1.Event_POWER_LIMIT_CLEAR, true
	default:
		return 0, false
	}
}

// toProtoEvent converts an event message into the AgentEvent published via WatchEvents.
func toProtoEvent(msg events.Message, blade string) (*bladeapiv1alpha1.AgentEvent, error) {
	eventType, ok := toProtoEventType(msg.Event)
	if !ok {
		return nil, fmt.Errorf("event %s has no API representation", msg.Event)
	}

	agentEvent := &bladeapiv1alpha1.AgentEvent{
		Event:     eventType,
		Timestamp: timestamppb.New(msg.Timestamp),
		Blade:     blade,
	}

	switch details := msg.Details.(type) {
	case events.FanDetails:
		agentEvent.Details = &bladeapiv1alpha1.AgentEvent_Fan{Fan: &bladeapiv1alpha1.FanDetails{
			TargetPercent: uint32(details.TargetPercent),
			Rpm:           uint32(max(details.RPM, 0)),
		}}
	case events.ThrottleDetails:
		status := hal.ThrottleStatus(details.Flags)
		agentEvent.Details = &bladeapiv1alpha1.AgentEvent_Throttle{Throttle: &bladeapiv1alpha1.ThrottleDetails{
			Flags:         details.Flags,
			UnderVoltage:  status.Has(hal.ThrottleUnderVoltage),
			ArmFreqCapped: status.Has(hal.ThrottleArmFreqCapped),
			Throttled:     status.Has(hal.ThrottleThrottled),
			SoftTempLimit: status.Has(hal.ThrottleSoftTempLimit),
		}}
	case events.PowerLimitDetails:
		agentEvent.Details = &bladeapiv1alpha1.AgentEvent_PowerLimit{PowerLimit: &bladeapiv1alpha1.PowerLimitDetails{
			Reasons:    details.Reasons,
			Governor:   details.Governor,
			MaxFreqMhz: uint32(details.MaxFreqMHz),
		}}
	}

	return agentEvent, nil
}

// eventFilter returns a predicate matching messages whose API event type is in the given list.
// An empty list matches every message.
func eventFilter(wanted []bladeapiv1alpha1.Event) func(events.Message) bool {
	if len(wanted) == 0 {
		return func(events.Message) bool { return true }
	}

	set := make(map[bladeapiv1alpha1.Event]struct{}, len(wanted))
	for _, e := range wanted {
		set[e] = struct{}{}
	}

	return func(msg events.Message) bool {
		eventType, ok := toProtoEventType(msg.Event)
		if !ok {
			return false
		}
		_, match := set[eventType]
		return match
	}
}
