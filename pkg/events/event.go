package events

import "time"

type Event int

const (
	NoopEvent = iota
	IdentifyEvent
	IdentifyConfirmEvent
	CriticalEvent
	CriticalResetEvent
	EdgeButtonEvent
	FanStallEvent
	FanStallClearEvent
)

// Health conditions. A condition is raised and cleared by a pair of events (see Event.ConditionChange).
const (
	ConditionFanStall = "fan_stall"
)

// Conditions lists all known health conditions.
var Conditions = []string{
	ConditionFanStall,
}

func (e Event) String() string {
	switch e {
	case NoopEvent:
		return "noop"
	case IdentifyEvent:
		return "identify"
	case IdentifyConfirmEvent:
		return "identify_confirm"
	case CriticalEvent:
		return "critical"
	case CriticalResetEvent:
		return "critical_reset"
	case EdgeButtonEvent:
		return "edge_button"
	case FanStallEvent:
		return "fan_stall"
	case FanStallClearEvent:
		return "fan_stall_clear"
	default:
		return "unknown"
	}
}

// ConditionChange reports whether the event raises (active=true) or clears (active=false) a health condition.
func (e Event) ConditionChange() (condition string, active bool, ok bool) {
	switch e {
	case FanStallEvent:
		return ConditionFanStall, true, true
	case FanStallClearEvent:
		return ConditionFanStall, false, true
	default:
		return "", false, false
	}
}

// FanDetails are attached to fan stall events.
type FanDetails struct {
	// TargetPercent is the fan speed the agent commanded
	TargetPercent uint8
	// RPM is the fan speed measured by the tachometer
	RPM float64
}

// Message is an Event together with the time it occurred and optional, event-specific details.
// Messages flow through the agent's event handler and are published to WatchEvents subscribers.
type Message struct {
	Event     Event
	Timestamp time.Time
	// Details carries event-specific information (e.g. which button gesture was recognised). May be nil.
	Details any
}

// NewMessage creates a Message for the given event, timestamped now.
func NewMessage(event Event, details any) Message {
	return Message{
		Event:     event,
		Timestamp: time.Now(),
		Details:   details,
	}
}
