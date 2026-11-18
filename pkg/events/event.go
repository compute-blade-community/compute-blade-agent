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
)

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
	default:
		return "unknown"
	}
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
