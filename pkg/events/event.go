package events

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
