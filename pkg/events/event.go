package events

import "time"

type Event int

const (
	NoopEvent = iota
	IdentifyEvent
	IdentifyConfirmEvent
	CriticalEvent
	CriticalResetEvent
	ButtonPressEvent
	FanStallEvent
	FanStallClearEvent
	UndervoltageEvent
	UndervoltageClearEvent
	ThrottledEvent
	ThrottledClearEvent
	PowerLimitEvent
	PowerLimitClearEvent
	ButtonGestureEvent
)

// Health conditions. A condition is raised and cleared by a pair of events (see Event.ConditionChange).
const (
	ConditionFanStall     = "fan_stall"
	ConditionUndervoltage = "undervoltage"
	ConditionThrottled    = "throttled"
)

// Conditions lists all known health conditions.
var Conditions = []string{
	ConditionFanStall,
	ConditionUndervoltage,
	ConditionThrottled,
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
	case ButtonPressEvent:
		return "button_press"
	case ButtonGestureEvent:
		return "button_gesture"
	case FanStallEvent:
		return "fan_stall"
	case FanStallClearEvent:
		return "fan_stall_clear"
	case UndervoltageEvent:
		return "undervoltage"
	case UndervoltageClearEvent:
		return "undervoltage_clear"
	case ThrottledEvent:
		return "throttled"
	case ThrottledClearEvent:
		return "throttled_clear"
	case PowerLimitEvent:
		return "power_limit"
	case PowerLimitClearEvent:
		return "power_limit_clear"
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
	case UndervoltageEvent:
		return ConditionUndervoltage, true, true
	case UndervoltageClearEvent:
		return ConditionUndervoltage, false, true
	case ThrottledEvent:
		return ConditionThrottled, true, true
	case ThrottledClearEvent:
		return ConditionThrottled, false, true
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

// ThrottleDetails are attached to under-voltage and throttling events.
type ThrottleDetails struct {
	// Flags is the raw Raspberry Pi firmware throttle bitfield (see hal.ThrottleStatus)
	Flags uint32
}

// PowerLimitDetails are attached to power limit events.
type PowerLimitDetails struct {
	// Reasons why the CPU is limited, e.g. "undervoltage", "limited_power". Empty when the limit was lifted.
	Reasons []string
	// Governor is the cpufreq governor in use because of the limit, if the policy sets one
	Governor string
	// MaxFreqMHz is the CPU frequency cap, 0 if the policy sets none
	MaxFreqMHz uint
}

// ButtonDetails are attached to button press events.
type ButtonDetails struct {
	// Source is the button that was pressed: edge or fan_unit
	Source string
}

// GestureDetails are attached to button gesture events.
type GestureDetails struct {
	// Gesture is single, double, multi_press or long_press
	Gesture string
	// Presses is the number of presses of a single, double or multi_press gesture
	Presses int
	// Held is how long the button was held for a long_press
	Held time.Duration
	// Action is what the agent ran in response: a built-in action name, "exec", or empty for nothing
	Action string
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
