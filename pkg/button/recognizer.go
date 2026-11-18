// Package button turns raw button press / release transitions into gestures: a series of short presses, or a long
// press. It has no timers of its own; the caller feeds it transitions and calls Tick at NextDeadline, which keeps it
// deterministic and easy to test.
package button

import "time"

// Gesture is a recognised button gesture.
type Gesture struct {
	// Presses is the number of short presses in the series (0 for a long press).
	Presses int
	// Long is true for a long press.
	Long bool
	// Held is how long the button was held for a long press.
	Held time.Duration
}

// Config configures the recognizer.
type Config struct {
	// Window is the longest gap between releasing the button and pressing it again for both presses to count as one
	// series. A series ends when the window passes without another press.
	Window time.Duration
	// FireAt ends a series as soon as it reaches this many presses, without waiting for the window. Used for the
	// highest press count that is bound to an action, so e.g. an emergency action reacts immediately. 0 disables it.
	FireAt int
	// LongPress is how long the button has to be held for a long press. 0 disables long presses.
	LongPress time.Duration
	// HoldFeedback is how long the button has to be held before Holding reports true, so the caller can give feedback
	// (e.g. blink an LED) that a long press is under way. Only used if LongPress is enabled.
	HoldFeedback time.Duration
}

type state int

const (
	stateIdle state = iota
	statePressed
	stateReleased
)

// Recognizer is a button gesture state machine. It is not safe for concurrent use.
type Recognizer struct {
	cfg Config

	state       state
	presses     int
	pressedAt   time.Time
	releasedAt  time.Time
	longEmitted bool
}

// NewRecognizer creates a Recognizer.
func NewRecognizer(cfg Config) *Recognizer {
	return &Recognizer{cfg: cfg}
}

// Press feeds a press transition. It may complete a series that should already have timed out.
func (r *Recognizer) Press(now time.Time) []Gesture {
	var out []Gesture

	switch r.state {
	case statePressed:
		// a press while pressed: the release got lost, ignore
		return nil
	case stateReleased:
		if now.Sub(r.releasedAt) > r.cfg.Window {
			// Tick wasn't called in time: finish the previous series first
			out = append(out, r.finishSeries())
		}
	case stateIdle:
	}

	if r.state == stateIdle {
		r.presses = 0
	}
	r.presses++
	r.state = statePressed
	r.pressedAt = now
	r.longEmitted = false
	return out
}

// Release feeds a release transition.
func (r *Recognizer) Release(now time.Time) []Gesture {
	if r.state != statePressed {
		// a release without press: ignore
		return nil
	}

	// a long press may have been reached without Tick being called
	out := r.checkLongPress(now)

	if r.longEmitted {
		// the press was consumed by the long press, as was the series it ended
		r.reset()
		return out
	}

	r.state = stateReleased
	r.releasedAt = now

	if r.cfg.FireAt > 0 && r.presses >= r.cfg.FireAt {
		out = append(out, r.finishSeries())
	}
	return out
}

// Tick advances time: it emits a long press once the button was held long enough and ends a series once the window
// passed. Call it at NextDeadline.
func (r *Recognizer) Tick(now time.Time) []Gesture {
	switch r.state {
	case statePressed:
		return r.checkLongPress(now)
	case stateReleased:
		if now.Sub(r.releasedAt) > r.cfg.Window {
			return []Gesture{r.finishSeries()}
		}
	case stateIdle:
	}
	return nil
}

// NextDeadline returns when Tick should be called next, if anything is pending.
func (r *Recognizer) NextDeadline(now time.Time) (time.Time, bool) {
	switch r.state {
	case statePressed:
		if r.cfg.LongPress <= 0 || r.longEmitted {
			return time.Time{}, false
		}
		// wake up at the feedback threshold too, so the caller can switch the feedback on in time
		if feedbackAt := r.pressedAt.Add(r.cfg.HoldFeedback); r.cfg.HoldFeedback < r.cfg.LongPress && now.Before(feedbackAt) {
			return feedbackAt, true
		}
		return r.pressedAt.Add(r.cfg.LongPress), true
	case stateReleased:
		// strictly after the window, Tick compares with >
		return r.releasedAt.Add(r.cfg.Window + time.Millisecond), true
	default:
		return time.Time{}, false
	}
}

// Holding reports whether the button has been held past the feedback threshold and a long press is still to come.
func (r *Recognizer) Holding(now time.Time) bool {
	return r.state == statePressed &&
		r.cfg.LongPress > 0 &&
		!r.longEmitted &&
		now.Sub(r.pressedAt) >= r.cfg.HoldFeedback
}

func (r *Recognizer) checkLongPress(now time.Time) []Gesture {
	if r.cfg.LongPress <= 0 || r.longEmitted {
		return nil
	}
	held := now.Sub(r.pressedAt)
	if held < r.cfg.LongPress {
		return nil
	}
	r.longEmitted = true
	return []Gesture{{Long: true, Held: held}}
}

func (r *Recognizer) finishSeries() Gesture {
	g := Gesture{Presses: r.presses}
	r.reset()
	return g
}

func (r *Recognizer) reset() {
	r.state = stateIdle
	r.presses = 0
	r.longEmitted = false
}
