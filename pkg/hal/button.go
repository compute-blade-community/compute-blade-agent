//go:build !tinygo

package hal

import (
	"context"
	"sync"
	"time"
)

// ButtonSource identifies the button an event came from.
type ButtonSource uint8

const (
	// ButtonSourceEdge is the button on the edge of the blade.
	ButtonSourceEdge ButtonSource = iota
	// ButtonSourceFanUnit is the smart fan unit's button. The fan unit firmware decides which blade a press is meant
	// for (1x left, 2x right) and forwards it as a single press.
	ButtonSourceFanUnit
)

func (s ButtonSource) String() string {
	switch s {
	case ButtonSourceEdge:
		return "edge"
	case ButtonSourceFanUnit:
		return "fan_unit"
	default:
		return "unknown"
	}
}

// ButtonEvent is a button transition.
type ButtonEvent struct {
	Source ButtonSource
	// Pressed is true when the button went down, false when it was released. The fan unit button only reports presses.
	Pressed bool
	// Time is when the transition was detected.
	Time time.Time
}

const (
	// buttonEventBufferSize is how many button events are buffered for the agent
	buttonEventBufferSize = 32
	// buttonSettleTime is how long the button line has to be quiet before its level is read. Contact bounce produces a
	// burst of edges; reading the level once it settled yields exactly one transition per real press / release.
	buttonSettleTime = 20 * time.Millisecond
)

// buttonDebouncer debounces a button line: every edge (re)starts a settle timer, and once the line was quiet for the
// settle time its level is read. A transition is reported only if the level differs from the last reported one.
type buttonDebouncer struct {
	settle time.Duration
	// read returns whether the button is currently pressed
	read func() (bool, error)
	// emit is called for every debounced transition
	emit func(pressed bool, at time.Time)

	mu      sync.Mutex
	timer   *time.Timer
	pressed bool
}

// edge is called for every raw edge on the button line.
func (d *buttonDebouncer) edge() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil {
		d.timer.Stop()
	}
	d.timer = time.AfterFunc(d.settle, d.settled)
}

func (d *buttonDebouncer) settled() {
	pressed, err := d.read()
	if err != nil {
		return
	}

	d.mu.Lock()
	changed := pressed != d.pressed
	d.pressed = pressed
	d.mu.Unlock()

	if changed {
		d.emit(pressed, time.Now())
	}
}

func (d *buttonDebouncer) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
	}
}

// sendButtonEvent queues a button event without blocking; if the agent falls behind, the event is dropped.
func sendButtonEvent(ch chan ButtonEvent, ev ButtonEvent) {
	if ev.Pressed {
		edgeButtonEventCount.Inc()
	}
	select {
	case ch <- ev:
	default:
		droppedButtonEventCount.Inc()
	}
}

// forwardFanUnitButton reports presses of the fan unit button until ctx is done.
func forwardFanUnitButton(ctx context.Context, fanUnit FanUnit, ch chan ButtonEvent) error {
	for {
		if err := fanUnit.WaitForButtonPress(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		sendButtonEvent(ch, ButtonEvent{Source: ButtonSourceFanUnit, Pressed: true, Time: time.Now()})
	}
}
