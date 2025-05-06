package ledengine

import (
	"context"
	"errors"
	"time"

	"github.com/uptime-industries/compute-blade-agent/pkg/hal"
	"github.com/uptime-industries/compute-blade-agent/pkg/hal/led"
	"github.com/uptime-industries/compute-blade-agent/pkg/util"
)

// LedEngine is the interface for controlling effects on the computeblade RGB LEDs
type LedEngine interface {
	// SetPattern sets the blink pattern
	SetPattern(pattern BlinkPattern) error
	// Run runs the LED Engine
	Run(ctx context.Context) error
}

// ledEngineImpl is the implementation of the LedEngine interface
type ledEngineImpl struct {
	ledIdx  uint
	restart chan struct{}
	pattern BlinkPattern
	hal     hal.ComputeBladeHal
	clock   util.Clock
}

type BlinkPattern struct {
	// BaseColor is the color is the color shown when the pattern starts (-> before the first blink)
	BaseColor led.Color
	// ActiveColor is the color shown when the pattern is active (-> during the blink)
	ActiveColor led.Color
	// Delays is a list of delays between changes -> (base) -> 0.5s(active) -> 1s(base) -> 0.5s (active) -> 1s (base)
	Delays []time.Duration
}

func mapBrightnessUint8(brightness float64) uint8 {
	return uint8(255.0 * brightness)
}

func LedColorPurple(brightness float64) led.Color {
	return led.Color{
		Red:   mapBrightnessUint8(brightness),
		Green: 0,
		Blue:  mapBrightnessUint8(brightness),
	}
}

func LedColorRed(brightness float64) led.Color {
	return led.Color{
		Red:   mapBrightnessUint8(brightness),
		Green: 0,
		Blue:  0,
	}
}

func LedColorGreen(brightness float64) led.Color {
	return led.Color{
		Red:   0,
		Green: mapBrightnessUint8(brightness),
		Blue:  0,
	}
}

// NewStaticPattern creates a new static pattern (no color changes)
func NewStaticPattern(color led.Color) BlinkPattern {
	return BlinkPattern{
		BaseColor:   color,
		ActiveColor: color,
		Delays:      []time.Duration{time.Hour}, // 1h delay, we don't care as there are no color changes involved
	}
}

// NewBurstPattern creates a new burst pattern (~1s cycle duration with 3x 50ms bursts)
func NewBurstPattern(baseColor led.Color, burstColor led.Color) BlinkPattern {
	return BlinkPattern{
		BaseColor:   baseColor,
		ActiveColor: burstColor,
		Delays: []time.Duration{
			500 * time.Millisecond, // 750ms off
			100 * time.Millisecond, // 100ms on
			100 * time.Millisecond, // 100ms off
			100 * time.Millisecond, // 100ms on
			100 * time.Millisecond, // 100ms off
			100 * time.Millisecond, // 100ms on
		},
	}
}

// NewSlowBlinkPattern creates a new slow blink pattern (~2s cycle duration with 1s off and 1s on)
func NewSlowBlinkPattern(baseColor led.Color, activeColor led.Color) BlinkPattern {
	return BlinkPattern{
		BaseColor:   baseColor,
		ActiveColor: activeColor,
		Delays: []time.Duration{
			time.Second, // 1s off
			time.Second, // 1s on
		},
	}
}

func NewLedEngine(opts Options) LedEngine {
	clock := opts.Clock
	if clock == nil {
		clock = util.RealClock{}
	}
	return &ledEngineImpl{
		ledIdx:  opts.LedIdx,
		hal:     opts.Hal,
		restart: make(chan struct{}),           // restart channel controls cancellation of any pattern
		pattern: NewStaticPattern(led.Color{}), // Turn off LEDs by default
		clock:   clock,
	}
}

func (b *ledEngineImpl) SetPattern(pattern BlinkPattern) error {
	if len(pattern.Delays) == 0 {
		return errors.New("pattern must have at least one delay")
	}

	b.pattern = pattern
	close(b.restart)
	b.restart = make(chan struct{})

	return nil
}

// Run runs the blink engine
func (b *ledEngineImpl) Run(ctx context.Context) error {
	// Iterate forever unless context is done
	for {
		// Set the base color
		if err := b.hal.SetLed(b.ledIdx, b.pattern.BaseColor); err != nil {
			return err
		}
		//  Iterate through pattern delays
	PatternLoop:
		for idx, delay := range b.pattern.Delays {
			select {
			// Whenever the pattern is restarted, break the loop and start over
			case <-b.restart:
				break PatternLoop
			// Whenever the context is done, return
			case <-ctx.Done():
				return ctx.Err()
			// Whenever the delay is over, change the color
			case <-b.clock.After(delay):
				color := b.pattern.BaseColor
				if idx%2 == 0 {
					color = b.pattern.ActiveColor
				}
				if err := b.hal.SetLed(b.ledIdx, color); err != nil {
					return err
				}
			}
		}
	}
}
