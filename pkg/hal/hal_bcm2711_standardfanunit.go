//go:build linux && !tinygo

package hal

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"github.com/warthog618/gpiod"
	"github.com/warthog618/gpiod/device/rpi"
)

// standardFanRpmStaleAfter is how long the tachometer may stay silent before the fan is considered stopped.
// Even at 100 RPM the fan produces ~3 edges per second, so 2s without an edge means the fan isn't turning.
const standardFanRpmStaleAfter = 2 * time.Second

type standardFanUnitBcm2711 struct {
	GpioChip0           *gpiod.Chip
	SetFanSpeedPwmFunc  func(speed uint8) error
	DisableRpmReporting bool

	// Fan tachometer input
	fanEdgeLine *gpiod.Line

	// mu guards the tachometer state below, which is written from the gpiod event handler goroutine
	mu               sync.Mutex
	lastFanEdgeEvent *gpiod.LineEvent
	lastFanEdgeAt    time.Time
	fanRpm           float64
}

func (fu *standardFanUnitBcm2711) Kind() FanUnitKind {
	if fu.DisableRpmReporting {
		return FanUnitKindStandardNoRPM
	}
	return FanUnitKindStandard
}

func (fu *standardFanUnitBcm2711) Run(ctx context.Context) error {
	var err error
	fanUnit.WithLabelValues("standard").Set(1)

	// Register edge event handler for fan tachometer input
	if !fu.DisableRpmReporting {
		fu.fanEdgeLine, err = fu.GpioChip0.RequestLine(
			rpi.GPIO13,
			gpiod.WithEventHandler(fu.handleFanEdge),
			gpiod.WithFallingEdge,
			gpiod.WithPullUp,
		)
		if err != nil {
			return err
		}
		defer func(fanEdgeLine *gpiod.Line) {
			err := fanEdgeLine.Close()
			if err != nil {
				log.FromContext(ctx).WithError(err).Error("failed to close fanEdgeLine")
			}
		}(fu.fanEdgeLine)
	}

	<-ctx.Done()
	return ctx.Err()
}

// handleFanEdge handles an edge event on the fan tachometer input for the standard fan unite.
// Exponential moving average is used to smooth out the fan speed.
func (fu *standardFanUnitBcm2711) handleFanEdge(evt gpiod.LineEvent) {
	fu.mu.Lock()
	defer fu.mu.Unlock()

	now := time.Now()
	previous := fu.lastFanEdgeEvent
	stale := now.Sub(fu.lastFanEdgeAt) > standardFanRpmStaleAfter

	// Ensure we're always storing the last event
	fu.lastFanEdgeEvent = &evt
	fu.lastFanEdgeAt = now

	// First event (or first after the fan stopped), we cannot extrapolate the fan speed yet
	if previous == nil || stale {
		return
	}

	// Calculate time delta between events
	delta := evt.Timestamp - previous.Timestamp
	if delta <= 0 {
		return
	}
	ticksPerSecond := 1.0 / delta.Seconds()
	rpm := (ticksPerSecond * 60.0) / 2.0 // 2 ticks per revolution

	// Simple moving average to smooth out the fan speed
	fu.fanRpm = (rpm * 0.1) + (fu.fanRpm * 0.9)
	fanSpeed.Set(fu.fanRpm)
}

func (fu *standardFanUnitBcm2711) SetFanSpeedPercent(_ context.Context, percent uint8) error {
	return fu.SetFanSpeedPwmFunc(percent)
}

func (fu *standardFanUnitBcm2711) SetLed(_ context.Context, _ led.Color) error {
	return nil
}

func (fu *standardFanUnitBcm2711) FanSpeedRPM(_ context.Context) (float64, error) {
	fu.mu.Lock()
	defer fu.mu.Unlock()

	// No tachometer edges for a while: the fan stopped. The moving average would otherwise keep the last value forever.
	if time.Since(fu.lastFanEdgeAt) > standardFanRpmStaleAfter && fu.fanRpm != 0 {
		fu.fanRpm = 0
		fanSpeed.Set(0)
	}

	return fu.fanRpm, nil
}

func (fu *standardFanUnitBcm2711) WaitForButtonPress(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (fu *standardFanUnitBcm2711) AirFlowTemperature(_ context.Context) (float32, error) {
	return -1 * math.MaxFloat32, nil
}

func (fu *standardFanUnitBcm2711) Close() error {
	return nil
}
