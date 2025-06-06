//go:build linux && !tinygo

package hal

import (
	"context"
	"math"

	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"go.uber.org/zap"

	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
	"github.com/warthog618/gpiod"
	"github.com/warthog618/gpiod/device/rpi"
)

type standardFanUnitBcm2711 struct {
	GpioChip0           *gpiod.Chip
	SetFanSpeedPwmFunc  func(speed uint8) error
	DisableRpmReporting bool

	// Fan tachometer input
	fanEdgeLine      *gpiod.Line
	lastFanEdgeEvent *gpiod.LineEvent
	fanRpm           float64
}

func (fu standardFanUnitBcm2711) Kind() FanUnitKind {
	if fu.DisableRpmReporting {
		return FanUnitKindStandardNoRPM
	}
	return FanUnitKindStandard
}

func (fu standardFanUnitBcm2711) Run(ctx context.Context) error {
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
				log.FromContext(ctx).Error("failed to close fanEdgeLine", zap.Error(err))
			}
		}(fu.fanEdgeLine)
	}

	<-ctx.Done()
	return ctx.Err()
}

// handleFanEdge handles an edge event on the fan tachometer input for the standard fan unite.
// Exponential moving average is used to smooth out the fan speed.
func (fu *standardFanUnitBcm2711) handleFanEdge(evt gpiod.LineEvent) {
	// Ensure we're always storing the last event
	defer func() {
		fu.lastFanEdgeEvent = &evt
	}()

	// First event, we cannot extrapolate the fan speed yet
	if fu.lastFanEdgeEvent == nil {
		return
	}

	// Calculate time delta between events
	delta := evt.Timestamp - fu.lastFanEdgeEvent.Timestamp
	ticksPerSecond := 1000.0 / float64(delta.Milliseconds())
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
