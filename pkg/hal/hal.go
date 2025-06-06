package hal

import (
	"context"

	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
)

type FanUnitKind uint8
type ComputeModule uint8
type PowerStatus uint8

func (p PowerStatus) String() string {
	switch p {
	case PowerPoe802at:
		return "poe+"
	case PowerPoeOrUsbC:
		return "poeOrUsbC"
	default:
		return "undefined"
	}
}

const (
	FanUnitKindStandard = iota
	FanUnitKindStandardNoRPM
	FanUnitKindSmart
)

const (
	PowerPoeOrUsbC = iota
	PowerPoe802at
)

type LedIndex uint8

const (
	LedTop LedIndex = iota
	LedEdge
)

type ComputeBladeHalOpts struct {
	RpmReportingStandardFanUnit bool `mapstructure:"rpm_reporting_standard_fan_unit"`
}

// ComputeBladeHal abstracts hardware details of the Compute Blade and provides a simple interface
type ComputeBladeHal interface {
	// Run starts background tasks and returns when the context is cancelled or an error occurs
	Run(ctx context.Context) error
	// Close closes the ComputeBladeHal
	Close() error
	// SetFanSpeed sets the fan speed in percent
	SetFanSpeed(speed uint8) error
	// GetFanRPM returns the current fan speed in percent (based on moving average)
	GetFanRPM() (float64, error)
	// SetStealthMode enables/disables stealth mode of the blade (turning on/off the LEDs)
	SetStealthMode(enabled bool) error
	// StealthModeActive returns if stealth mode of the blade is currently active
	StealthModeActive() bool
	// SetLed sets the color of the LEDs
	SetLed(idx LedIndex, color led.Color) error
	// GetPowerStatus returns the current power status of the blade
	GetPowerStatus() (PowerStatus, error)
	// GetTemperature returns the current temperature of the SoC in °C
	GetTemperature() (float64, error)
	// WaitForEdgeButtonPress returns a channel emitting edge button press events
	WaitForEdgeButtonPress(ctx context.Context) error
}

// FanUnit abstracts the fan unit
type FanUnit interface {
	// Kind returns the kind of the fan FanUnit
	Kind() FanUnitKind

	// Run the client with event loop
	Run(context.Context) error

	// SetFanSpeedPercent sets the fan speed in percent.
	SetFanSpeedPercent(context.Context, uint8) error

	// SetLed sets the LED color. Noop if the LED is not available.
	SetLed(context.Context, led.Color) error

	// FanSpeedRPM returns the current fan speed in rotations per minute.
	FanSpeedRPM(context.Context) (float64, error)

	// WaitForButtonPress blocks until the button is pressed. Noop if the button is not available.
	WaitForButtonPress(context.Context) error

	// AirFlowTemperature returns the temperature of the air flow. Noop if the sensor is not available.
	AirFlowTemperature(context.Context) (float32, error)

	Close() error
}
