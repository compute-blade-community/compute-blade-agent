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

// Typed, so fmt and the power_status metric labels use String() (poe+, poeOrUsbC) instead of the bare number
const (
	PowerPoeOrUsbC PowerStatus = iota
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
	// GetFanRPM returns the current fan speed in RPM (based on moving average)
	GetFanRPM() (float64, error)
	// FanRPMSupported reports whether GetFanRPM reflects the real fan speed. It is false when the fan unit has no
	// tachometer or RPM reporting was disabled; fan stall detection is skipped in that case.
	FanRPMSupported() bool
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
	// GetThrottleStatus returns the SoC's under-voltage and throttling flags.
	// Returns ErrNotSupported if the platform doesn't report them.
	GetThrottleStatus() (ThrottleStatus, error)
	// ButtonEvents returns a channel receiving button transitions (edge button presses / releases and fan unit button
	// presses). Events are dropped if the receiver falls behind.
	ButtonEvents() <-chan ButtonEvent
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
