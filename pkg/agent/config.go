package agent

import (
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/fancontroller"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
	"github.com/compute-blade-community/compute-blade-agent/pkg/health"
)

type LogConfiguration struct {
	Mode string `mapstructure:"mode"`
}

type ApiConfig struct {
	Metrics           string `mapstructure:"metrics"`
	Grpc              string `mapstructure:"grpc"`
	GrpcAuthenticated bool   `mapstructure:"authenticated"`
	GrpcListenMode    string `mapstructure:"mode"`
}

type ComputeBladeAgentConfig struct {
	// Log is the logging configuration
	Log LogConfiguration `mapstructure:"log"`

	// Listen is the listen configuration for the server
	Listen ApiConfig `mapstructure:"listen"`

	// Hal is the hardware abstraction layer configuration
	Hal hal.Config `mapstructure:"hal"`

	// IdleLedColor is the color of the edge LED when the blade is idle mode
	IdleLedColor led.Color `mapstructure:"idle_led_color"`

	// IdentifyLedColor is the color of the edge LED when the blade is in identify mode
	IdentifyLedColor led.Color `mapstructure:"identify_led_color"`

	// CriticalLedColor is the color of the top(!) LED when the blade is in critical mode.
	// In the circumstance when >1 blades are in critical mode, the identify function can be used to find the right blade
	CriticalLedColor led.Color `mapstructure:"critical_led_color"`

	// StealthModeEnabled indicates whether stealth mode is enabled
	StealthModeEnabled bool `mapstructure:"stealth_mode"`

	// Critical temperature of the compute blade (used to trigger critical mode)
	CriticalTemperatureThreshold uint `mapstructure:"critical_temperature_threshold"`

	// FanSpeed allows to set a fixed fan speed (in percent)
	FanSpeed *fancontroller.FanOverrideOpts `mapstructure:"fan_speed"`

	// FanControllerConfig is the configuration of the fan controller
	FanControllerConfig fancontroller.Config `mapstructure:"fan_controller"`

	ComputeBladeHalOpts hal.ComputeBladeHalOpts `mapstructure:"hal"`

	// Health configures the detection of health conditions (e.g. a stalled fan)
	Health HealthConfig `mapstructure:"health"`

	// Indicators configures how health conditions are shown on the LEDs, keyed by condition name (e.g. fan_stall)
	Indicators map[string]IndicatorConfig `mapstructure:"indicators"`
}

// HealthConfig configures the health condition detectors
type HealthConfig struct {
	// FanStall configures detection of a fan that is commanded to spin but doesn't
	FanStall health.FanStallConfig `mapstructure:"fan_stall"`
}

// IndicatorConfig defines how a health condition is shown on one of the LEDs
type IndicatorConfig struct {
	// Led is the LED to show the condition on: top, edge or none (don't show it)
	Led string `mapstructure:"led"`
	// Color of the indicator
	Color led.Color `mapstructure:"color"`
	// Pattern is one of static, slow-blink, fast-blink or burst
	Pattern string `mapstructure:"pattern"`
	// Priority decides which indicator is shown when several conditions are active on the same LED (higher wins).
	// Identify and critical mode always take precedence over indicators.
	Priority int `mapstructure:"priority"`
}

// LED names used in IndicatorConfig.Led
const (
	IndicatorLedTop  = "top"
	IndicatorLedEdge = "edge"
	IndicatorLedNone = "none"
)

// ComputeBladeAgentInfo represents metadata information about a compute blade agent, including version, commit, and build time.
type ComputeBladeAgentInfo struct {
	Version   string
	Commit    string
	BuildTime time.Time
}
