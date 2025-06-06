package agent

import (
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/fancontroller"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
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
}

// ComputeBladeAgentInfo represents metadata information about a compute blade agent, including version, commit, and build time.
type ComputeBladeAgentInfo struct {
	Version   string
	Commit    string
	BuildTime time.Time
}
