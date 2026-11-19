package agent

import (
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/actions"
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

	// PowerPolicy limits the CPU when the blade is short on power
	PowerPolicy PowerPolicyConfig `mapstructure:"power_policy"`

	// Button configures what the edge button's gestures do
	Button ButtonConfig `mapstructure:"button"`

	// Discovery configures how the agent announces itself on the network
	Discovery DiscoveryConfig `mapstructure:"discovery"`
}

// DiscoveryConfig configures network discovery
type DiscoveryConfig struct {
	// MDNS announces the gRPC API via mDNS / DNS-SD (_compute-blade._tcp) so bladectl can find the blade.
	// Only used when the API listens on TCP.
	MDNS MDNSConfig `mapstructure:"mdns"`
}

// MDNSConfig configures the mDNS announcement
type MDNSConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// ButtonConfig binds actions to gestures of the edge button. Every gesture is published as a BUTTON_GESTURE event,
// whether or not it has an action, so other tools can react to it via WatchEvents.
type ButtonConfig struct {
	// GestureWindow is the longest gap between two presses for them to count as one gesture (e.g. a double press)
	GestureWindow time.Duration `mapstructure:"gesture_window"`
	// Single is a single short press. Defaults to identify-toggle; set `action: none` to disable.
	Single actions.Spec `mapstructure:"single"`
	// Double is two short presses
	Double actions.Spec `mapstructure:"double"`
	// LongPress is holding the button down
	LongPress LongPressConfig `mapstructure:"long_press"`
	// MultiPress is a series of Count short presses
	MultiPress MultiPressConfig `mapstructure:"multi_press"`
}

// LongPressConfig binds an action to holding the button
type LongPressConfig struct {
	// Hold is how long the button has to be held
	Hold         time.Duration `mapstructure:"hold"`
	actions.Spec `mapstructure:",squash"`
}

// MultiPressConfig binds an action to a series of short presses
type MultiPressConfig struct {
	// Count is the number of presses, at least 3 (1 and 2 are single and double)
	Count        int `mapstructure:"count"`
	actions.Spec `mapstructure:",squash"`
}

// PowerPolicyConfig defines CPU limits applied while the blade is short on power. If several apply at once, the
// lowest frequency cap wins and the under-voltage governor takes precedence.
type PowerPolicyConfig struct {
	// LimitedPower applies while the blade is not powered by 802.3at PoE+ (i.e. 802.3af PoE or USB-C)
	LimitedPower CPULimitsConfig `mapstructure:"limited_power"`
	// Undervoltage applies while the under-voltage condition is raised (requires health.undervoltage.enabled)
	Undervoltage CPULimitsConfig `mapstructure:"undervoltage"`
}

// CPULimitsConfig restricts the CPU. Empty / zero fields leave the respective setting untouched.
type CPULimitsConfig struct {
	// Governor is the cpufreq governor to switch to, e.g. powersave
	Governor string `mapstructure:"governor"`
	// MaxFreqMHz caps the CPU frequency
	MaxFreqMHz uint `mapstructure:"max_freq_mhz"`
}

// HealthConfig configures the health condition detectors
type HealthConfig struct {
	// FanStall configures detection of a fan that is commanded to spin but doesn't
	FanStall health.FanStallConfig `mapstructure:"fan_stall"`
	// Undervoltage configures detection of a too low supply voltage (Raspberry Pi firmware flag)
	Undervoltage health.FlagConfig `mapstructure:"undervoltage"`
	// Throttling configures detection of CPU throttling: frequency capped, throttled or soft temperature limit
	// (Raspberry Pi firmware flags)
	Throttling health.FlagConfig `mapstructure:"throttling"`
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
