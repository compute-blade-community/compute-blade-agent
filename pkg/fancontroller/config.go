package fancontroller

type FanOverrideOpts struct {
	Percent uint8 `mapstructure:"speed"`
}

type Step struct {
	// Temperature is the temperature to react to
	Temperature float64 `mapstructure:"temperature"`
	// Percent is the fan speed in percent
	Percent uint8 `mapstructure:"percent"`
}

// Config configures a fan controller for the computeblade
type Config struct {
	// Steps defines the temperature/speed steps for the fan controller
	Steps []Step `mapstructure:"steps"`
}
