package agent

import (
	"sort"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
	"github.com/spf13/viper"
)

// SetDefaults registers default values for configuration keys that may be missing from existing config files.
// Package managers don't overwrite a modified config file on upgrade, so features added later must work without
// their keys being present. Values from the config file and BLADE_* environment variables take precedence.
func SetDefaults(v *viper.Viper) {
	setColorDefault(v, "idle_led_color", 0, 16, 0)
	setColorDefault(v, "identify_led_color", 16, 0, 16)
	setColorDefault(v, "critical_led_color", 64, 0, 0)

	// Fan stall detection
	v.SetDefault("health.fan_stall.enabled", true)
	v.SetDefault("health.fan_stall.min_percent", 20)
	v.SetDefault("health.fan_stall.min_rpm", 100)
	v.SetDefault("health.fan_stall.grace_period", 15*time.Second)

	// Fan stall indicator: fast blinking orange on the top LED
	setIndicatorDefaults(v, events.ConditionFanStall, IndicatorLedTop, "fast-blink", 64, 24, 0, 30)
}

func setColorDefault(v *viper.Viper, key string, red, green, blue uint8) {
	v.SetDefault(key+".red", red)
	v.SetDefault(key+".green", green)
	v.SetDefault(key+".blue", blue)
}

func setIndicatorDefaults(v *viper.Viper, condition string, led string, pattern string, red, green, blue uint8, priority int) {
	prefix := "indicators." + condition + "."
	v.SetDefault(prefix+"led", led)
	v.SetDefault(prefix+"pattern", pattern)
	setColorDefault(v, prefix+"color", red, green, blue)
	v.SetDefault(prefix+"priority", priority)
}

// legacyKeys maps configuration keys that were renamed to their current name
var legacyKeys = map[string]string{
	"criticalLedColor": "critical_led_color",
}

// MigrateLegacyKeys makes values set under a renamed key available under its current name, unless the config file
// sets the current name as well. Call it after reading the config file. It returns the legacy keys found in the
// config file, so they can be reported as deprecated.
func MigrateLegacyKeys(v *viper.Viper) []string {
	var found []string
	for legacy, current := range legacyKeys {
		if !v.InConfig(legacy) {
			continue
		}
		found = append(found, legacy)
		if !v.InConfig(current) {
			v.Set(current, v.Get(legacy))
		}
	}
	sort.Strings(found)
	return found
}
