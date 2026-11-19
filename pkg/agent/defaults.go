package agent

import (
	"sort"

	"github.com/spf13/viper"
)

// SetDefaults registers the defaults of settings that may be missing from a config file, e.g. one written for an
// older agent version.
func SetDefaults(v *viper.Viper) {
	setColorDefault(v, "idle_led_color", 0, 16, 0)
	setColorDefault(v, "identify_led_color", 16, 0, 16)
	setColorDefault(v, "critical_led_color", 64, 0, 0)
}

func setColorDefault(v *viper.Viper, key string, red, green, blue uint8) {
	v.SetDefault(key+".red", red)
	v.SetDefault(key+".green", green)
	v.SetDefault(key+".blue", blue)
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
