package health

import "time"

// FlagConfig configures detection of a condition reported as an on/off flag (e.g. under-voltage).
type FlagConfig struct {
	// Enabled turns detection on or off.
	Enabled bool `mapstructure:"enabled"`
	// ClearAfter is how long the flag has to stay off before the condition is cleared. Short dips are common
	// (e.g. under-voltage under load spikes); without it the LED indicator would flicker.
	ClearAfter time.Duration `mapstructure:"clear_after"`
}

// FlagDetector raises a condition as soon as a flag is observed set and clears it once the flag stayed unset for
// ClearAfter.
type FlagDetector struct {
	ClearAfter time.Duration

	active   bool
	lastSeen time.Time
}

// Observe feeds the current flag value into the detector.
func (d *FlagDetector) Observe(now time.Time, set bool) Transition {
	if set {
		d.lastSeen = now
		if !d.active {
			d.active = true
			return Raised
		}
		return Unchanged
	}

	if d.active && now.Sub(d.lastSeen) >= d.ClearAfter {
		d.active = false
		return Cleared
	}
	return Unchanged
}

// Active reports whether the condition is currently raised.
func (d *FlagDetector) Active() bool {
	return d.active
}
