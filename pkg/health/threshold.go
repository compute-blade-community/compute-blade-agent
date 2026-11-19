// Package health contains detectors that turn raw hardware readings into
// discrete health conditions (raised / cleared) for the agent to act on.
package health

// Transition describes how a detector's state changed after an observation.
type Transition int

const (
	// Unchanged means the condition kept its previous state.
	Unchanged Transition = iota
	// Raised means the condition just became active.
	Raised
	// Cleared means the condition just became inactive.
	Cleared
)

// ThresholdDetector raises a condition when a value reaches Threshold and
// clears it once the value drops below Threshold-Hysteresis. The hysteresis
// keeps the condition from flapping while the value hovers around the threshold.
type ThresholdDetector struct {
	Threshold  float64
	Hysteresis float64

	active bool
}

// Observe feeds a new value into the detector and reports the resulting transition.
func (d *ThresholdDetector) Observe(value float64) Transition {
	switch {
	case !d.active && value >= d.Threshold:
		d.active = true
		return Raised
	case d.active && value < d.Threshold-d.Hysteresis:
		d.active = false
		return Cleared
	default:
		return Unchanged
	}
}

// Active reports whether the condition is currently raised.
func (d *ThresholdDetector) Active() bool {
	return d.active
}

// Reset forces the detector back into the inactive state without reporting a transition.
func (d *ThresholdDetector) Reset() {
	d.active = false
}
