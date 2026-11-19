package health

import "time"

// FanStallConfig configures fan stall detection.
type FanStallConfig struct {
	// Enabled turns fan stall detection on or off.
	Enabled bool `mapstructure:"enabled"`
	// MinPercent is the lowest commanded fan speed at which a stall is judged. Many fans legitimately stop at very
	// low duty cycles, so readings taken below this speed are ignored.
	MinPercent uint8 `mapstructure:"min_percent"`
	// MinRPM is the speed below which the fan counts as not spinning.
	MinRPM float64 `mapstructure:"min_rpm"`
	// GracePeriod is how long the fan has to stay below MinRPM (while commanded to at least MinPercent) before a stall
	// is raised. It also covers spin-up after the fan was commanded to start.
	GracePeriod time.Duration `mapstructure:"grace_period"`
}

// FanStallDetector raises a stall when the fan is commanded to spin but its tachometer reports (almost) no rotation
// for longer than the grace period. It clears as soon as the fan spins again.
type FanStallDetector struct {
	Config FanStallConfig

	suspectSince time.Time
	active       bool
}

// Observe feeds a reading into the detector: the commanded fan speed in percent and the measured RPM.
func (d *FanStallDetector) Observe(now time.Time, targetPercent uint8, rpm float64) Transition {
	// The fan spins: no stall, whatever the commanded speed.
	if rpm >= d.Config.MinRPM {
		d.suspectSince = time.Time{}
		if d.active {
			d.active = false
			return Cleared
		}
		return Unchanged
	}

	// The fan doesn't spin, but it may be supposed to stand still at this speed. We can't tell, so keep the current
	// state: a stall is only cleared once the fan is seen spinning again.
	if targetPercent < d.Config.MinPercent {
		d.suspectSince = time.Time{}
		return Unchanged
	}

	if d.suspectSince.IsZero() {
		d.suspectSince = now
	}

	if !d.active && now.Sub(d.suspectSince) >= d.Config.GracePeriod {
		d.active = true
		return Raised
	}

	return Unchanged
}

// Active reports whether a fan stall is currently raised.
func (d *FanStallDetector) Active() bool {
	return d.active
}
