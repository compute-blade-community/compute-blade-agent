//go:build !tinygo

package hal

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrNotSupported is returned by HAL functions the platform doesn't support.
var ErrNotSupported = errors.New("not supported on this platform")

// ThrottleStatus is the Raspberry Pi firmware's throttle bitfield, as reported by `vcgencmd get_throttled`.
// The low bits describe the current state, the high bits whether the state occurred since boot.
type ThrottleStatus uint32

const (
	ThrottleUnderVoltage  ThrottleStatus = 1 << 0
	ThrottleArmFreqCapped ThrottleStatus = 1 << 1
	ThrottleThrottled     ThrottleStatus = 1 << 2
	ThrottleSoftTempLimit ThrottleStatus = 1 << 3

	ThrottleUnderVoltageOccurred  ThrottleStatus = 1 << 16
	ThrottleArmFreqCappedOccurred ThrottleStatus = 1 << 17
	ThrottleThrottledOccurred     ThrottleStatus = 1 << 18
	ThrottleSoftTempLimitOccurred ThrottleStatus = 1 << 19
)

// throttleFlags names the current-state bits and their "occurred since boot" counterparts, e.g. for metric labels.
var throttleFlags = []struct {
	name     string
	now      ThrottleStatus
	occurred ThrottleStatus
}{
	{"under_voltage", ThrottleUnderVoltage, ThrottleUnderVoltageOccurred},
	{"arm_freq_capped", ThrottleArmFreqCapped, ThrottleArmFreqCappedOccurred},
	{"throttled", ThrottleThrottled, ThrottleThrottledOccurred},
	{"soft_temp_limit", ThrottleSoftTempLimit, ThrottleSoftTempLimitOccurred},
}

// UnderVoltage reports whether the supply voltage is currently too low.
func (t ThrottleStatus) UnderVoltage() bool {
	return t&ThrottleUnderVoltage != 0
}

// Throttling reports whether the CPU is currently slowed down: frequency capped, throttled or at the soft temperature
// limit.
func (t ThrottleStatus) Throttling() bool {
	return t&(ThrottleArmFreqCapped|ThrottleThrottled|ThrottleSoftTempLimit) != 0
}

// Has reports whether all given bits are set.
func (t ThrottleStatus) Has(bits ThrottleStatus) bool {
	return t&bits == bits
}

// ParseThrottleStatus parses the hexadecimal value of the firmware's get_throttled attribute, with or without 0x prefix.
func ParseThrottleStatus(raw string) (ThrottleStatus, error) {
	value := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "0x")
	parsed, err := strconv.ParseUint(value, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid throttle status %q: %w", raw, err)
	}
	return ThrottleStatus(parsed), nil
}

// throttleReader reads the throttle status of a Raspberry Pi SoC from sysfs.
type throttleReader struct {
	// getThrottledPath is the firmware's get_throttled attribute; preferred, it reports all flags
	getThrottledPath string
	// undervoltageAlarmPath is the rpi_volt hwmon alarm; fallback that only reports under-voltage
	undervoltageAlarmPath string
}

// getThrottledGlobs are the places the raspberrypi firmware driver's get_throttled attribute lives in sysfs.
// The firmware node's location in the device tree differs between SoC generations.
var getThrottledGlobs = []string{
	"sys/devices/platform/*firmware/get_throttled",
	"sys/devices/platform/*/*firmware/get_throttled",
	"sys/devices/platform/*/*/*firmware/get_throttled",
}

// newThrottleReader locates the throttle status in the sysfs tree under root ("/" on a real system).
// Returns ErrNotSupported if neither the firmware attribute nor the rpi_volt hwmon device exist.
func newThrottleReader(root string) (*throttleReader, error) {
	for _, pattern := range getThrottledGlobs {
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err == nil && len(matches) > 0 {
			return &throttleReader{getThrottledPath: matches[0]}, nil
		}
	}

	hwmonNames, _ := filepath.Glob(filepath.Join(root, "sys/class/hwmon/hwmon*/name"))
	for _, namePath := range hwmonNames {
		raw, err := os.ReadFile(namePath)
		if err != nil || strings.TrimSpace(string(raw)) != "rpi_volt" {
			continue
		}
		alarm := filepath.Join(filepath.Dir(namePath), "in0_lcrit_alarm")
		if _, err := os.Stat(alarm); err == nil {
			return &throttleReader{undervoltageAlarmPath: alarm}, nil
		}
	}

	return nil, ErrNotSupported
}

// Read returns the current throttle status.
func (r *throttleReader) Read() (ThrottleStatus, error) {
	if r.getThrottledPath != "" {
		raw, err := os.ReadFile(r.getThrottledPath)
		if err != nil {
			return 0, err
		}
		status, err := ParseThrottleStatus(string(raw))
		if err != nil {
			return 0, err
		}
		recordThrottleMetrics(status, true)
		return status, nil
	}

	raw, err := os.ReadFile(r.undervoltageAlarmPath)
	if err != nil {
		return 0, err
	}
	var status ThrottleStatus
	if strings.TrimSpace(string(raw)) == "1" {
		status = ThrottleUnderVoltage
	}
	recordThrottleMetrics(status, false)
	return status, nil
}

// recordThrottleMetrics exports the throttle flags. With the hwmon fallback only under-voltage is known.
func recordThrottleMetrics(status ThrottleStatus, allFlags bool) {
	for _, flag := range throttleFlags {
		if !allFlags && flag.now != ThrottleUnderVoltage {
			continue
		}
		throttleActive.WithLabelValues(flag.name).Set(boolToFloat(status.Has(flag.now)))
		if allFlags {
			throttleOccurred.WithLabelValues(flag.name).Set(boolToFloat(status.Has(flag.occurred)))
		}
	}
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
