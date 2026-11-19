//go:build !tinygo

package hal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"go.uber.org/zap"
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

// Sources of the throttle status, in order of preference
const (
	ThrottleSourceMailbox = "firmware mailbox (/dev/vcio)"
	ThrottleSourceSysfs   = "firmware get_throttled attribute"
	ThrottleSourceHwmon   = "rpi_volt hwmon (under-voltage only)"
)

// throttleReader reads the throttle status of a Raspberry Pi SoC.
type throttleReader struct {
	// source describes where the status comes from, one of the ThrottleSource* constants
	source string
	// allFlags is false if the source only reports under-voltage
	allFlags bool
	read     func() (ThrottleStatus, error)
}

// getThrottledGlobs are the places the raspberrypi firmware driver's get_throttled attribute lives in sysfs.
// The firmware node's location in the device tree differs between SoC generations, and newer kernels (6.x) dropped
// the attribute altogether.
var getThrottledGlobs = []string{
	"sys/devices/platform/*firmware/get_throttled",
	"sys/devices/platform/*/*firmware/get_throttled",
	"sys/devices/platform/*/*/*firmware/get_throttled",
}

// newThrottleReader locates the throttle status under root ("/" on a real system). It prefers the firmware mailbox
// (what vcgencmd uses), then the get_throttled sysfs attribute of older kernels, and falls back to the rpi_volt hwmon
// device, which only reports under-voltage.
// Returns ErrNotSupported if none of them are available.
func newThrottleReader(root string) (*throttleReader, error) {
	vcio := filepath.Join(root, "dev/vcio")
	if _, err := os.Stat(vcio); err == nil {
		read := func() (ThrottleStatus, error) { return readMailboxThrottled(vcio) }
		if _, err := read(); err == nil {
			return &throttleReader{source: ThrottleSourceMailbox, allFlags: true, read: read}, nil
		}
	}

	for _, pattern := range getThrottledGlobs {
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err == nil && len(matches) > 0 {
			path := matches[0]
			return &throttleReader{source: ThrottleSourceSysfs, allFlags: true, read: func() (ThrottleStatus, error) {
				raw, err := os.ReadFile(path)
				if err != nil {
					return 0, err
				}
				return ParseThrottleStatus(string(raw))
			}}, nil
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
			return &throttleReader{source: ThrottleSourceHwmon, read: func() (ThrottleStatus, error) {
				raw, err := os.ReadFile(alarm)
				if err != nil {
					return 0, err
				}
				if strings.TrimSpace(string(raw)) == "1" {
					return ThrottleUnderVoltage, nil
				}
				return 0, nil
			}}, nil
		}
	}

	return nil, ErrNotSupported
}

// Source describes where the throttle status comes from.
func (r *throttleReader) Source() string {
	return r.source
}

// AllFlags reports whether the source reports throttling, not just under-voltage.
func (r *throttleReader) AllFlags() bool {
	return r.allFlags
}

// Read returns the current throttle status.
func (r *throttleReader) Read() (ThrottleStatus, error) {
	status, err := r.read()
	if err != nil {
		return 0, err
	}
	recordThrottleMetrics(status, r.allFlags)
	return status, nil
}

// logThrottleSource reports which throttle status source a HAL found, warning about missing detection.
func logThrottleSource(ctx context.Context, reader *throttleReader, err error) {
	switch {
	case err != nil:
		log.FromContext(ctx).WithError(err).Warn("throttle status unavailable, under-voltage and throttling detection disabled")
	case !reader.AllFlags():
		log.FromContext(ctx).Warn("only under-voltage is reported by the firmware interface found, throttling detection disabled",
			zap.String("source", reader.Source()))
	default:
		log.FromContext(ctx).Info("reading throttle status", zap.String("source", reader.Source()))
	}
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
