//go:build !tinygo

package hal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseThrottleStatus(t *testing.T) {
	t.Parallel()

	for raw, want := range map[string]ThrottleStatus{
		"0":         0,
		"0x0\n":     0,
		"50005\n":   ThrottleUnderVoltage | ThrottleThrottled | ThrottleUnderVoltageOccurred | ThrottleThrottledOccurred,
		"0x50005":   ThrottleUnderVoltage | ThrottleThrottled | ThrottleUnderVoltageOccurred | ThrottleThrottledOccurred,
		"0X8":       ThrottleSoftTempLimit,
		"  80000  ": ThrottleSoftTempLimitOccurred,
	} {
		got, err := ParseThrottleStatus(raw)
		require.NoError(t, err, raw)
		assert.Equal(t, want, got, raw)
	}

	_, err := ParseThrottleStatus("not-hex")
	assert.Error(t, err)
}

func TestThrottleStatus_Predicates(t *testing.T) {
	t.Parallel()

	assert.True(t, ThrottleUnderVoltage.UnderVoltage())
	assert.False(t, ThrottleUnderVoltageOccurred.UnderVoltage())

	assert.True(t, ThrottleArmFreqCapped.Throttling())
	assert.True(t, ThrottleThrottled.Throttling())
	assert.True(t, ThrottleSoftTempLimit.Throttling())
	assert.False(t, ThrottleUnderVoltage.Throttling())
	assert.False(t, ThrottleThrottledOccurred.Throttling())
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func TestThrottleReader_FirmwareAttribute(t *testing.T) {
	t.Parallel()

	for _, location := range []string{
		"sys/devices/platform/soc/soc:firmware/get_throttled",                       // CM4
		"sys/devices/platform/axi/axi:firmware/get_throttled",                       // nested firmware node
		"sys/devices/platform/soc@107c000000/soc@107c000000:firmware/get_throttled", // CM5
	} {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, location), "50005\n")

		reader, err := newThrottleReader(root)
		require.NoError(t, err, location)

		status, err := reader.Read()
		require.NoError(t, err, location)
		assert.True(t, status.UnderVoltage(), location)
		assert.True(t, status.Throttling(), location)
	}
}

func TestThrottleReader_HwmonFallback(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "sys/class/hwmon/hwmon0/name"), "cpu_thermal\n")
	writeFile(t, filepath.Join(root, "sys/class/hwmon/hwmon1/name"), "rpi_volt\n")
	alarm := filepath.Join(root, "sys/class/hwmon/hwmon1/in0_lcrit_alarm")
	writeFile(t, alarm, "1\n")

	reader, err := newThrottleReader(root)
	require.NoError(t, err)

	status, err := reader.Read()
	require.NoError(t, err)
	assert.Equal(t, ThrottleUnderVoltage, status)

	writeFile(t, alarm, "0\n")
	status, err = reader.Read()
	require.NoError(t, err)
	assert.Equal(t, ThrottleStatus(0), status)
}

func TestThrottleReader_NotSupported(t *testing.T) {
	t.Parallel()

	_, err := newThrottleReader(t.TempDir())
	assert.ErrorIs(t, err, ErrNotSupported)
}
