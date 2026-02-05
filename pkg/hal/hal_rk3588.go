//go:build linux && !tinygo

package hal

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"go.uber.org/zap"
)

const (
	rk3588ThermalZonePath = "/sys/class/thermal/thermal_zone0/temp"
	rk3588PwmFanHwmonName = "pwmfan"
)

// rk3588 implements the ComputeBladeHal interface for the Rockchip RK3588 (Radxa CM5).
// Fan control uses the kernel's pwmfan driver via sysfs. GPIO-dependent features
// (button, stealth hardware, PoE detection, LEDs, tachometer) are stubbed until the
// Rockchip-to-B2B-connector pin mapping is determined.
type rk3588 struct {
	opts          ComputeBladeHalOpts
	pwmPath       string // e.g. /sys/class/hwmon/hwmon8/pwm1
	pwmEnablePath string // e.g. /sys/class/hwmon/hwmon8/pwm1_enable
	stealthMode   bool
}

// Compile-time interface check
var _ ComputeBladeHal = &rk3588{}

func newRk3588Hal(ctx context.Context, opts ComputeBladeHalOpts) (*rk3588, error) {
	logger := log.FromContext(ctx)

	pwmPath, err := findHwmonPwm(rk3588PwmFanHwmonName)
	if err != nil {
		return nil, fmt.Errorf("failed to find pwmfan hwmon device: %w", err)
	}

	enablePath := pwmPath + "_enable"

	// Set manual control mode (1 = manual PWM control)
	if err := os.WriteFile(enablePath, []byte("1"), 0644); err != nil {
		return nil, fmt.Errorf("failed to set pwm1_enable to manual mode: %w", err)
	}

	computeModule.WithLabelValues("radxa-cm5").Set(1)

	logger.Info("starting hal setup", zap.String("hal", "rk3588"))
	logger.Warn("GPIO pin mapping unknown for RK3588 B2B connector — button, stealth hardware, PoE detection, LEDs, and tachometer are stubbed")

	return &rk3588{
		opts:          opts,
		pwmPath:       pwmPath,
		pwmEnablePath: enablePath,
	}, nil
}

func (rk *rk3588) Run(ctx context.Context) error {
	fanUnit.WithLabelValues("sysfs").Set(1)
	<-ctx.Done()
	return ctx.Err()
}

func (rk *rk3588) Close() error {
	return nil
}

// SetFanSpeed sets the fan speed via sysfs pwm1 (0-100% mapped to 0-255).
func (rk *rk3588) SetFanSpeed(speed uint8) error {
	fanTargetPercent.Set(float64(speed))

	var pwmVal uint8
	if speed == 0 {
		pwmVal = 0
	} else if speed >= 100 {
		pwmVal = 255
	} else {
		pwmVal = uint8(float64(speed) * 255.0 / 100.0)
	}

	return os.WriteFile(rk.pwmPath, []byte(strconv.Itoa(int(pwmVal))), 0644)
}

// GetFanRPM returns 0 — no tachometer GPIO is mapped on the RK3588.
func (rk *rk3588) GetFanRPM() (float64, error) {
	return 0, nil
}

// GetTemperature returns the SoC temperature in degrees Celsius.
func (rk *rk3588) GetTemperature() (float64, error) {
	f, err := os.Open(rk3588ThermalZonePath)
	if err != nil {
		return -1, err
	}
	defer f.Close()

	raw, err := io.ReadAll(f)
	if err != nil {
		return -1, err
	}

	cpuTemp, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return -1, err
	}

	temp := float64(cpuTemp) / 1000.0
	socTemperature.Set(temp)

	return temp, nil
}

// SetStealthMode tracks stealth mode in software only (no GPIO mapped).
func (rk *rk3588) SetStealthMode(enabled bool) error {
	rk.stealthMode = enabled
	if enabled {
		stealthModeEnabled.Set(1)
	} else {
		stealthModeEnabled.Set(0)
	}
	return nil
}

func (rk *rk3588) StealthModeActive() bool {
	return rk.stealthMode
}

// SetLed is a no-op — WS281x LED GPIO pin mapping is unknown on RK3588.
func (rk *rk3588) SetLed(idx LedIndex, color led.Color) error {
	ledColorChangeEventCount.Inc()
	return nil
}

// GetPowerStatus returns PowerPoeOrUsbC as a safe default (no PoE detection GPIO mapped).
func (rk *rk3588) GetPowerStatus() (PowerStatus, error) {
	powerStatus.WithLabelValues(fmt.Sprint(PowerPoe802at)).Set(0)
	powerStatus.WithLabelValues(fmt.Sprint(PowerPoeOrUsbC)).Set(1)
	return PowerPoeOrUsbC, nil
}

// WaitForEdgeButtonPress blocks until context cancellation (no button GPIO mapped).
func (rk *rk3588) WaitForEdgeButtonPress(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

// findHwmonPwm scans /sys/class/hwmon/hwmon*/name for a device matching the given name
// and returns the path to its pwm1 file.
func findHwmonPwm(name string) (string, error) {
	matches, err := filepath.Glob("/sys/class/hwmon/hwmon*/name")
	if err != nil {
		return "", fmt.Errorf("failed to glob hwmon devices: %w", err)
	}

	for _, namePath := range matches {
		raw, err := os.ReadFile(namePath)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(raw)) == name {
			dir := filepath.Dir(namePath)
			pwmPath := filepath.Join(dir, "pwm1")
			if _, err := os.Stat(pwmPath); err != nil {
				return "", fmt.Errorf("found %s hwmon at %s but pwm1 does not exist: %w", name, dir, err)
			}
			return pwmPath, nil
		}
	}

	return "", fmt.Errorf("no hwmon device found with name %q", name)
}
