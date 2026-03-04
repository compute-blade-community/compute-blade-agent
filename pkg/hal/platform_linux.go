//go:build linux && !tinygo

package hal

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"go.uber.org/zap"
)

const deviceTreeCompatiblePath = "/sys/firmware/devicetree/base/compatible"

// NewHal creates the appropriate HAL implementation based on the detected platform.
// It reads the device tree compatible string to determine whether the SoC is a
// BCM2711 (CM4/Pi 4) or BCM2712 (CM5/Pi 5).
func NewHal(ctx context.Context, opts ComputeBladeHalOpts) (ComputeBladeHal, error) {
	compatible, err := os.ReadFile(deviceTreeCompatiblePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read device tree compatible string: %w", err)
	}

	compatStr := string(compatible)
	log.FromContext(ctx).Info("detected platform", zap.String("compatible", strings.ReplaceAll(compatStr, "\x00", ", ")))

	switch {
	case strings.Contains(compatStr, "bcm2712"):
		return newBcm2712Hal(ctx, opts)
	case strings.Contains(compatStr, "bcm2711"):
		return newBcm2711Hal(ctx, opts)
	case strings.Contains(compatStr, "rockchip,rk3588"):
		return newRk3588Hal(ctx, opts)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", strings.ReplaceAll(compatStr, "\x00", ", "))
	}
}
