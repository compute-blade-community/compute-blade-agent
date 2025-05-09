//go:build darwin

package hal

import (
	"context"
	"time"

	"github.com/spechtlabs/go-otel-utils/otelzap"
	"github.com/uptime-industries/compute-blade-agent/pkg/hal/led"
	"go.uber.org/zap"
)

// fails if SimulatedHal does not implement ComputeBladeHal
var _ ComputeBladeHal = &SimulatedHal{}

// SimulatedHal implements a mock for the ComputeBladeHal interface
type SimulatedHal struct {
	logger *zap.Logger
}

func NewCm4Hal(_ context.Context, _ ComputeBladeHalOpts) (ComputeBladeHal, error) {
	logger := otelzap.L().Named("hal").Named("simulated-cm4")
	logger.Warn("Using simulated hal")

	computeModule.WithLabelValues("simulated").Set(1)
	fanUnit.WithLabelValues("simulated").Set(1)

	socTemperature.Set(42)

	return &SimulatedHal{
		logger: logger,
	}, nil
}

func (m *SimulatedHal) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (m *SimulatedHal) Close() error {
	return nil
}

func (m *SimulatedHal) SetFanSpeed(percent uint8) error {
	m.logger.Info("SetFanSpeed", zap.Uint8("percent", percent))
	fanSpeed.Set(2500 * (float64(percent) / 100))
	return nil
}

func (m *SimulatedHal) GetFanRPM() (float64, error) {
	return 1337, nil
}

func (m *SimulatedHal) SetStealthMode(enabled bool) error {
	if enabled {
		stealthModeEnabled.Set(1)
	} else {
		stealthModeEnabled.Set(0)
	}
	m.logger.Info("SetStealthMode", zap.Bool("enabled", enabled))
	return nil
}

func (m *SimulatedHal) GetPowerStatus() (PowerStatus, error) {
	m.logger.Info("GetPowerStatus")
	powerStatus.WithLabelValues("simulated").Set(1)
	return PowerPoe802at, nil
}

func (m *SimulatedHal) WaitForEdgeButtonPress(ctx context.Context) error {
	m.logger.Info("WaitForEdgeButtonPress")
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		edgeButtonEventCount.Inc()
		return nil
	}
}

func (m *SimulatedHal) SetLed(idx uint, color led.Color) error {
	ledColorChangeEventCount.Inc()
	m.logger.Info("SetLed", zap.Uint("idx", idx), zap.Any("color", color))
	return nil
}

func (m *SimulatedHal) GetTemperature() (float64, error) {
	m.logger.Info("GetTemperature")
	return 42, nil
}
