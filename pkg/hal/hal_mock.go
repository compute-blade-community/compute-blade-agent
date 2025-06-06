package hal

import (
	"context"

	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
	"github.com/stretchr/testify/mock"
)

// fails if ComputeBladeHalMock does not implement ComputeBladeHal
var _ ComputeBladeHal = &ComputeBladeHalMock{}

// ComputeBladeHalMock implements a mock for the ComputeBladeHal interface
type ComputeBladeHalMock struct {
	mock.Mock
}

func (m *ComputeBladeHalMock) Run(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *ComputeBladeHalMock) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *ComputeBladeHalMock) SetFanSpeed(percent uint8) error {
	args := m.Called(percent)
	return args.Error(0)
}

func (m *ComputeBladeHalMock) GetFanRPM() (float64, error) {
	args := m.Called()
	return args.Get(0).(float64), args.Error(1)
}

func (m *ComputeBladeHalMock) SetStealthMode(enabled bool) error {
	args := m.Called(enabled)
	return args.Error(0)
}

func (m *ComputeBladeHalMock) StealthModeActive() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *ComputeBladeHalMock) GetPowerStatus() (PowerStatus, error) {
	args := m.Called()
	return args.Get(0).(PowerStatus), args.Error(1)
}

func (m *ComputeBladeHalMock) WaitForEdgeButtonPress(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *ComputeBladeHalMock) SetLed(idx LedIndex, color led.Color) error {
	args := m.Called(idx, color)
	return args.Error(0)
}

func (m *ComputeBladeHalMock) GetTemperature() (float64, error) {
	args := m.Called()
	return args.Get(0).(float64), args.Error(1)
}
