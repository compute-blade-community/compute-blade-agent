package fancontroller_test

import (
	"testing"

	"github.com/uptime-industries/compute-blade-agent/pkg/fancontroller"
)

func TestFanControllerLinear_GetFanSpeed(t *testing.T) {
	t.Parallel()

	config := fancontroller.Config{
		Steps: []fancontroller.Step{
			{Temperature: 20, Percent: 30},
			{Temperature: 30, Percent: 60},
		},
	}

	controller, err := fancontroller.NewLinearFanController(config)
	if err != nil {
		t.Fatalf("Failed to create fan controller: %v", err)
	}

	testCases := []struct {
		temperature float64
		expected    uint8
	}{
		{15, 30}, // Should use the minimum speed
		{25, 45}, // Should calculate speed based on linear function
		{35, 60}, // Should use the maximum speed
	}

	for _, tc := range testCases {
		expected := tc.expected
		temperature := tc.temperature
		t.Run("", func(t *testing.T) {
			t.Parallel()
			speed := controller.GetFanSpeed(temperature)
			if speed != expected {
				t.Errorf("For temperature %.2f, expected speed %d but got %d", temperature, expected, speed)
			}
		})
	}
}

func TestFanControllerLinear_GetFanSpeedWithOverride(t *testing.T) {
	t.Parallel()

	config := fancontroller.Config{
		Steps: []fancontroller.Step{
			{Temperature: 20, Percent: 30},
			{Temperature: 30, Percent: 60},
		},
	}

	controller, err := fancontroller.NewLinearFanController(config)
	if err != nil {
		t.Fatalf("Failed to create fan controller: %v", err)
	}
	controller.Override(&fancontroller.FanOverrideOpts{
		Percent: 99,
	})

	testCases := []struct {
		temperature float64
		expected    uint8
	}{
		{15, 99},
		{25, 99},
		{35, 99},
	}

	for _, tc := range testCases {
		expected := tc.expected
		temperature := tc.temperature
		t.Run("", func(t *testing.T) {
			t.Parallel()
			speed := controller.GetFanSpeed(temperature)
			if speed != expected {
				t.Errorf("For temperature %.2f, expected speed %d but got %d", temperature, expected, speed)
			}
		})
	}
}

func TestFanControllerLinear_ConstructionErrors(t *testing.T) {
	testCases := []struct {
		name   string
		config fancontroller.Config
		errMsg string
	}{
		{
			name: "Overlapping Step Temperatures",
			config: fancontroller.Config{
				Steps: []fancontroller.Step{
					{Temperature: 20, Percent: 60},
					{Temperature: 20, Percent: 30},
				},
			},
			errMsg: "steps must have strictly increasing temperatures",
		},
		{
			name: "Percentages must not decrease",
			config: fancontroller.Config{
				Steps: []fancontroller.Step{
					{Temperature: 20, Percent: 60},
					{Temperature: 30, Percent: 30},
				},
			},
			errMsg: "fan percent must not decrease",
		},
		{
			name: "InvalidSpeedRange",
			config: fancontroller.Config{
				Steps: []fancontroller.Step{
					{Temperature: 20, Percent: 10},
					{Temperature: 30, Percent: 200},
				},
			},
			errMsg: "fan percent must be between 0 and 100",
		},
	}

	for _, tc := range testCases {
		config := tc.config
		expectedErrMsg := tc.errMsg
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := fancontroller.NewLinearFanController(config)
			if err == nil {
				t.Errorf("Expected error with message '%s', but got no error", expectedErrMsg)
			} else if err.Error() != expectedErrMsg {
				t.Errorf("Expected error message '%s', but got '%s'", expectedErrMsg, err.Error())
			}
		})
	}
}
