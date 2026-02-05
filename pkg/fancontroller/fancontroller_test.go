package fancontroller_test

import (
	"testing"

	"github.com/compute-blade-community/compute-blade-agent/pkg/fancontroller"
	"github.com/stretchr/testify/assert"
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

	assert.Equal(t, controller.Steps(), config.Steps)

	for _, tc := range testCases {
		expected := tc.expected
		temperature := tc.temperature
		t.Run("", func(t *testing.T) {
			t.Parallel()
			speed := controller.GetFanSpeedPercent(temperature)
			assert.Equal(t, expected, speed)
			assert.True(t, controller.IsAutomaticSpeed(), "Expected fan speed to be automatic, but it was not")
		})
	}
}

func TestFanControllerLinear_GetFanSpeedMultipleSteps(t *testing.T) {
	t.Parallel()

	// Typical 5-step fan curve configuration
	config := fancontroller.Config{
		Steps: []fancontroller.Step{
			{Temperature: 40, Percent: 30},
			{Temperature: 50, Percent: 50},
			{Temperature: 60, Percent: 70},
			{Temperature: 70, Percent: 90},
			{Temperature: 75, Percent: 100},
		},
	}

	controller, err := fancontroller.NewLinearFanController(config)
	if err != nil {
		t.Fatalf("Failed to create fan controller: %v", err)
	}

	testCases := []struct {
		name        string
		temperature float64
		expected    uint8
	}{
		{"below minimum", 30, 30},      // Below 40°C: use minimum 30%
		{"at step 0", 40, 30},          // At 40°C: 30%
		{"between step 0-1", 45, 40},   // Midpoint 40-50°C: 40%
		{"at step 1", 50, 50},          // At 50°C: 50%
		{"between step 1-2", 55, 60},   // Midpoint 50-60°C: 60%
		{"at step 2", 60, 70},          // At 60°C: 70%
		{"between step 2-3", 65, 80},   // Midpoint 60-70°C: 80%
		{"at step 3", 70, 90},          // At 70°C: 90%
		{"between step 3-4", 72, 94},   // 70 + (100-90)*(72-70)/(75-70) = 90 + 4 = 94%
		{"at step 4", 75, 100},         // At 75°C: 100%
		{"above maximum", 80, 100},     // Above 75°C: use maximum 100%
		{"well above maximum", 90, 100}, // Well above: still 100%
	}

	for _, tc := range testCases {
		expected := tc.expected
		temperature := tc.temperature
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			speed := controller.GetFanSpeedPercent(temperature)
			assert.Equal(t, expected, speed, "Temperature %.1f°C should yield %d%% fan speed", temperature, expected)
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
			speed := controller.GetFanSpeedPercent(temperature)
			assert.Equal(t, expected, speed)
			assert.False(t, controller.IsAutomaticSpeed(), "Expected fan speed to be overridden, but it was not")
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

			assert.NotNil(t, err, "Expected error with message '%s', but got no error", expectedErrMsg)
			assert.EqualError(t, err, expectedErrMsg)
		})
	}
}
