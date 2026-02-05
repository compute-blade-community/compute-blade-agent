package fancontroller

import (
	"fmt"
	"sort"
	"sync"

	"github.com/sierrasoftworks/humane-errors-go"
)

type FanController interface {
	Override(opts *FanOverrideOpts)
	// GetFanSpeedPercent returns the fan speed in percent based on the current temperature
	GetFanSpeedPercent(temperature float64) uint8
	// IsAutomaticSpeed returns true if the FanSpeed is determined by the fan controller logic, or false if determined
	// by an FanOverrideOpts
	IsAutomaticSpeed() bool

	// Steps returns the list of temperature and fan speed steps configured for the fan controller.
	Steps() []Step
}

// FanController is a simple fan controller that reacts to temperature changes with a linear function
type fanControllerLinear struct {
	mu           sync.Mutex
	overrideOpts *FanOverrideOpts
	config       Config
}

// NewLinearFanController creates a new FanControllerLinear
func NewLinearFanController(config Config) (FanController, humane.Error) {
	steps := config.Steps

	// Sort steps by temperature
	sort.Slice(steps, func(i, j int) bool {
		return steps[i].Temperature < steps[j].Temperature
	})

	for i := 0; i < len(steps)-1; i++ {
		curr := steps[i]
		next := steps[i+1]

		if curr.Temperature >= next.Temperature {
			return nil, humane.New("steps must have strictly increasing temperatures",
				"Ensure that the temperatures are in ascending order and the ranges do not overlap",
				fmt.Sprintf("Ensure defined temperature stepd %.2f is >= %.2f", curr.Temperature, next.Temperature),
			)
		}
		if curr.Percent > next.Percent {
			return nil, humane.New("fan percent must not decrease",
				"Ensure that the fan percentages are not decreasing for higher temperatures",
				fmt.Sprintf("Temperature %.2f is defined at %d%% and must be >= %d%% defined for temperature %.2f", curr.Temperature, curr.Percent, next.Percent, next.Temperature),
			)
		}
	}

	for _, step := range steps {
		if step.Percent > 100 {
			return nil, humane.New("fan percent must be between 0 and 100",
				fmt.Sprintf("Ensure your fan percentage is 0 < %d < 100", step.Percent),
			)
		}
	}

	return &fanControllerLinear{
		config: config,
	}, nil
}

func (f *fanControllerLinear) Steps() []Step {
	return f.config.Steps
}

func (f *fanControllerLinear) Override(opts *FanOverrideOpts) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.overrideOpts = opts
}

// GetFanSpeedPercent returns the fan speed in percent based on the current temperature
func (f *fanControllerLinear) GetFanSpeedPercent(temperature float64) uint8 {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.overrideOpts != nil {
		return f.overrideOpts.Percent
	}

	steps := f.config.Steps

	// Below minimum temperature: use minimum fan speed
	if temperature <= steps[0].Temperature {
		return steps[0].Percent
	}

	// Above maximum temperature: use maximum fan speed
	lastIdx := len(steps) - 1
	if temperature >= steps[lastIdx].Temperature {
		return steps[lastIdx].Percent
	}

	// Find the bracket where steps[i].Temperature <= temperature < steps[i+1].Temperature
	for i := 0; i < lastIdx; i++ {
		if temperature >= steps[i].Temperature && temperature < steps[i+1].Temperature {
			// Linear interpolation between steps[i] and steps[i+1]
			slope := float64(steps[i+1].Percent-steps[i].Percent) / (steps[i+1].Temperature - steps[i].Temperature)
			speed := float64(steps[i].Percent) + slope*(temperature-steps[i].Temperature)
			return uint8(speed)
		}
	}

	// Fallback (should not reach here due to above checks)
	return steps[lastIdx].Percent
}

func (f *fanControllerLinear) IsAutomaticSpeed() bool {
	return f.overrideOpts == nil
}
