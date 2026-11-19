package hal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithUart5Pins(t *testing.T) {
	t.Parallel()

	// What a blade looks like after the agent fell back to the standard fan unit: GPIO 12 on PWM0 (alt0), GPIO 13 an
	// input; GPIO 18 (WS281x LEDs, bits 26:24) is an output and must stay one.
	afterStandard := uint32(0b100<<6 | 0b000<<9 | 0b001<<24)
	assert.Equal(t, uint32(0b011<<6|0b011<<9|0b001<<24), withUart5Pins(afterStandard))

	// Already on UART5 (as the firmware sets them at boot): unchanged
	assert.Equal(t, withUart5Pins(afterStandard), withUart5Pins(withUart5Pins(afterStandard)))
}

func TestWithPwmFanPin(t *testing.T) {
	t.Parallel()

	uart5 := uint32(0b011<<6 | 0b011<<9)
	assert.Equal(t, uint32(0b100<<6|0b011<<9), withPwmFanPin(uart5))
}
