//go:build !tinygo

package smartfanunit

import (
	"fmt"
	"testing"
)

func TestFloat32ToAndFrom24Bit(t *testing.T) {
	tests := []struct {
		input    float32
		expected float32
	}{
		{0.0, 0.0},
		{1.0, 1.0},
		{0.123, 0.1},
		{10.0, 10.0},
		{100.0, 100.0},
		{1677721.5, 1677721.5},
		{2000000.0, 1677721.5}, // Should be capped at 0xFFFFFF
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Input: %f", test.input), func(t *testing.T) {
			data := float32To24Bit(test.input)
			result := float32From24Bit(data)

			// Check if the result is approximately equal within a small delta
			if result < test.expected-0.01 || result > test.expected+0.01 {
				t.Errorf("Expected %f, but got %f", test.expected, result)
			}
		})
	}
}
