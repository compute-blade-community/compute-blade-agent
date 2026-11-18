//go:build !linux

package internal_agent

import (
	"context"
	"errors"
)

// emergencyPoweroff is only supported on Linux.
func emergencyPoweroff(context.Context) error {
	return errors.New("emergency power-off is only supported on linux")
}
