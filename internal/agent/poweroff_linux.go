//go:build linux

package internal_agent

import (
	"context"
	"syscall"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
)

// emergencySyncTimeout bounds how long the emergency power-off waits for dirty data to be flushed. A hung storage
// device (or NFS mount) is a common reason to need an emergency power-off in the first place.
const emergencySyncTimeout = 2 * time.Second

// emergencyPoweroff powers the blade off immediately, without stopping services or unmounting file systems.
// File systems may need to be repaired on the next boot.
func emergencyPoweroff(ctx context.Context) error {
	log.FromContext(ctx).Error("EMERGENCY POWER-OFF requested, powering off without shutting down")

	synced := make(chan struct{})
	go func() {
		syscall.Sync()
		close(synced)
	}()
	select {
	case <-synced:
	case <-time.After(emergencySyncTimeout):
		log.FromContext(ctx).Error("sync did not finish in time, powering off anyway")
	}

	return syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
}
