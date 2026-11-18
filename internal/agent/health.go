package internal_agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal"
	"github.com/compute-blade-community/compute-blade-agent/pkg/health"
	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"go.uber.org/zap"
)

// healthMonitorInterval is how often the health monitor polls the hardware
const healthMonitorInterval = 2 * time.Second

// setupThrottleDetection creates the under-voltage and throttling detectors, if enabled.
func (a *computeBladeAgent) setupThrottleDetection() {
	if cfg := a.config.Health.Undervoltage; cfg.Enabled {
		a.undervoltageDetector = &health.FlagDetector{ClearAfter: cfg.ClearAfter}
	}
	if cfg := a.config.Health.Throttling; cfg.Enabled {
		a.throttlingDetector = &health.FlagDetector{ClearAfter: cfg.ClearAfter}
	}
}

// runHealthMonitor periodically polls hardware health that isn't tied to the fan controller.
func (a *computeBladeAgent) runHealthMonitor(ctx context.Context) {
	log.FromContext(ctx).Info("Starting health monitor")

	ticker := time.NewTicker(healthMonitorInterval)
	defer ticker.Stop()

	throttleSupported := a.undervoltageDetector != nil || a.throttlingDetector != nil

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if throttleSupported {
			throttleSupported = a.evaluateThrottleStatus(ctx)
		}
	}
}

// evaluateThrottleStatus reads the firmware throttle flags and raises / clears the under-voltage and throttling
// conditions. Returns false if the platform doesn't report throttle flags, so polling can stop.
func (a *computeBladeAgent) evaluateThrottleStatus(ctx context.Context) bool {
	status, err := a.blade.GetThrottleStatus()
	if errors.Is(err, hal.ErrNotSupported) {
		log.FromContext(ctx).Info("Platform doesn't report throttle status, under-voltage and throttling detection disabled")
		return false
	}
	if err != nil {
		log.FromContext(ctx).WithError(err).Warn("Failed to read throttle status")
		return true
	}

	now := time.Now()
	details := events.ThrottleDetails{Flags: uint32(status)}

	if a.undervoltageDetector != nil {
		switch a.undervoltageDetector.Observe(now, status.UnderVoltage()) {
		case health.Raised:
			log.FromContext(ctx).Error("Under-voltage detected: the blade doesn't get enough power",
				zap.String("flags", throttleFlagsString(status)))
			a.emitMessage(ctx, events.NewMessage(events.UndervoltageEvent, details))
		case health.Cleared:
			log.FromContext(ctx).Info("Supply voltage back to normal", zap.String("flags", throttleFlagsString(status)))
			a.emitMessage(ctx, events.NewMessage(events.UndervoltageClearEvent, details))
		case health.Unchanged:
		}
	}

	if a.throttlingDetector != nil {
		switch a.throttlingDetector.Observe(now, status.Throttling()) {
		case health.Raised:
			log.FromContext(ctx).Warn("CPU throttling detected", zap.String("flags", throttleFlagsString(status)))
			a.emitMessage(ctx, events.NewMessage(events.ThrottledEvent, details))
		case health.Cleared:
			log.FromContext(ctx).Info("CPU no longer throttled", zap.String("flags", throttleFlagsString(status)))
			a.emitMessage(ctx, events.NewMessage(events.ThrottledClearEvent, details))
		case health.Unchanged:
		}
	}

	return true
}

// throttleFlagsString renders the throttle flags as hex, matching `vcgencmd get_throttled`
func throttleFlagsString(status hal.ThrottleStatus) string {
	return fmt.Sprintf("0x%x", uint32(status))
}
