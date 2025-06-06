package internal_agent

import (
	"context"
	"errors"

	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
	"github.com/compute-blade-community/compute-blade-agent/pkg/fancontroller"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
	"github.com/compute-blade-community/compute-blade-agent/pkg/ledengine"
	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"go.uber.org/zap"
)

// handleEvent processes an incoming event, updates state, and dispatches it to the appropriate handler based on the event type.
func (a *computeBladeAgent) handleEvent(ctx context.Context, event events.Event) error {
	log.FromContext(ctx).Info("Handling event", zap.String("event", event.String()))
	eventCounter.WithLabelValues(event.String()).Inc()

	// register event in state
	a.state.RegisterEvent(event)

	// Dispatch incoming events to the right handler(s)
	switch event {
	case events.CriticalEvent:
		// Handle critical event
		return a.handleCriticalActive(ctx)
	case events.CriticalResetEvent:
		// Handle critical event
		return a.handleCriticalReset(ctx)
	case events.IdentifyEvent:
		// Handle identify event
		return a.handleIdentifyActive(ctx)
	case events.IdentifyConfirmEvent:
		// Handle identify event
		return a.handleIdentifyConfirm(ctx)
	case events.EdgeButtonEvent:
		// Handle edge button press to toggle identify mode
		event := events.Event(events.IdentifyEvent)
		if a.state.IdentifyActive() {
			event = events.Event(events.IdentifyConfirmEvent)
		}
		select {
		case a.eventChan <- event:
		default:
			log.FromContext(ctx).Warn("Edge button press event dropped due to backlog")
			droppedEventCounter.WithLabelValues(event.String()).Inc()
		}
	case events.NoopEvent:
	}

	return nil
}

// handleIdentifyActive is responsible for handling the identify event by setting a burst LED pattern based on the configuration.
func (a *computeBladeAgent) handleIdentifyActive(ctx context.Context) error {
	log.FromContext(ctx).Info("Identify active")
	return a.edgeLedEngine.SetPattern(ledengine.NewBurstPattern(led.Color{}, a.config.IdentifyLedColor))
}

// handleIdentifyConfirm handles the confirmation of an identify event by updating the LED engine with a static idle pattern.
func (a *computeBladeAgent) handleIdentifyConfirm(ctx context.Context) error {
	log.FromContext(ctx).Info("Identify confirmed/cleared")
	return a.edgeLedEngine.SetPattern(ledengine.NewStaticPattern(a.config.IdleLedColor))
}

// handleCriticalActive handles the system's response to a critical state by adjusting fan speed and LED indications.
// It sets the fan speed to 100%, disables stealth mode, and applies a critical LED pattern.
// Returns any errors encountered during the process as a combined error.
func (a *computeBladeAgent) handleCriticalActive(ctx context.Context) error {
	log.FromContext(ctx).Warn("Blade in critical state, setting fan speed to 100% and turning on LEDs")

	// Set fan speed to 100%
	a.fanController.Override(&fancontroller.FanOverrideOpts{Percent: 100})

	// Disable stealth mode (turn on LEDs)
	setStealthModeError := a.blade.SetStealthMode(false)

	// Set critical pattern for top LED
	setPatternTopLedErr := a.topLedEngine.SetPattern(
		ledengine.NewSlowBlinkPattern(led.Color{}, a.config.CriticalLedColor),
	)
	// Combine errors, but don't stop execution flow for now
	return errors.Join(setStealthModeError, setPatternTopLedErr)
}

// handleCriticalReset handles the reset of a critical state by restoring default hardware settings for fans and LEDs.
func (a *computeBladeAgent) handleCriticalReset(ctx context.Context) error {
	log.FromContext(ctx).Info("Critical state cleared, setting fan speed to default and restoring LEDs to default state")
	// Reset fan controller overrides
	a.fanController.Override(nil)

	// Reset stealth mode
	if err := a.blade.SetStealthMode(a.config.StealthModeEnabled); err != nil {
		return err
	}

	// Set top LED off
	if err := a.topLedEngine.SetPattern(ledengine.NewStaticPattern(led.Color{})); err != nil {
		return err
	}

	return nil
}
