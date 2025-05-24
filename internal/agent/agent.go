package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	agent2 "github.com/uptime-industries/compute-blade-agent/pkg/agent"
	"github.com/uptime-industries/compute-blade-agent/pkg/events"
	"github.com/uptime-industries/compute-blade-agent/pkg/fancontroller"
	"github.com/uptime-industries/compute-blade-agent/pkg/hal"
	"github.com/uptime-industries/compute-blade-agent/pkg/hal/led"
	"github.com/uptime-industries/compute-blade-agent/pkg/ledengine"
	"github.com/uptime-industries/compute-blade-agent/pkg/log"
	"go.uber.org/zap"
)

var (
	// eventCounter is a prometheus counter that counts the number of events handled by the agent
	eventCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "computeblade_agent",
		Name:      "events_count",
		Help:      "ComputeBlade agent internal event handler statistics (handled events)",
	}, []string{"type"})

	// droppedEventCounter is a prometheus counter that counts the number of events dropped by the agent
	droppedEventCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "computeblade_agent",
		Name:      "events_dropped_count",
		Help:      "ComputeBlade agent internal event handler statistics (dropped events)",
	}, []string{"type"})
)

// computeBladeAgentImpl is the implementation of the ComputeBladeAgent interface
type computeBladeAgentImpl struct {
	opts          ComputeBladeAgentConfig
	blade         hal.ComputeBladeHal
	state         agent2.ComputebladeState
	edgeLedEngine ledengine.LedEngine
	topLedEngine  ledengine.LedEngine
	fanController fancontroller.FanController
	eventChan     chan events.Event
}

func NewComputeBladeAgent(ctx context.Context, opts ComputeBladeAgentConfig) (agent2.ComputeBladeAgent, error) {
	var err error

	// blade, err := hal.NewCm4Hal(hal.ComputeBladeHalOpts{
	blade, err := hal.NewCm4Hal(ctx, opts.ComputeBladeHalOpts)
	if err != nil {
		return nil, err
	}

	edgeLedEngine := ledengine.NewLedEngine(ledengine.Options{
		LedIdx: hal.LedEdge,
		Hal:    blade,
	})

	topLedEngine := ledengine.NewLedEngine(ledengine.Options{
		LedIdx: hal.LedTop,
		Hal:    blade,
	})

	fanController, err := fancontroller.NewLinearFanController(opts.FanControllerConfig)
	if err != nil {
		return nil, err
	}

	return &computeBladeAgentImpl{
		opts:          opts,
		blade:         blade,
		edgeLedEngine: edgeLedEngine,
		topLedEngine:  topLedEngine,
		fanController: fanController,
		state:         agent2.NewComputeBladeState(),
		eventChan: make(
			chan events.Event,
			10,
		), // backlog of 10 events. They should process fast but we e.g. don't want to miss button presses
	}, nil
}

func (a *computeBladeAgentImpl) RunAsync(ctx context.Context, cancel context.CancelCauseFunc) {
	go func() {
		log.FromContext(ctx).Info("Starting agent")
		err := a.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.FromContext(ctx).WithError(err).Error("Failed to run agent")
			cancel(err)
		}
	}()
}

func (a *computeBladeAgentImpl) Run(origCtx context.Context) error {
	var wg sync.WaitGroup
	ctx, cancelCtx := context.WithCancelCause(origCtx)
	defer cancelCtx(fmt.Errorf("cancel"))
	defer a.cleanup(ctx)

	log.FromContext(ctx).Info("Starting ComputeBlade agent")

	// Ingest noop event to initialise metrics
	a.state.RegisterEvent(events.NoopEvent)

	// Set defaults
	if err := a.blade.SetStealthMode(a.opts.StealthModeEnabled); err != nil {
		return err
	}

	// Run HAL
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.FromContext(ctx).Info("Starting HAL")
		if err := a.blade.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.FromContext(ctx).WithError(err).Error("HAL failed")
			cancelCtx(err)
		}
	}()

	// Start edge button event handler
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.FromContext(ctx).Info("Starting edge button event handler")
		for {
			err := a.blade.WaitForEdgeButtonPress(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				log.FromContext(ctx).WithError(err).Error("Edge button event handler failed")
				cancelCtx(err)
			} else if err != nil {
				return
			}
			select {
			case a.eventChan <- events.Event(events.EdgeButtonEvent):
			default:
				log.FromContext(ctx).Warn("Edge button press event dropped due to backlog")
				droppedEventCounter.WithLabelValues(events.Event(events.EdgeButtonEvent).String()).Inc()
			}
		}
	}()

	// Start top LED engine
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.FromContext(ctx).Info("Starting top LED engine")
		err := a.runTopLedEngine(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.FromContext(ctx).WithError(err).Error("Top LED engine failed")
			cancelCtx(err)
		}
	}()

	// Start edge LED engine
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.FromContext(ctx).Info("Starting edge LED engine")
		err := a.runEdgeLedEngine(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.FromContext(ctx).WithError(err).Error("Edge LED engine failed")
			cancelCtx(err)
		}
	}()

	// Start fan controller
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.FromContext(ctx).Info("Starting fan controller")
		err := a.runFanController(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.FromContext(ctx).WithError(err).Error("Fan Controller Failed")
			cancelCtx(err)
		}
	}()

	// Start event handler
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.FromContext(ctx).Info("Starting event handler")
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-a.eventChan:
				err := a.handleEvent(ctx, event)
				if err != nil && !errors.Is(err, context.Canceled) {
					log.FromContext(ctx).WithError(err).Error("Event handler failed")
					cancelCtx(err)
				}
			}
		}
	}()

	wg.Wait()
	return ctx.Err()
}

// cleanup restores sane defaults before exiting. Ignores canceled context!
func (a *computeBladeAgentImpl) cleanup(ctx context.Context) {
	log.FromContext(ctx).Info("Exiting, restoring safe settings")
	if err := a.blade.SetFanSpeed(100); err != nil {
		log.FromContext(ctx).WithError(err).Error("Failed to set fan speed to 100%")
	}
	if err := a.blade.SetLed(hal.LedEdge, led.Color{}); err != nil {
		log.FromContext(ctx).WithError(err).Error("Failed to set edge LED to off")
	}
	if err := a.blade.SetLed(hal.LedTop, led.Color{}); err != nil {
		log.FromContext(ctx).WithError(err).Error("Failed to set edge LED to off")
	}
	if err := a.Close(); err != nil {
		log.FromContext(ctx).WithError(err).Error("Failed to close blade")
	}
}

// EmitEvent dispatches an event to the event handler
func (a *computeBladeAgentImpl) EmitEvent(ctx context.Context, event events.Event) error {
	select {
	case a.eventChan <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SetFanSpeed sets the fan speed
func (a *computeBladeAgentImpl) SetFanSpeed(_ context.Context, speed uint8) error {
	if a.state.CriticalActive() {
		return errors.New("cannot set fan speed while the blade is in a critical state")
	}
	a.fanController.Override(&fancontroller.FanOverrideOpts{Percent: speed})
	return nil
}

// SetStealthMode enables/disables the stealth mode
func (a *computeBladeAgentImpl) SetStealthMode(_ context.Context, enabled bool) error {
	if a.state.CriticalActive() {
		return errors.New("cannot set stealth mode while the blade is in a critical state")
	}
	return a.blade.SetStealthMode(enabled)
}

// WaitForIdentifyConfirm waits for the identify confirm event
func (a *computeBladeAgentImpl) WaitForIdentifyConfirm(ctx context.Context) error {
	return a.state.WaitForIdentifyConfirm(ctx)
}

// Close shuts down the underlying blade instance and releases any associated resources, returning a combined error if any.
func (a *computeBladeAgentImpl) Close() error {
	return errors.Join(a.blade.Close())
}

func (a *computeBladeAgentImpl) handleEvent(ctx context.Context, event events.Event) error {
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

func (a *computeBladeAgentImpl) handleIdentifyActive(ctx context.Context) error {
	log.FromContext(ctx).Info("Identify active")
	return a.edgeLedEngine.SetPattern(ledengine.NewBurstPattern(led.Color{}, a.opts.IdentifyLedColor))
}

func (a *computeBladeAgentImpl) handleIdentifyConfirm(ctx context.Context) error {
	log.FromContext(ctx).Info("Identify confirmed/cleared")
	return a.edgeLedEngine.SetPattern(ledengine.NewStaticPattern(a.opts.IdleLedColor))
}

func (a *computeBladeAgentImpl) handleCriticalActive(ctx context.Context) error {
	log.FromContext(ctx).Warn("Blade in critical state, setting fan speed to 100% and turning on LEDs")

	// Set fan speed to 100%
	a.fanController.Override(&fancontroller.FanOverrideOpts{Percent: 100})

	// Disable stealth mode (turn on LEDs)
	setStealthModeError := a.blade.SetStealthMode(false)

	// Set critical pattern for top LED
	setPatternTopLedErr := a.topLedEngine.SetPattern(
		ledengine.NewSlowBlinkPattern(led.Color{}, a.opts.CriticalLedColor),
	)
	// Combine errors, but don't stop execution flow for now
	return errors.Join(setStealthModeError, setPatternTopLedErr)
}

func (a *computeBladeAgentImpl) handleCriticalReset(ctx context.Context) error {
	log.FromContext(ctx).Info("Critical state cleared, setting fan speed to default and restoring LEDs to default state")
	// Reset fan controller overrides
	a.fanController.Override(nil)

	// Reset stealth mode
	if err := a.blade.SetStealthMode(a.opts.StealthModeEnabled); err != nil {
		return err
	}

	// Set top LED off
	if err := a.topLedEngine.SetPattern(ledengine.NewStaticPattern(led.Color{})); err != nil {
		return err
	}

	return nil
}

// runTopLedEngine runs the top LED engine
func (a *computeBladeAgentImpl) runTopLedEngine(ctx context.Context) error {
	// FIXME the top LED is only used to indicate emergency situations
	err := a.topLedEngine.SetPattern(ledengine.NewStaticPattern(led.Color{}))
	if err != nil {
		return err
	}
	return a.topLedEngine.Run(ctx)
}

// runEdgeLedEngine runs the edge LED engine
func (a *computeBladeAgentImpl) runEdgeLedEngine(ctx context.Context) error {
	err := a.edgeLedEngine.SetPattern(ledengine.NewStaticPattern(a.opts.IdleLedColor))
	if err != nil {
		return err
	}
	return a.edgeLedEngine.Run(ctx)
}

func (a *computeBladeAgentImpl) runFanController(ctx context.Context) error {
	// Update fan speed periodically
	ticker := time.NewTicker(5 * time.Second)

	for {

		// Wait for the next tick
		select {
		case <-ctx.Done():
			ticker.Stop()
			return ctx.Err()
		case <-ticker.C:
		}

		// Get temperature
		temp, err := a.blade.GetTemperature()
		if err != nil {
			log.FromContext(ctx).WithError(err).Error("Failed to get temperature")
			temp = 100 // set to a high value to trigger the maximum speed defined by the fan curve
		}
		// Derive fan speed from temperature
		speed := a.fanController.GetFanSpeed(temp)
		// Set fan speed
		if err := a.blade.SetFanSpeed(speed); err != nil {
			log.FromContext(ctx).WithError(err).Error("Failed to set fan speed")
		}
	}
}
