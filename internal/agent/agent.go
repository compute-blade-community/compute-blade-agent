package internal_agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/compute-blade-community/compute-blade-agent/pkg/actions"
	"github.com/compute-blade-community/compute-blade-agent/pkg/agent"
	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
	"github.com/compute-blade-community/compute-blade-agent/pkg/fancontroller"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
	"github.com/compute-blade-community/compute-blade-agent/pkg/health"
	"github.com/compute-blade-community/compute-blade-agent/pkg/ledengine"
	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sierrasoftworks/humane-errors-go"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// criticalTemperatureHysteresis is how far (in °C) the SoC temperature has to drop below the
// critical threshold before an automatically raised critical state is cleared again.
const criticalTemperatureHysteresis = 5

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

// computeBladeAgent manages the operation and coordination of hardware components and services for a compute blade agent.
type computeBladeAgent struct {
	bladeapiv1alpha1.UnimplementedBladeAgentServiceServer
	config        agent.ComputeBladeAgentConfig
	blade         hal.ComputeBladeHal
	state         agent.ComputebladeState
	edgeLedEngine ledengine.LedEngine
	topLedEngine  ledengine.LedEngine
	// edgeLeds and topLeds layer identify, critical mode and health indicators on the two LEDs
	edgeLeds *ledengine.Stack
	topLeds  *ledengine.Stack
	// indicatorLeds maps a health condition to the LED stack its indicator is shown on
	indicatorLeds map[string]*ledengine.Stack
	fanController fancontroller.FanController
	eventChan     chan events.Message
	server        *grpc.Server
	agentInfo     agent.ComputeBladeAgentInfo

	// eventBus fans handled events out to WatchEvents subscribers
	eventBus events.EventBus
	// hostname is reported as the blade name in published events
	hostname string
	// shutdown is closed when the agent stops, ending all WatchEvents streams so the gRPC server can stop gracefully
	shutdown     chan struct{}
	shutdownOnce sync.Once

	// criticalDetector raises critical mode when the SoC temperature exceeds the configured threshold.
	// Only accessed from the fan controller goroutine.
	criticalDetector health.ThresholdDetector

	// fanStallDetector raises a fan stall when the fan doesn't spin although commanded to. Nil if disabled.
	// Only accessed from the fan controller goroutine.
	fanStallDetector *health.FanStallDetector

	// undervoltageDetector and throttlingDetector track the firmware throttle flags. Nil if disabled.
	// Only accessed from the health monitor goroutine.
	undervoltageDetector *health.FlagDetector
	throttlingDetector   *health.FlagDetector

	// powerPolicy limits the CPU while the blade is short on power. Nil if not configured.
	powerPolicy *powerPolicy

	// actions runs the actions bound to button gestures
	actions *actions.Runner
	// buttons is the validated button configuration
	buttons buttonBindings
}

// NewComputeBladeAgent creates and initializes a new ComputeBladeAgent, including gRPC server setup and hardware interfaces.
func NewComputeBladeAgent(ctx context.Context, config agent.ComputeBladeAgentConfig, agentInfo agent.ComputeBladeAgentInfo) (agent.ComputeBladeAgent, error) {
	blade, err := hal.NewHal(ctx, config.ComputeBladeHalOpts)
	if err != nil {
		return nil, err
	}

	fanController, err := fancontroller.NewLinearFanController(config.FanControllerConfig)
	if err != nil {
		return nil, err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, humane.Wrap(err, "failed to determine hostname")
	}

	a := &computeBladeAgent{
		config:        config,
		blade:         blade,
		edgeLedEngine: ledengine.New(blade, hal.LedEdge),
		topLedEngine:  ledengine.New(blade, hal.LedTop),
		fanController: fanController,
		state:         agent.NewComputeBladeState(),
		eventChan:     make(chan events.Message, 10),
		agentInfo:     agentInfo,
		eventBus:      events.New(),
		hostname:      hostname,
		shutdown:      make(chan struct{}),
		criticalDetector: health.ThresholdDetector{
			Threshold:  float64(config.CriticalTemperatureThreshold),
			Hysteresis: criticalTemperatureHysteresis,
		},
	}

	if err := a.setupLeds(); err != nil {
		return nil, err
	}

	a.setupFanStallDetection(ctx)
	a.setupThrottleDetection()

	if err := a.setupPowerPolicy(ctx); err != nil {
		return nil, err
	}

	a.actions = a.newActionRunner()
	if err := a.setupButtons(); err != nil {
		return nil, err
	}

	if err := a.setupGrpcServer(ctx); err != nil {
		return nil, err
	}

	bladeapiv1alpha1.RegisterBladeAgentServiceServer(a.server, a)
	return a, nil
}

// RunAsync starts the agent in a separate goroutine and handles errors, allowing cancellation through the provided context.
func (a *computeBladeAgent) RunAsync(ctx context.Context, cancel context.CancelCauseFunc) {
	go func() {
		log.FromContext(ctx).Info("Starting agent")
		err := a.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.FromContext(ctx).WithError(err).Error("Failed to run agent")
			cancel(err)
		}
	}()
}

// Run initializes and starts the compute blade agent, setting up necessary components and processes, and waits for termination.
func (a *computeBladeAgent) Run(origCtx context.Context) error {
	ctx, cancelCtx := context.WithCancelCause(origCtx)
	defer cancelCtx(fmt.Errorf("cancel"))

	log.FromContext(ctx).Info("Starting ComputeBlade agent")

	// Ingest noop event to initialise metrics
	a.state.RegisterEvent(events.NoopEvent)

	// Set defaults
	if err := a.blade.SetStealthMode(a.config.StealthModeEnabled); err != nil {
		return err
	}

	// Run HAL

	go a.runHal(ctx, cancelCtx)

	// Start button handler
	go a.runButtonHandler(ctx)

	// Start top LED engine
	go a.runTopLedEngine(ctx, cancelCtx)

	// Start edge LED engine
	go a.runEdgeLedEngine(ctx, cancelCtx)

	// Start fan controller
	go a.runFanController(ctx, cancelCtx)

	// Start health monitor
	go a.runHealthMonitor(ctx)

	// Start event handler
	go a.runEventHandler(ctx, cancelCtx)

	// Start gRPC API
	go a.runGRpcApi(ctx, cancelCtx)

	// wait till we're done
	<-ctx.Done()

	return ctx.Err()
}

// GracefulStop gracefully stops the gRPC server, ensuring all in-progress RPCs are completed before shutting down.
func (a *computeBladeAgent) GracefulStop(ctx context.Context) error {
	// End all event streams first, GracefulStop waits for them to return
	a.shutdownOnce.Do(func() { close(a.shutdown) })
	a.server.GracefulStop()

	log.FromContext(ctx).Info("Exiting, restoring safe settings")
	if a.powerPolicy != nil {
		if err := a.powerPolicy.stop(); err != nil {
			log.FromContext(ctx).WithError(err).Error("Failed to restore original CPU settings")
		}
	}
	if err := a.blade.SetFanSpeed(100); err != nil {
		log.FromContext(ctx).WithError(err).Error("Failed to set fan speed to 100%")
	}
	if err := a.blade.SetLed(hal.LedEdge, led.Color{}); err != nil {
		log.FromContext(ctx).WithError(err).Error("Failed to set edge LED to off")
	}
	if err := a.blade.SetLed(hal.LedTop, led.Color{}); err != nil {
		log.FromContext(ctx).WithError(err).Error("Failed to set edge LED to off")
	}

	return a.blade.Close()
}

// runHal initializes and starts the HAL service within the given context, handling errors and supporting graceful cancellation.
func (a *computeBladeAgent) runHal(ctx context.Context, cancel context.CancelCauseFunc) {
	log.FromContext(ctx).Info("Starting HAL")
	if err := a.blade.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.FromContext(ctx).WithError(err).Error("HAL failed")
		cancel(err)
	}
}

// runTopLedEngine runs the top LED engine
// FIXME the top LED is only used to indicate emergency situations
func (a *computeBladeAgent) runTopLedEngine(ctx context.Context, cancel context.CancelCauseFunc) {
	log.FromContext(ctx).Info("Starting top LED engine")
	if err := a.topLedEngine.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.FromContext(ctx).WithError(err).Error("Top LED engine failed")
		cancel(err)
	}
}

// runEdgeLedEngine runs the edge LED engine
func (a *computeBladeAgent) runEdgeLedEngine(ctx context.Context, cancel context.CancelCauseFunc) {
	log.FromContext(ctx).Info("Starting edge LED engine")
	if err := a.edgeLedEngine.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.FromContext(ctx).WithError(err).Error("Edge LED engine failed")
		cancel(err)
	}
}

// runFanController initializes and manages a periodic task to control fan speed based on temperature readings.
// The method uses a ticker to execute fan speed adjustments and handles context cancellation for cleanup.
// If obtaining temperature or setting fan speed fails, appropriate error logs are recorded.
func (a *computeBladeAgent) runFanController(ctx context.Context, cancel context.CancelCauseFunc) {
	log.FromContext(ctx).Info("Starting fan controller")

	// Update fan speed periodically
	ticker := time.NewTicker(5 * time.Second)

	for {
		// Wait for the next tick
		select {
		case <-ctx.Done():
			ticker.Stop()

			if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
				log.FromContext(ctx).WithError(err).Error("Fan Controller Failed")
				cancel(err)
			}
			return
		case <-ticker.C:
		}

		// Get temperature
		temp, err := a.blade.GetTemperature()
		if err != nil {
			log.FromContext(ctx).WithError(err).Error("Failed to get temperature")
			temp = 100 // set to a high value to trigger the maximum speed defined by the fan curve
		} else {
			a.evaluateCriticalTemperature(ctx, temp)
		}
		// Derive fan speed from temperature
		speed := a.fanSpeedPercent(temp)
		// Set fan speed
		if err := a.blade.SetFanSpeed(speed); err != nil {
			log.FromContext(ctx).WithError(err).Error("Failed to set fan speed")
		}

		a.evaluateFanStall(ctx, speed)
	}
}

// evaluateFanStall compares the commanded fan speed with the measured RPM and raises / clears a fan stall.
func (a *computeBladeAgent) evaluateFanStall(ctx context.Context, targetPercent uint8) {
	if a.fanStallDetector == nil {
		return
	}

	rpm, err := a.blade.GetFanRPM()
	if err != nil {
		log.FromContext(ctx).WithError(err).Warn("Failed to get fan RPM, skipping fan stall detection")
		return
	}

	details := events.FanDetails{TargetPercent: targetPercent, RPM: rpm}
	switch a.fanStallDetector.Observe(time.Now(), targetPercent, rpm) {
	case health.Raised:
		log.FromContext(ctx).Error("Fan stall detected: fan is not spinning although commanded to",
			zap.Uint8("target_percent", targetPercent),
			zap.Float64("rpm", rpm),
		)
		a.emitMessage(ctx, events.NewMessage(events.FanStallEvent, details))
	case health.Cleared:
		log.FromContext(ctx).Info("Fan is spinning again, fan stall cleared",
			zap.Uint8("target_percent", targetPercent),
			zap.Float64("rpm", rpm),
		)
		a.emitMessage(ctx, events.NewMessage(events.FanStallClearEvent, details))
	case health.Unchanged:
	}
}

// fanSpeedPercent is the fan speed for the given temperature: the fan curve or the override set via the API, and
// full speed while critical mode is active.
func (a *computeBladeAgent) fanSpeedPercent(temp float64) uint8 {
	if a.state.CriticalActive() {
		return 100
	}
	return a.fanController.GetFanSpeedPercent(temp)
}

// evaluateCriticalTemperature raises critical mode when the SoC temperature reaches the configured threshold and
// clears it again once the temperature dropped below the threshold minus a small hysteresis.
// A critical state raised manually (e.g. via the API) is only cleared automatically if the temperature crossed the
// threshold in the meantime.
func (a *computeBladeAgent) evaluateCriticalTemperature(ctx context.Context, temp float64) {
	if a.config.CriticalTemperatureThreshold == 0 {
		return
	}

	// Critical mode was reset manually (e.g. via the API) while the blade is still hot:
	// forget the previous state so the next observation raises critical mode again.
	if a.criticalDetector.Active() && !a.state.CriticalActive() {
		a.criticalDetector.Reset()
	}

	switch a.criticalDetector.Observe(temp) {
	case health.Raised:
		log.FromContext(ctx).Warn("SoC temperature reached critical threshold",
			zap.Float64("temperature", temp),
			zap.Uint("threshold", a.config.CriticalTemperatureThreshold),
		)
		a.emitEvent(ctx, events.CriticalEvent)
	case health.Cleared:
		log.FromContext(ctx).Info("SoC temperature dropped below critical threshold",
			zap.Float64("temperature", temp),
			zap.Uint("threshold", a.config.CriticalTemperatureThreshold),
		)
		a.emitEvent(ctx, events.CriticalResetEvent)
	case health.Unchanged:
	}
}

// emitEvent queues an event for the event handler without blocking. If the queue is full, the event is dropped and
// counted in droppedEventCounter.
func (a *computeBladeAgent) emitEvent(ctx context.Context, event events.Event) {
	a.emitMessage(ctx, events.NewMessage(event, nil))
}

// emitMessage queues an event message (an event with details) for the event handler without blocking.
// If the queue is full, the event is dropped and counted in droppedEventCounter.
func (a *computeBladeAgent) emitMessage(ctx context.Context, msg events.Message) {
	select {
	case a.eventChan <- msg:
	default:
		log.FromContext(ctx).Warn("Event dropped due to backlog", zap.String("event", msg.Event.String()))
		droppedEventCounter.WithLabelValues(msg.Event.String()).Inc()
	}
}

// runEventHandler processes events from the agent's event channel, handles them, and cancels on critical failure or context cancellation.
func (a *computeBladeAgent) runEventHandler(ctx context.Context, cancel context.CancelCauseFunc) {
	log.FromContext(ctx).Info("Starting event handler")
	for {
		select {
		case <-ctx.Done():
			return

		case msg := <-a.eventChan:
			err := a.handleEvent(ctx, msg)
			if err != nil && !errors.Is(err, context.Canceled) {
				log.FromContext(ctx).WithError(err).Error("Event handler failed")
				cancel(err)
			}
		}
	}
}

// runGRpcApi starts the gRPC server for the agent based on the configuration and gracefully handles errors or cancellation.
func (a *computeBladeAgent) runGRpcApi(ctx context.Context, cancel context.CancelCauseFunc) {
	if len(a.config.Listen.Grpc) == 0 {
		err := humane.New("no listen address provided",
			"ensure you are passing a valid listen config to the grpc server",
		)
		log.FromContext(ctx).Error("no listen address provided, not starting gRPC server", humane.Zap(err)...)
		cancel(err)
	}

	grpcListen, err := net.Listen(a.config.Listen.GrpcListenMode, a.config.Listen.Grpc)
	if err != nil {
		err := humane.Wrap(err, "failed to create grpc listener",
			"ensure the gRPC server you are trying to serve to is not already running and the address is not bound by another process",
		)
		log.FromContext(ctx).Error("failed to create grpc listener, not starting gRPC server", humane.Zap(err)...)
		cancel(err)
	}

	log.FromContext(ctx).Info("Starting grpc server", zap.String("address", a.config.Listen.Grpc))
	if err := a.server.Serve(grpcListen); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		log.FromContext(ctx).Error("failed to start grpc server", humane.Zap(err)...)
		cancel(err)
	}
}
