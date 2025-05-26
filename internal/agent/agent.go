package internal_agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	grpczap "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sierrasoftworks/humane-errors-go"
	bladeapiv1alpha1 "github.com/uptime-industries/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/uptime-industries/compute-blade-agent/pkg/agent"
	"github.com/uptime-industries/compute-blade-agent/pkg/events"
	"github.com/uptime-industries/compute-blade-agent/pkg/fancontroller"
	"github.com/uptime-industries/compute-blade-agent/pkg/hal"
	"github.com/uptime-industries/compute-blade-agent/pkg/hal/led"
	"github.com/uptime-industries/compute-blade-agent/pkg/ledengine"
	"github.com/uptime-industries/compute-blade-agent/pkg/log"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
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
	bladeapiv1alpha1.UnimplementedBladeAgentServiceServer
	config        agent.ComputeBladeAgentConfig
	blade         hal.ComputeBladeHal
	state         agent.ComputebladeState
	edgeLedEngine ledengine.LedEngine
	topLedEngine  ledengine.LedEngine
	fanController fancontroller.FanController
	eventChan     chan events.Event
	server        *grpc.Server
}

func NewComputeBladeAgent(ctx context.Context, config agent.ComputeBladeAgentConfig) (agent.ComputeBladeAgent, error) {
	blade, err := hal.NewCm4Hal(ctx, config.ComputeBladeHalOpts)
	if err != nil {
		return nil, err
	}

	fanController, err := fancontroller.NewLinearFanController(config.FanControllerConfig)
	if err != nil {
		return nil, err
	}

	a := &computeBladeAgentImpl{
		config:        config,
		blade:         blade,
		edgeLedEngine: newLedEngine(blade, hal.LedEdge),
		topLedEngine:  newLedEngine(blade, hal.LedTop),
		fanController: fanController,
		state:         agent.NewComputeBladeState(),
		eventChan:     make(chan events.Event, 10),
	}

	if err := a.setupGrpcServer(ctx); err != nil {
		return nil, err
	}

	bladeapiv1alpha1.RegisterBladeAgentServiceServer(a.server, a)
	return a, nil
}

func newLedEngine(blade hal.ComputeBladeHal, idx hal.LedIndex) ledengine.LedEngine {
	return ledengine.NewLedEngine(ledengine.Options{
		LedIdx: idx,
		Hal:    blade,
	})
}

func (a *computeBladeAgentImpl) setupGrpcServer(ctx context.Context) error {
	listenMode, err := ListenModeFromString(a.config.Listen.GrpcListenMode)
	if err != nil {
		return err
	}

	var grpcOpts []grpc.ServerOption

	if listenMode == ModeTcp && a.config.Listen.GrpcAuthenticated {
		tlsCfg, err := createServerTLSConfig(ctx)
		if err != nil {
			return err
		}
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))

		if err := EnsureAuthenticatedBladectlConfig(ctx, a.config.Listen.Grpc, listenMode); err != nil {
			return err
		}
	} else {
		if err := EnsureUnauthenticatedBladectlConfig(ctx, a.config.Listen.Grpc, listenMode); err != nil {
			return err
		}
	}

	logger := log.InterceptorLogger(zap.L())
	grpcOpts = append(grpcOpts,
		grpc.ChainUnaryInterceptor(grpczap.UnaryServerInterceptor(logger)),
		grpc.ChainStreamInterceptor(grpczap.StreamServerInterceptor(logger)),
	)

	a.server = grpc.NewServer(grpcOpts...)
	return nil
}

func createServerTLSConfig(ctx context.Context) (*tls.Config, error) {
	cert, certPool, err := EnsureServerCertificate(ctx)
	if err != nil {
		log.FromContext(ctx).Fatal("failed to load server key pair",
			zap.Error(err),
			zap.Strings("advice", err.Advice()),
		)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}, nil
}

// RunAsync starts the agent in a separate goroutine and handles errors, allowing cancellation through the provided context.
func (a *computeBladeAgentImpl) RunAsync(ctx context.Context, cancel context.CancelCauseFunc) {
	go func() {
		log.FromContext(ctx).Info("Starting agent")
		err := a.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.FromContext(ctx).Error("Failed to run agent", zap.Error(err))
			cancel(err)
		}
	}()
}

// Run initializes and starts the compute blade agent, setting up necessary components and processes, and waits for termination.
func (a *computeBladeAgentImpl) Run(origCtx context.Context) error {
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

	// Start edge button event handler
	go a.runEdgeButtonHandler(ctx, cancelCtx)

	// Start top LED engine
	go a.runTopLedEngine(ctx, cancelCtx)

	// Start edge LED engine
	go a.runEdgeLedEngine(ctx, cancelCtx)

	// Start fan controller
	go a.runFanController(ctx, cancelCtx)

	// Start event handler
	go a.runEventHandler(ctx, cancelCtx)

	// Start gRPC API
	go a.runGRpcApi(ctx, cancelCtx)

	// wait till we're done
	<-ctx.Done()

	return ctx.Err()
}

// GracefulStop gracefully stops the gRPC server, ensuring all in-progress RPCs are completed before shutting down.
func (a *computeBladeAgentImpl) GracefulStop(ctx context.Context) error {
	a.server.GracefulStop()

	log.FromContext(ctx).Info("Exiting, restoring safe settings")
	if err := a.blade.SetFanSpeed(100); err != nil {
		log.FromContext(ctx).Error("Failed to set fan speed to 100%", zap.Error(err))
	}
	if err := a.blade.SetLed(hal.LedEdge, led.Color{}); err != nil {
		log.FromContext(ctx).Error("Failed to set edge LED to off", zap.Error(err))
	}
	if err := a.blade.SetLed(hal.LedTop, led.Color{}); err != nil {
		log.FromContext(ctx).Error("Failed to set edge LED to off", zap.Error(err))
	}

	return errors.Join(a.blade.Close())
}

// EmitEvent dispatches an event to the event handler
func (a *computeBladeAgentImpl) EmitEvent(ctx context.Context, req *bladeapiv1alpha1.EmitEventRequest) (*emptypb.Empty, error) {
	event, err := fromProto(req.GetEvent())
	if err != nil {
		return nil, err
	}

	select {
	case a.eventChan <- event:
		return &emptypb.Empty{}, nil
	case <-ctx.Done():
		return &emptypb.Empty{}, ctx.Err()
	}
}

// SetFanSpeed sets the fan speed
func (a *computeBladeAgentImpl) SetFanSpeed(_ context.Context, req *bladeapiv1alpha1.SetFanSpeedRequest) (*emptypb.Empty, error) {
	if a.state.CriticalActive() {
		return &emptypb.Empty{}, humane.New("cannot set fan speed while the blade is in a critical state", "improve cooling on your blade before attempting to overwrite the fan speed")
	}

	a.fanController.Override(&fancontroller.FanOverrideOpts{Percent: uint8(req.GetPercent())})
	return &emptypb.Empty{}, nil
}

// SetFanSpeedAuto sets the fan speed to automatic mode
func (a *computeBladeAgentImpl) SetFanSpeedAuto(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	a.fanController.Override(nil)
	return &emptypb.Empty{}, nil
}

// SetStealthMode enables/disables the stealth mode
func (a *computeBladeAgentImpl) SetStealthMode(_ context.Context, req *bladeapiv1alpha1.StealthModeRequest) (*emptypb.Empty, error) {
	if a.state.CriticalActive() {
		return &emptypb.Empty{}, humane.New("cannot set stealth mode while the blade is in a critical state", "improve cooling on your blade before attempting to enable stealth mode again")
	}
	return &emptypb.Empty{}, a.blade.SetStealthMode(req.GetEnable())
}

// GetStatus aggregates the status of the blade
func (a *computeBladeAgentImpl) GetStatus(_ context.Context, _ *emptypb.Empty) (*bladeapiv1alpha1.StatusResponse, error) {
	rpm, err := a.blade.GetFanRPM()
	if err != nil {
		return nil, err
	}

	temp, err := a.blade.GetTemperature()
	if err != nil {
		return nil, err
	}

	powerStatus, err := a.blade.GetPowerStatus()
	if err != nil {
		return nil, err
	}

	steps := a.fanController.Config().Steps
	fanCurveSteps := make([]*bladeapiv1alpha1.FanCurveStep, len(steps))
	for idx, step := range steps {
		fanCurveSteps[idx] = &bladeapiv1alpha1.FanCurveStep{
			Temperature: int64(step.Temperature),
			Percent:     uint32(step.Percent),
		}
	}

	return &bladeapiv1alpha1.StatusResponse{
		StealthMode:                  a.blade.StealthModeActive(),
		IdentifyActive:               a.state.IdentifyActive(),
		CriticalActive:               a.state.CriticalActive(),
		Temperature:                  int64(temp),
		FanRpm:                       int64(rpm),
		FanPercent:                   uint32(a.fanController.GetFanSpeedPercent(temp)),
		FanSpeedAutomatic:            a.fanController.IsAutomaticSpeed(),
		PowerStatus:                  bladeapiv1alpha1.PowerStatus(powerStatus),
		FanCurveSteps:                fanCurveSteps,
		CriticalTemperatureThreshold: int64(a.config.CriticalTemperatureThreshold),
	}, nil
}

// WaitForIdentifyConfirm blocks until the identify confirmation process is completed or an error occurs.
func (a *computeBladeAgentImpl) WaitForIdentifyConfirm(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, a.state.WaitForIdentifyConfirm(ctx)
}

// handleEvent processes an incoming event, updates state, and dispatches it to the appropriate handler based on the event type.
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

// handleIdentifyActive is responsible for handling the identify event by setting a burst LED pattern based on the configuration.
func (a *computeBladeAgentImpl) handleIdentifyActive(ctx context.Context) error {
	log.FromContext(ctx).Info("Identify active")
	return a.edgeLedEngine.SetPattern(ledengine.NewBurstPattern(led.Color{}, a.config.IdentifyLedColor))
}

// handleIdentifyConfirm handles the confirmation of an identify event by updating the LED engine with a static idle pattern.
func (a *computeBladeAgentImpl) handleIdentifyConfirm(ctx context.Context) error {
	log.FromContext(ctx).Info("Identify confirmed/cleared")
	return a.edgeLedEngine.SetPattern(ledengine.NewStaticPattern(a.config.IdleLedColor))
}

// handleCriticalActive handles the system's response to a critical state by adjusting fan speed and LED indications.
// It sets the fan speed to 100%, disables stealth mode, and applies a critical LED pattern.
// Returns any errors encountered during the process as a combined error.
func (a *computeBladeAgentImpl) handleCriticalActive(ctx context.Context) error {
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
func (a *computeBladeAgentImpl) handleCriticalReset(ctx context.Context) error {
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

// runHal initializes and starts the HAL service within the given context, handling errors and supporting graceful cancellation.
func (a *computeBladeAgentImpl) runHal(ctx context.Context, cancel context.CancelCauseFunc) {
	log.FromContext(ctx).Info("Starting HAL")
	if err := a.blade.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.FromContext(ctx).Error("HAL failed", zap.Error(err))
		cancel(err)
	}
}

// runTopLedEngine runs the top LED engine
// FIXME the top LED is only used to indicate emergency situations
func (a *computeBladeAgentImpl) runTopLedEngine(ctx context.Context, cancel context.CancelCauseFunc) {
	log.FromContext(ctx).Info("Starting top LED engine")
	if err := a.topLedEngine.SetPattern(ledengine.NewStaticPattern(led.Color{})); err != nil && !errors.Is(err, context.Canceled) {
		log.FromContext(ctx).Error("Top LED engine failed", zap.Error(err))
		cancel(err)
	}

	if err := a.topLedEngine.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.FromContext(ctx).Error("Top LED engine failed", zap.Error(err))
		cancel(err)
	}
}

// runEdgeLedEngine runs the edge LED engine
func (a *computeBladeAgentImpl) runEdgeLedEngine(ctx context.Context, cancel context.CancelCauseFunc) {
	log.FromContext(ctx).Info("Starting edge LED engine")

	if err := a.edgeLedEngine.SetPattern(ledengine.NewStaticPattern(a.config.IdleLedColor)); err != nil && !errors.Is(err, context.Canceled) {
		log.FromContext(ctx).Error("Edge LED engine failed", zap.Error(err))
		cancel(err)
	}

	if err := a.edgeLedEngine.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.FromContext(ctx).Error("Edge LED engine failed", zap.Error(err))
		cancel(err)
	}
}

// runFanController initializes and manages a periodic task to control fan speed based on temperature readings.
// The method uses a ticker to execute fan speed adjustments and handles context cancellation for cleanup.
// If obtaining temperature or setting fan speed fails, appropriate error logs are recorded.
func (a *computeBladeAgentImpl) runFanController(ctx context.Context, cancel context.CancelCauseFunc) {
	log.FromContext(ctx).Info("Starting fan controller")

	// Update fan speed periodically
	ticker := time.NewTicker(5 * time.Second)

	for {
		// Wait for the next tick
		select {
		case <-ctx.Done():
			ticker.Stop()

			if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
				log.FromContext(ctx).Error("Fan Controller Failed", zap.Error(err))
				cancel(err)
			}
			return
		case <-ticker.C:
		}

		// Get temperature
		temp, err := a.blade.GetTemperature()
		if err != nil {
			log.FromContext(ctx).Error("Failed to get temperature", zap.Error(err))
			temp = 100 // set to a high value to trigger the maximum speed defined by the fan curve
		}
		// Derive fan speed from temperature
		speed := a.fanController.GetFanSpeedPercent(temp)
		// Set fan speed
		if err := a.blade.SetFanSpeed(speed); err != nil {
			log.FromContext(ctx).Error("Failed to set fan speed", zap.Error(err))
		}
	}
}

// runEdgeButtonHandler initializes and handles edge button press events in a loop until the context is canceled.
// It waits for edge button presses and sends corresponding events to the event channel, logging errors and warnings.
// If an unrecoverable error occurs, the cancel function is triggered to terminate the operation.
func (a *computeBladeAgentImpl) runEdgeButtonHandler(ctx context.Context, cancel context.CancelCauseFunc) {
	log.FromContext(ctx).Info("Starting edge button event handler")
	for {
		if err := a.blade.WaitForEdgeButtonPress(ctx); err != nil {
			if !errors.Is(err, context.Canceled) {
				log.FromContext(ctx).Error("Edge button event handler failed", zap.Error(err))
				cancel(err)
			}

			return
		}

		select {
		case a.eventChan <- events.Event(events.EdgeButtonEvent):
		default:
			log.FromContext(ctx).Warn("Edge button press event dropped due to backlog")
			droppedEventCounter.WithLabelValues(events.Event(events.EdgeButtonEvent).String()).Inc()
		}
	}
}

// runEventHandler processes events from the agent's event channel, handles them, and cancels on critical failure or context cancellation.
func (a *computeBladeAgentImpl) runEventHandler(ctx context.Context, cancel context.CancelCauseFunc) {
	log.FromContext(ctx).Info("Starting event handler")
	for {
		select {
		case <-ctx.Done():
			return

		case event := <-a.eventChan:
			err := a.handleEvent(ctx, event)
			if err != nil && !errors.Is(err, context.Canceled) {
				log.FromContext(ctx).Error("Event handler failed", zap.Error(err))
				cancel(err)
			}
		}
	}
}

// runGRpcApi starts the gRPC server for the agent based on the configuration and gracefully handles errors or cancellation.
func (a *computeBladeAgentImpl) runGRpcApi(ctx context.Context, cancel context.CancelCauseFunc) {
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

// fromProto converts a `bladeapiv1alpha1.Event` into a corresponding `events.Event` type.
// Returns an error if the event type is invalid.
func fromProto(event bladeapiv1alpha1.Event) (events.Event, error) {
	switch event {
	case bladeapiv1alpha1.Event_IDENTIFY:
		return events.IdentifyEvent, nil
	case bladeapiv1alpha1.Event_IDENTIFY_CONFIRM:
		return events.IdentifyConfirmEvent, nil
	case bladeapiv1alpha1.Event_CRITICAL:
		return events.CriticalEvent, nil
	case bladeapiv1alpha1.Event_CRITICAL_RESET:
		return events.CriticalResetEvent, nil
	default:
		return events.NoopEvent, status.Errorf(codes.InvalidArgument, "invalid event type")
	}
}
