package internal_agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/compute-blade-community/compute-blade-agent/pkg/agent"
	"github.com/compute-blade-community/compute-blade-agent/pkg/events"
	"github.com/compute-blade-community/compute-blade-agent/pkg/fancontroller"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal"
	"github.com/compute-blade-community/compute-blade-agent/pkg/hal/led"
	"github.com/compute-blade-community/compute-blade-agent/pkg/ledengine"
	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sierrasoftworks/humane-errors-go"
	"go.uber.org/zap"
	"google.golang.org/grpc"
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

// computeBladeAgent manages the operation and coordination of hardware components and services for a compute blade agent.
type computeBladeAgent struct {
	bladeapiv1alpha1.UnimplementedBladeAgentServiceServer
	config        agent.ComputeBladeAgentConfig
	blade         hal.ComputeBladeHal
	state         agent.ComputebladeState
	edgeLedEngine ledengine.LedEngine
	topLedEngine  ledengine.LedEngine
	fanController fancontroller.FanController
	eventChan     chan events.Event
	server        *grpc.Server
	agentInfo     agent.ComputeBladeAgentInfo
}

// NewComputeBladeAgent creates and initializes a new ComputeBladeAgent, including gRPC server setup and hardware interfaces.
func NewComputeBladeAgent(ctx context.Context, config agent.ComputeBladeAgentConfig, agentInfo agent.ComputeBladeAgentInfo) (agent.ComputeBladeAgent, error) {
	blade, err := hal.NewCm4Hal(ctx, config.ComputeBladeHalOpts)
	if err != nil {
		return nil, err
	}

	fanController, err := fancontroller.NewLinearFanController(config.FanControllerConfig)
	if err != nil {
		return nil, err
	}

	a := &computeBladeAgent{
		config:        config,
		blade:         blade,
		edgeLedEngine: ledengine.New(blade, hal.LedEdge),
		topLedEngine:  ledengine.New(blade, hal.LedTop),
		fanController: fanController,
		state:         agent.NewComputeBladeState(),
		eventChan:     make(chan events.Event, 10),
		agentInfo:     agentInfo,
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
func (a *computeBladeAgent) GracefulStop(ctx context.Context) error {
	a.server.GracefulStop()

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
	if err := a.topLedEngine.SetPattern(ledengine.NewStaticPattern(led.Color{})); err != nil && !errors.Is(err, context.Canceled) {
		log.FromContext(ctx).WithError(err).Error("Top LED engine failed")
		cancel(err)
	}

	if err := a.topLedEngine.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.FromContext(ctx).WithError(err).Error("Top LED engine failed")
		cancel(err)
	}
}

// runEdgeLedEngine runs the edge LED engine
func (a *computeBladeAgent) runEdgeLedEngine(ctx context.Context, cancel context.CancelCauseFunc) {
	log.FromContext(ctx).Info("Starting edge LED engine")

	if err := a.edgeLedEngine.SetPattern(ledengine.NewStaticPattern(a.config.IdleLedColor)); err != nil && !errors.Is(err, context.Canceled) {
		log.FromContext(ctx).WithError(err).Error("Edge LED engine failed")
		cancel(err)
	}

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
		}
		// Derive fan speed from temperature
		speed := a.fanController.GetFanSpeedPercent(temp)
		// Set fan speed
		if err := a.blade.SetFanSpeed(speed); err != nil {
			log.FromContext(ctx).WithError(err).Error("Failed to set fan speed")
		}
	}
}

// runEdgeButtonHandler initializes and handles edge button press events in a loop until the context is canceled.
// It waits for edge button presses and sends corresponding events to the event channel, logging errors and warnings.
// If an unrecoverable error occurs, the cancel function is triggered to terminate the operation.
func (a *computeBladeAgent) runEdgeButtonHandler(ctx context.Context, cancel context.CancelCauseFunc) {
	log.FromContext(ctx).Info("Starting edge button event handler")
	for {
		if err := a.blade.WaitForEdgeButtonPress(ctx); err != nil {
			if !errors.Is(err, context.Canceled) {
				log.FromContext(ctx).WithError(err).Error("Edge button event handler failed")
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
func (a *computeBladeAgent) runEventHandler(ctx context.Context, cancel context.CancelCauseFunc) {
	log.FromContext(ctx).Info("Starting event handler")
	for {
		select {
		case <-ctx.Done():
			return

		case event := <-a.eventChan:
			err := a.handleEvent(ctx, event)
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
