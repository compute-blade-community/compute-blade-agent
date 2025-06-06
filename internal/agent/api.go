package internal_agent

import (
	"context"
	"crypto/tls"

	bladeapiv1alpha1 "github.com/compute-blade-community/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/compute-blade-community/compute-blade-agent/pkg/fancontroller"
	"github.com/compute-blade-community/compute-blade-agent/pkg/log"
	grpczap "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/sierrasoftworks/humane-errors-go"
	"github.com/spechtlabs/go-otel-utils/otelzap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/emptypb"
)

// setupGrpcServer initializes and configures the gRPC server with authentication, logging, and server options.
func (a *computeBladeAgent) setupGrpcServer(ctx context.Context) error {
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

	logger := log.InterceptorLogger(otelzap.L())
	grpcOpts = append(grpcOpts,
		grpc.ChainUnaryInterceptor(grpczap.UnaryServerInterceptor(logger)),
		grpc.ChainStreamInterceptor(grpczap.StreamServerInterceptor(logger)),
	)

	a.server = grpc.NewServer(grpcOpts...)
	return nil
}

// createServerTLSConfig creates and returns a TLS configuration for a server, enforcing client authentication.
// It generates or loads the necessary certificates and certificate pools, logging fatal errors if certificate loading fails.
func createServerTLSConfig(ctx context.Context) (*tls.Config, error) {
	cert, certPool, err := EnsureServerCertificate(ctx)
	if err != nil {
		log.FromContext(ctx).WithError(err).Fatal("failed to load server key pair")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}, nil
}

// EmitEvent dispatches an event to the event handler
func (a *computeBladeAgent) EmitEvent(ctx context.Context, req *bladeapiv1alpha1.EmitEventRequest) (*emptypb.Empty, error) {
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
func (a *computeBladeAgent) SetFanSpeed(_ context.Context, req *bladeapiv1alpha1.SetFanSpeedRequest) (*emptypb.Empty, error) {
	if a.state.CriticalActive() {
		return &emptypb.Empty{}, humane.New("cannot set fan speed while the blade is in a critical state", "improve cooling on your blade before attempting to overwrite the fan speed")
	}

	a.fanController.Override(&fancontroller.FanOverrideOpts{Percent: uint8(req.GetPercent())})
	return &emptypb.Empty{}, nil
}

// SetFanSpeedAuto sets the fan speed to automatic mode
func (a *computeBladeAgent) SetFanSpeedAuto(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	a.fanController.Override(nil)
	return &emptypb.Empty{}, nil
}

// SetStealthMode enables/disables the stealth mode
func (a *computeBladeAgent) SetStealthMode(_ context.Context, req *bladeapiv1alpha1.StealthModeRequest) (*emptypb.Empty, error) {
	if a.state.CriticalActive() {
		return &emptypb.Empty{}, humane.New("cannot set stealth mode while the blade is in a critical state", "improve cooling on your blade before attempting to enable stealth mode again")
	}
	return &emptypb.Empty{}, a.blade.SetStealthMode(req.GetEnable())
}

// GetStatus aggregates the status of the blade
func (a *computeBladeAgent) GetStatus(_ context.Context, _ *emptypb.Empty) (*bladeapiv1alpha1.StatusResponse, error) {
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

	steps := a.fanController.Steps()
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
func (a *computeBladeAgent) WaitForIdentifyConfirm(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, a.state.WaitForIdentifyConfirm(ctx)
}
