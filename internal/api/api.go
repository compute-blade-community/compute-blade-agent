package api

import (
	"context"
	"net"

	"github.com/sierrasoftworks/humane-errors-go"
	"github.com/spf13/viper"
	bladeapiv1alpha1 "github.com/uptime-induestries/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/uptime-induestries/compute-blade-agent/internal/agent"
	"github.com/uptime-induestries/compute-blade-agent/pkg/log"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ComputeBladeAgent implementing the BladeAgentServiceServer
type agentGrpcService struct {
	bladeapiv1alpha1.UnimplementedBladeAgentServiceServer
	agent  agent.ComputeBladeAgent
	server *grpc.Server
}

// NewGrpcApiServer creates a new gRPC service
func NewGrpcApiServer(options ...GrpcApiServiceOption) *agentGrpcService {
	service := &agentGrpcService{}

	for _, option := range options {
		option(service)
	}

	service.server = grpc.NewServer()
	bladeapiv1alpha1.RegisterBladeAgentServiceServer(service.server, service)

	return service
}

func (s *agentGrpcService) ServeAsync(ctx context.Context, cancel context.CancelCauseFunc) {
	go func() {
		err := s.Serve(ctx)
		if err != nil {
			log.FromContext(ctx).Error("Failed to start grpc server",
				zap.Error(err),
				zap.String("cause", err.Cause().Error()),
				zap.Strings("advice", err.Advice()),
			)

			cancel(err.Cause())
		}
	}()
}

func (s *agentGrpcService) Serve(ctx context.Context) humane.Error {
	grpcListen, err := net.Listen("unix", viper.GetString("listen.grpc"))
	if err != nil {
		return humane.Wrap(err, "failed to create grpc listener", "ensure the gRPC server you are trying to serve to is not already running and the address is not bound by another process")
	}

	log.FromContext(ctx).Info("Starting grpc server", zap.String("address", viper.GetString("listen.grpc")))
	if err := s.server.Serve(grpcListen); err != nil && err != grpc.ErrServerStopped {
		return humane.Wrap(err, "failed to start grpc server", "ensure the gRPC server you are trying to serve to is not already running and the address is not bound by another process")
	}

	return nil
}

func (s *agentGrpcService) GracefulStop() {
	s.server.GracefulStop()
}

// EmitEvent emits an event to the agent runtime
func (service *agentGrpcService) EmitEvent(
	ctx context.Context,
	req *bladeapiv1alpha1.EmitEventRequest,
) (*emptypb.Empty, error) {
	switch req.GetEvent() {
	case bladeapiv1alpha1.Event_IDENTIFY:
		return &emptypb.Empty{}, service.agent.EmitEvent(ctx, agent.IdentifyEvent)
	case bladeapiv1alpha1.Event_IDENTIFY_CONFIRM:
		return &emptypb.Empty{}, service.agent.EmitEvent(ctx, agent.IdentifyConfirmEvent)
	case bladeapiv1alpha1.Event_CRITICAL:
		return &emptypb.Empty{}, service.agent.EmitEvent(ctx, agent.CriticalEvent)
	case bladeapiv1alpha1.Event_CRITICAL_RESET:
		return &emptypb.Empty{}, service.agent.EmitEvent(ctx, agent.CriticalResetEvent)
	default:
		return &emptypb.Empty{}, status.Errorf(codes.InvalidArgument, "invalid event type")
	}
}

func (service *agentGrpcService) WaitForIdentifyConfirm(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, service.agent.WaitForIdentifyConfirm(ctx)
}

// SetFanSpeed sets the fan speed of the blade
func (service *agentGrpcService) SetFanSpeed(
	ctx context.Context,
	req *bladeapiv1alpha1.SetFanSpeedRequest,
) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, service.agent.SetFanSpeed(ctx, uint8(req.GetPercent()))
}

// SetStealthMode enables/disables stealth mode on the blade
func (service *agentGrpcService) SetStealthMode(ctx context.Context, req *bladeapiv1alpha1.StealthModeRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, service.agent.SetStealthMode(ctx, req.GetEnable())
}

// GetStatus aggregates the status of the blade
func (service *agentGrpcService) GetStatus(context.Context, *emptypb.Empty) (*bladeapiv1alpha1.StatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetStatus not implemented")
}
