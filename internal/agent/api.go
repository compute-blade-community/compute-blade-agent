package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	grpczap "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/sierrasoftworks/humane-errors-go"
	bladeapiv1alpha1 "github.com/uptime-induestries/compute-blade-agent/api/bladeapi/v1alpha1"
	"github.com/uptime-induestries/compute-blade-agent/pkg/certs"
	"github.com/uptime-induestries/compute-blade-agent/pkg/log"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// AgentGrpcService represents a gRPC server implementation for managing compute blade agents.
// It embeds UnimplementedBladeAgentServiceServer for forward compatibility and integrates ComputeBladeAgent logic.
// The type allows for serving gRPC requests and gracefully shutting down the server.
type AgentGrpcService struct {
	bladeapiv1alpha1.UnimplementedBladeAgentServiceServer
	agent         ComputeBladeAgent
	server        *grpc.Server
	authenticated bool
	listenAddr    string
	listenMode    string
}

// NewGrpcApiServer creates a new gRPC service
func NewGrpcApiServer(ctx context.Context, options ...GrpcApiServiceOption) *AgentGrpcService {
	service := &AgentGrpcService{}

	for _, option := range options {
		option(service)
	}

	grpcOpts := make([]grpc.ServerOption, 0)
	if service.authenticated {
		// Load server's certificate and private key
		cert, certPool, err := certs.GenerateServerCert(ctx, service.listenAddr)
		if err != nil {
			log.FromContext(ctx).Fatal("failed to load server key pair",
				zap.Error(err),
				zap.Strings("advice", err.Advice()),
			)
		}

		// Create the TLS config that enforces mTLS for client authentication
		tlsConfig := &tls.Config{
			Certificates:       []tls.Certificate{cert},
			ClientAuth:         tls.VerifyClientCertIfGiven, //tls.RequireAndVerifyClientCert, // FIXME
			ClientCAs:          certPool,
			InsecureSkipVerify: true, // FIXME
		}

		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	// Add Logging Middleware
	grpcOpts = append(grpcOpts, grpc.ChainUnaryInterceptor(grpczap.UnaryServerInterceptor(log.InterceptorLogger(zap.L()))))
	grpcOpts = append(grpcOpts, grpc.ChainStreamInterceptor(grpczap.StreamServerInterceptor(log.InterceptorLogger(zap.L()))))

	// Make server
	service.server = grpc.NewServer(grpcOpts...)
	bladeapiv1alpha1.RegisterBladeAgentServiceServer(service.server, service)

	return service
}

func (s *AgentGrpcService) ServeAsync(ctx context.Context, cancel context.CancelCauseFunc) {
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

func (s *AgentGrpcService) Serve(ctx context.Context) humane.Error {
	if len(s.listenAddr) == 0 {
		return humane.New("no listen address provided",
			"ensure you are passing a valid listen config to the grpc server",
		)
	}

	grpcListen, err := net.Listen(s.listenMode, s.listenAddr)
	if err != nil {
		return humane.Wrap(err, "failed to create grpc listener",
			"ensure the gRPC server you are trying to serve to is not already running and the address is not bound by another process",
		)
	}

	log.FromContext(ctx).Info("Starting grpc server", zap.String("address", s.listenAddr))
	if err := s.server.Serve(grpcListen); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return humane.Wrap(err, "failed to start grpc server",
			"ensure the gRPC server you are trying to serve to is not already running and the address is not bound by another process",
		)
	}

	return nil
}

func (s *AgentGrpcService) GracefulStop() {
	s.server.GracefulStop()
}

// EmitEvent emits an event to the agent runtime
func (s *AgentGrpcService) EmitEvent(
	ctx context.Context,
	req *bladeapiv1alpha1.EmitEventRequest,
) (*emptypb.Empty, error) {
	switch req.GetEvent() {
	case bladeapiv1alpha1.Event_IDENTIFY:
		return &emptypb.Empty{}, s.agent.EmitEvent(ctx, IdentifyEvent)
	case bladeapiv1alpha1.Event_IDENTIFY_CONFIRM:
		return &emptypb.Empty{}, s.agent.EmitEvent(ctx, IdentifyConfirmEvent)
	case bladeapiv1alpha1.Event_CRITICAL:
		return &emptypb.Empty{}, s.agent.EmitEvent(ctx, CriticalEvent)
	case bladeapiv1alpha1.Event_CRITICAL_RESET:
		return &emptypb.Empty{}, s.agent.EmitEvent(ctx, CriticalResetEvent)
	default:
		return &emptypb.Empty{}, status.Errorf(codes.InvalidArgument, "invalid event type")
	}
}

func (s *AgentGrpcService) WaitForIdentifyConfirm(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.agent.WaitForIdentifyConfirm(ctx)
}

// SetFanSpeed sets the fan speed of the blade
func (s *AgentGrpcService) SetFanSpeed(
	ctx context.Context,
	req *bladeapiv1alpha1.SetFanSpeedRequest,
) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.agent.SetFanSpeed(ctx, uint8(req.GetPercent()))
}

// SetStealthMode enables/disables stealth mode on the blade
func (s *AgentGrpcService) SetStealthMode(ctx context.Context, req *bladeapiv1alpha1.StealthModeRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.agent.SetStealthMode(ctx, req.GetEnable())
}

// GetStatus aggregates the status of the blade
func (s *AgentGrpcService) GetStatus(context.Context, *emptypb.Empty) (*bladeapiv1alpha1.StatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetStatus not implemented")
}

// GenerateClientCertificate creates a client certificate for secure communication with the blade agent.
// It returns a StatusResponse containing the updated agent status or an error if the operation fails.
func (s *AgentGrpcService) GenerateClientCertificate(_ context.Context, req *bladeapiv1alpha1.ClientCertRequest) (*bladeapiv1alpha1.ClientCertResponse, error) {
	caPEM, certPEM, keyPEM, err := certs.GenerateClientCert(req.CommonName)
	if err != nil {
		return nil, status.Errorf(codes.Aborted, "failed to generate client certificate: %s", err.Error())
	}

	return &bladeapiv1alpha1.ClientCertResponse{
		CaPem:          string(caPEM),
		CertificatePem: string(certPEM),
		PrivateKeyPem:  string(keyPEM),
	}, nil
}
