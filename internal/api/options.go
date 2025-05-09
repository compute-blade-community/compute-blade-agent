package api

import (
	"github.com/spechtlabs/go-otel-utils/otelzap"
	"github.com/uptime-industries/compute-blade-agent/pkg/agent"
	"go.uber.org/zap"
)

// GrpcApiServiceOption defines a functional option for configuring an AgentGrpcService instance.
type GrpcApiServiceOption func(*AgentGrpcService)

// WithComputeBladeAgent sets the ComputeBladeAgent implementation for the AgentGrpcService.
func WithComputeBladeAgent(agent agent.ComputeBladeAgent) GrpcApiServiceOption {
	return func(service *AgentGrpcService) {
		service.agent = agent
	}
}

// WithAuthentication configures the authentication requirement for the gRPC service by enabling or disabling it.
func WithAuthentication(enabled bool) GrpcApiServiceOption {
	return func(service *AgentGrpcService) {
		service.authenticated = enabled
	}
}

// WithListenAddr sets the server's listen address on an AgentGrpcService instance.
func WithListenAddr(server string) GrpcApiServiceOption {
	return func(service *AgentGrpcService) {
		service.listenAddr = server
	}
}

// WithListenMode configures the listen mode for the AgentGrpcService using the provided mode string.
func WithListenMode(mode string) GrpcApiServiceOption {
	return func(service *AgentGrpcService) {
		lMode, err := ListenModeFromString(mode)
		if err != nil {
			otelzap.L().Fatal(err.Error(),
				zap.String("mode", mode),
				zap.Strings("advice", err.Advice()),
			)
		}

		service.listenMode = lMode
	}
}
