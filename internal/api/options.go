package api

import "github.com/uptime-induestries/compute-blade-agent/internal/agent"

type GrpcApiServiceOption func(*agentGrpcService)

func WithComputeBladeAgent(agent agent.ComputeBladeAgent) GrpcApiServiceOption {
	return func(service *agentGrpcService) {
		service.agent = agent
	}
}
