package agent

type GrpcApiServiceOption func(*AgentGrpcService)

func WithComputeBladeAgent(agent ComputeBladeAgent) GrpcApiServiceOption {
	return func(service *AgentGrpcService) {
		service.agent = agent
	}
}
func WithGrpcApiInsecure(insecure bool) GrpcApiServiceOption {
	return func(service *AgentGrpcService) {
		service.insecure = insecure
	}
}
